// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "storage_crypto.h"
#include "error_codes.h"
#include "random_utils.h"
#include "crypto_asm.h"
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <stdbool.h>
#include <string.h>

#ifdef ESP_PLATFORM
#include "esp_mac.h"
#include "esp_log.h"
#include "esp_timer.h"
static uint32_t get_time_ms(void) {
    return (uint32_t)(esp_timer_get_time() / 1000);
}
#else
#include <stdio.h>
#include <time.h>
#define ESP_LOGW(tag, ...)            \
    fprintf(stderr, "W (%s): ", tag); \
    fprintf(stderr, __VA_ARGS__);     \
    fprintf(stderr, "\n")
static uint32_t get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}
#endif

#define TAG            "storage_crypto"
#define DEVICE_ID_SIZE 6

#define PIN_RATE_LIMIT_WINDOW_MS   60000
#define PIN_RATE_LIMIT_MAX         3
#define PIN_LOCKOUT_MS             300000
#define PIN_LOCKOUT_FAILURE_THRESH 5

static uint8_t storage_key[STORAGE_CRYPTO_KEY_SIZE];
static bool key_initialized = false;

static uint32_t pin_attempt_times[PIN_RATE_LIMIT_MAX];
static uint8_t pin_attempt_count = 0;
static uint32_t pin_lockout_until = 0;
static uint8_t pin_consecutive_failures = 0;

static int get_device_id(uint8_t device_id[DEVICE_ID_SIZE]) {
#ifdef ESP_PLATFORM
    return esp_read_mac(device_id, ESP_MAC_EFUSE_FACTORY) == ESP_OK ? 0 : -1;
#else
    memset(device_id, 0x42, DEVICE_ID_SIZE);
    FILE *fp = fopen("/etc/machine-id", "r");
    if (!fp)
        return 0;

    char buf[13] = {0};
    size_t bytes_read = fread(buf, 1, 12, fp);
    fclose(fp);

    if (bytes_read < 12) {
        return 0;
    }

    for (int i = 0; i < DEVICE_ID_SIZE; i++) {
        unsigned int val = 0;
        if (sscanf(buf + i * 2, "%2x", &val) != 1) {
            memset(device_id, 0x42, DEVICE_ID_SIZE);
            return 0;
        }
        device_id[i] = (uint8_t)val;
    }
    return 0;
#endif
}

// The "v1" in the salt is the HKDF key derivation version, not the storage format version.
// Do not change this value - it would invalidate all existing encrypted data.
static const uint8_t HKDF_SALT[] = "keep-esp32-share-storage-v1";
static const uint8_t HKDF_INFO[] = "share-encryption-key";

static int derive_key(const uint8_t *device_id, size_t device_id_len, const uint8_t *pin,
                      size_t pin_len, uint8_t *key_out) {
    if (device_id_len > DEVICE_ID_SIZE) {
        return -1;
    }

    uint8_t ikm[DEVICE_ID_SIZE + STORAGE_CRYPTO_MAX_PIN_LEN];
    size_t ikm_len = device_id_len;
    memcpy(ikm, device_id, device_id_len);

    if (pin && pin_len > 0) {
        size_t copy_len =
            pin_len < STORAGE_CRYPTO_MAX_PIN_LEN ? pin_len : STORAGE_CRYPTO_MAX_PIN_LEN;
        memcpy(ikm + device_id_len, pin, copy_len);
        ikm_len += copy_len;
    }

    int ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), HKDF_SALT,
                           sizeof(HKDF_SALT) - 1, ikm, ikm_len, HKDF_INFO, sizeof(HKDF_INFO) - 1,
                           key_out, STORAGE_CRYPTO_KEY_SIZE);

    secure_memzero(ikm, sizeof(ikm));
    return (ret == 0) ? 0 : -1;
}

int storage_crypto_check_rate_limit(void) {
    uint32_t now = get_time_ms();

    if (pin_lockout_until > 0) {
        if ((int32_t)(now - pin_lockout_until) < 0) {
            return ERR_PIN_LOCKED;
        }
        pin_lockout_until = 0;
        pin_consecutive_failures = 0;
    }

    int recent = 0;
    for (int i = 0; i < pin_attempt_count && i < PIN_RATE_LIMIT_MAX; i++) {
        if ((int32_t)(now - pin_attempt_times[i]) < (int32_t)PIN_RATE_LIMIT_WINDOW_MS) {
            recent++;
        }
    }

    if (recent >= PIN_RATE_LIMIT_MAX) {
        return ERR_PIN_MUST_WAIT;
    }

    return 0;
}

void storage_crypto_record_attempt(bool success) {
    uint32_t now = get_time_ms();

    if (pin_attempt_count < PIN_RATE_LIMIT_MAX) {
        pin_attempt_times[pin_attempt_count++] = now;
    } else {
        memmove(pin_attempt_times, pin_attempt_times + 1,
                (PIN_RATE_LIMIT_MAX - 1) * sizeof(pin_attempt_times[0]));
        pin_attempt_times[PIN_RATE_LIMIT_MAX - 1] = now;
    }

    if (!success) {
        if (pin_consecutive_failures < UINT8_MAX) {
            pin_consecutive_failures++;
        }
        if (pin_consecutive_failures >= PIN_LOCKOUT_FAILURE_THRESH) {
            pin_lockout_until = now + PIN_LOCKOUT_MS;
            ESP_LOGW(TAG, "PIN lockout activated for %d seconds", PIN_LOCKOUT_MS / 1000);
        }
    } else {
        pin_consecutive_failures = 0;
    }
}

int storage_crypto_init(const char *pin) {
    int rate_limit = storage_crypto_check_rate_limit();
    if (rate_limit != 0) {
        return rate_limit;
    }

    size_t pin_len = pin ? strnlen(pin, STORAGE_CRYPTO_MAX_PIN_LEN + 1) : 0;
    if (pin_len == 0 || pin_len > STORAGE_CRYPTO_MAX_PIN_LEN) {
        storage_crypto_record_attempt(false);
        return ERR_PIN_INVALID;
    }

    uint8_t device_id[DEVICE_ID_SIZE];
    if (get_device_id(device_id) != 0) {
        return -1;
    }

    int ret = derive_key(device_id, sizeof(device_id), (const uint8_t *)pin, pin_len, storage_key);
    secure_memzero(device_id, sizeof(device_id));

    if (ret == 0) {
        key_initialized = true;
        storage_crypto_record_attempt(true);
    } else {
        storage_crypto_record_attempt(false);
    }
    return ret;
}

bool storage_crypto_is_initialized(void) {
    return key_initialized;
}

void storage_crypto_clear(void) {
    secure_memzero(storage_key, sizeof(storage_key));
    key_initialized = false;
}

static int gcm_init_with_key(mbedtls_gcm_context *gcm) {
    mbedtls_gcm_init(gcm);
    return mbedtls_gcm_setkey(gcm, MBEDTLS_CIPHER_ID_AES, storage_key, STORAGE_CRYPTO_KEY_SIZE * 8);
}

int storage_crypto_encrypt(const uint8_t *plaintext, size_t plaintext_len, const uint8_t *aad,
                           size_t aad_len, uint8_t nonce[STORAGE_CRYPTO_NONCE_SIZE],
                           uint8_t *ciphertext, uint8_t tag[STORAGE_CRYPTO_TAG_SIZE]) {
    if (!key_initialized || !plaintext || !nonce || !ciphertext || !tag) {
        return -1;
    }
    if (aad_len > 0 && !aad) {
        return -1;
    }
    if (rng_fill_checked(nonce, STORAGE_CRYPTO_NONCE_SIZE) != 0) {
        return -1;
    }

    mbedtls_gcm_context gcm;
    if (gcm_init_with_key(&gcm) != 0) {
        mbedtls_gcm_free(&gcm);
        return -1;
    }

    int ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plaintext_len, nonce,
                                        STORAGE_CRYPTO_NONCE_SIZE, aad, aad_len, plaintext,
                                        ciphertext, STORAGE_CRYPTO_TAG_SIZE, tag);
    mbedtls_gcm_free(&gcm);
    return (ret == 0) ? 0 : -1;
}

int storage_crypto_decrypt(const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t *aad,
                           size_t aad_len, const uint8_t nonce[STORAGE_CRYPTO_NONCE_SIZE],
                           const uint8_t tag[STORAGE_CRYPTO_TAG_SIZE], uint8_t *plaintext) {
    if (!key_initialized || !ciphertext || !nonce || !tag || !plaintext) {
        return -1;
    }
    if (aad_len > 0 && !aad) {
        return -1;
    }

    mbedtls_gcm_context gcm;
    if (gcm_init_with_key(&gcm) != 0) {
        mbedtls_gcm_free(&gcm);
        return -1;
    }

    int ret =
        mbedtls_gcm_auth_decrypt(&gcm, ciphertext_len, nonce, STORAGE_CRYPTO_NONCE_SIZE, aad,
                                 aad_len, tag, STORAGE_CRYPTO_TAG_SIZE, ciphertext, plaintext);
    mbedtls_gcm_free(&gcm);
    return (ret == 0) ? 0 : -1;
}

void storage_crypto_reset_rate_limit(void) {
    pin_attempt_count = 0;
    pin_lockout_until = 0;
    pin_consecutive_failures = 0;
    memset(pin_attempt_times, 0, sizeof(pin_attempt_times));
}
