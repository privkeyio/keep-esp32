// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include "storage_crypto.h"
#include "error_codes.h"
#include "random_utils.h"
#include "crypto_asm.h"
#include "secure_element.h"
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/sha256.h>
#include <stdbool.h>
#include <string.h>

#include "log_compat.h"

#ifdef ESP_PLATFORM
#include "esp_mac.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "nvs.h"
static uint64_t get_time_ms(void) {
    return (uint64_t)(esp_timer_get_time() / 1000);
}
#else
#include <time.h>
static uint64_t get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
#endif

#define TAG            "storage_crypto"
#define DEVICE_ID_SIZE 6

#define PIN_MAX_ATTEMPTS      21
#define PIN_PBKDF2_ITERATIONS 100000
#define PIN_PBKDF2_SALT_LEN   16

#define NVS_NAMESPACE    "pin_rl"
#define NVS_KEY_FAILURES "failures"
#define NVS_KEY_LOCKOUT  "lockout"
#define NVS_KEY_BRICKED  "bricked"
#define NVS_KEY_SALT     "salt"
#define NVS_KEY_HMAC     "hmac"
#define NVS_KEY_KDF_VER  "kdfver"

// Storage key derivation scheme. Persisted; absent means legacy (an existing
// device), so its shares stay decryptable. See [[kdf-version]].
#define KDF_VERSION_LEGACY 0
#define KDF_VERSION_PBKDF2 1

#define SE_SLOT_PIN_STATE 0
#define SE_SLOT_HMAC_KEY  1
#define HMAC_KEY_SIZE     32

typedef struct __attribute__((packed)) {
    uint8_t magic[4];
    uint8_t failed_attempts;
    uint64_t lockout_deadline;
    uint8_t bricked;
    uint8_t reserved[2];
} pin_state_t;

#define PIN_STATE_MAGIC "PIN\0"
#define PIN_STATE_SIZE  sizeof(pin_state_t)

static uint8_t storage_key[STORAGE_CRYPTO_KEY_SIZE];
static bool key_initialized = false;
static uint8_t pin_salt[PIN_PBKDF2_SALT_LEN];
static bool salt_initialized = false;

static pin_state_t pin_state;
static bool pin_state_loaded = false;
static bool se_available = false;

#ifdef UNIT_TEST
static uint8_t kdf_version_override = KDF_VERSION_LEGACY;
#endif

// Reads the persisted derivation-scheme marker. Absent (a device provisioned
// before the marker existed) resolves to legacy so its shares still decrypt.
static uint8_t get_kdf_version(void) {
#ifdef UNIT_TEST
    return kdf_version_override;
#elif defined(ESP_PLATFORM)
    uint8_t ver = KDF_VERSION_LEGACY;
    nvs_handle_t handle;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle) == ESP_OK) {
        nvs_get_u8(handle, NVS_KEY_KDF_VER, &ver);
        nvs_close(handle);
    }
    return ver;
#else
    return KDF_VERSION_LEGACY;
#endif
}

static int get_device_id(uint8_t device_id[DEVICE_ID_SIZE]);

static int get_hmac_secret_key(uint8_t key_out[HMAC_KEY_SIZE]) {
    if (se_available) {
        uint8_t se_data[SE_SLOT_SIZE];
        if (se_read_slot(SE_SLOT_HMAC_KEY, se_data, sizeof(se_data)) == SE_OK) {
            bool key_set = false;
            for (size_t i = 0; i < HMAC_KEY_SIZE; i++) {
                if (se_data[i] != 0) {
                    key_set = true;
                    break;
                }
            }
            if (key_set) {
                memcpy(key_out, se_data, HMAC_KEY_SIZE);
                secure_memzero(se_data, sizeof(se_data));
                return 0;
            }
        }
        if (rng_fill_checked(key_out, HMAC_KEY_SIZE) != 0) {
            return -1;
        }
        uint8_t se_write_data[SE_SLOT_SIZE];
        memset(se_write_data, 0, sizeof(se_write_data));
        memcpy(se_write_data, key_out, HMAC_KEY_SIZE);
        se_write_slot(SE_SLOT_HMAC_KEY, se_write_data, sizeof(se_write_data));
        secure_memzero(se_write_data, sizeof(se_write_data));
        return 0;
    }

#ifdef ESP_PLATFORM
    uint8_t serial[SE_SERIAL_SIZE];
    uint8_t device_id[DEVICE_ID_SIZE];
    if (get_device_id(device_id) != 0) {
        return -1;
    }
    if (se_get_serial(serial) == SE_OK) {
        mbedtls_sha256_context ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts(&ctx, 0);
        mbedtls_sha256_update(&ctx, serial, SE_SERIAL_SIZE);
        mbedtls_sha256_update(&ctx, device_id, DEVICE_ID_SIZE);
        mbedtls_sha256_finish(&ctx, key_out);
        mbedtls_sha256_free(&ctx);
        secure_memzero(serial, sizeof(serial));
        secure_memzero(device_id, sizeof(device_id));
        return 0;
    }
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, device_id, DEVICE_ID_SIZE);
    mbedtls_sha256_finish(&ctx, key_out);
    mbedtls_sha256_free(&ctx);
    secure_memzero(device_id, sizeof(device_id));
    return 0;
#else
    uint8_t device_id[DEVICE_ID_SIZE];
    if (get_device_id(device_id) != 0) {
        return -1;
    }
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, device_id, DEVICE_ID_SIZE);
    mbedtls_sha256_finish(&ctx, key_out);
    mbedtls_sha256_free(&ctx);
    secure_memzero(device_id, sizeof(device_id));
    return 0;
#endif
}

static int compute_state_hmac(const pin_state_t *state, uint8_t hmac_out[32]) {
    uint8_t secret_key[HMAC_KEY_SIZE];
    if (get_hmac_secret_key(secret_key) != 0) {
        secure_memzero(secret_key, sizeof(secret_key));
        return -1;
    }

    // Library HMAC-SHA256 (identical output to the previous hand-rolled
    // ipad/opad, verified) so a crypto failure returns an error instead of a
    // valid-looking MAC over garbage.
    int ret = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), secret_key,
                              HMAC_KEY_SIZE, (const uint8_t *)state, PIN_STATE_SIZE, hmac_out);
    secure_memzero(secret_key, sizeof(secret_key));
    return (ret == 0) ? 0 : -1;
}

static void load_pin_state(void) {
    if (pin_state_loaded) {
        return;
    }

    memcpy(pin_state.magic, PIN_STATE_MAGIC, 4);
    pin_state.failed_attempts = 0;
    pin_state.lockout_deadline = 0;
    pin_state.bricked = 0;
    memset(pin_state.reserved, 0, sizeof(pin_state.reserved));

    if (se_init() == SE_OK && se_is_provisioned()) {
        se_available = true;
        uint8_t se_data[SE_SLOT_SIZE];
        if (se_read_slot(SE_SLOT_PIN_STATE, se_data, sizeof(se_data)) == SE_OK) {
            if (memcmp(se_data, PIN_STATE_MAGIC, 4) == 0) {
                memcpy(&pin_state, se_data, PIN_STATE_SIZE);
            }
        }
    } else {
#ifdef ESP_PLATFORM
        nvs_handle_t handle;
        if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle) == ESP_OK) {
            uint8_t failures = 0;
            uint64_t lockout = 0;
            uint8_t bricked = 0;
            uint8_t stored_hmac[32];
            size_t hmac_len = sizeof(stored_hmac);

            nvs_get_u8(handle, NVS_KEY_FAILURES, &failures);
            nvs_get_u64(handle, NVS_KEY_LOCKOUT, &lockout);
            nvs_get_u8(handle, NVS_KEY_BRICKED, &bricked);

            pin_state_t temp_state;
            memcpy(temp_state.magic, PIN_STATE_MAGIC, 4);
            temp_state.failed_attempts = failures;
            temp_state.lockout_deadline = lockout;
            temp_state.bricked = bricked;
            memset(temp_state.reserved, 0, sizeof(temp_state.reserved));

            if (nvs_get_blob(handle, NVS_KEY_HMAC, stored_hmac, &hmac_len) == ESP_OK &&
                hmac_len == 32) {
                uint8_t computed_hmac[32];
                if (compute_state_hmac(&temp_state, computed_hmac) == 0 &&
                    secure_memcmp(stored_hmac, computed_hmac, 32) == 0) {
                    memcpy(&pin_state, &temp_state, sizeof(pin_state));
                }
            }
            nvs_close(handle);
        }
#endif
    }

    pin_state_loaded = true;
}

static void save_pin_state(void) {
    if (se_available) {
        uint8_t se_data[SE_SLOT_SIZE];
        memset(se_data, 0, sizeof(se_data));
        memcpy(se_data, &pin_state, PIN_STATE_SIZE);
        se_write_slot(SE_SLOT_PIN_STATE, se_data, sizeof(se_data));
    } else {
#ifdef ESP_PLATFORM
        nvs_handle_t handle;
        if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle) == ESP_OK) {
            uint8_t hmac[32];
            if (compute_state_hmac(&pin_state, hmac) != 0) {
                nvs_close(handle);
                return;
            }

            nvs_set_u8(handle, NVS_KEY_FAILURES, pin_state.failed_attempts);
            nvs_set_u64(handle, NVS_KEY_LOCKOUT, pin_state.lockout_deadline);
            nvs_set_u8(handle, NVS_KEY_BRICKED, pin_state.bricked);
            nvs_set_blob(handle, NVS_KEY_HMAC, hmac, sizeof(hmac));
            nvs_commit(handle);
            nvs_close(handle);
        }
#endif
    }
}

static int get_device_id(uint8_t device_id[DEVICE_ID_SIZE]) {
#ifdef ESP_PLATFORM
    return esp_read_mac(device_id, ESP_MAC_EFUSE_FACTORY) == ESP_OK ? 0 : -1;
#else
    FILE *fp = fopen("/etc/machine-id", "r");
    if (!fp) {
        ESP_LOGE(TAG, "Cannot read /etc/machine-id - device ID unavailable");
        return -1;
    }

    char buf[13] = {0};
    size_t bytes_read = fread(buf, 1, 12, fp);
    fclose(fp);

    if (bytes_read < 12) {
        ESP_LOGE(TAG, "Machine ID too short");
        return -1;
    }

    for (int i = 0; i < DEVICE_ID_SIZE; i++) {
        unsigned int val = 0;
        if (sscanf(buf + i * 2, "%2x", &val) != 1) {
            ESP_LOGE(TAG, "Invalid machine ID format");
            return -1;
        }
        device_id[i] = (uint8_t)val;
    }
    return 0;
#endif
}

static int init_or_load_salt(void) {
    if (salt_initialized) {
        return 0;
    }

#ifdef ESP_PLATFORM
    nvs_handle_t handle;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle) == ESP_OK) {
        size_t salt_len = PIN_PBKDF2_SALT_LEN;
        if (nvs_get_blob(handle, NVS_KEY_SALT, pin_salt, &salt_len) == ESP_OK &&
            salt_len == PIN_PBKDF2_SALT_LEN) {
            salt_initialized = true;
            nvs_close(handle);
            return 0;
        }
        if (rng_fill_checked(pin_salt, PIN_PBKDF2_SALT_LEN) != 0) {
            nvs_close(handle);
            return -1;
        }
        nvs_set_blob(handle, NVS_KEY_SALT, pin_salt, PIN_PBKDF2_SALT_LEN);
        nvs_commit(handle);
        nvs_close(handle);
        salt_initialized = true;
        return 0;
    }
    return -1;
#else
    if (rng_fill_checked(pin_salt, PIN_PBKDF2_SALT_LEN) != 0) {
        return -1;
    }
    salt_initialized = true;
    return 0;
#endif
}

static const uint8_t HKDF_INFO[] = "share-encryption-key";

// Legacy (v0.2.0) key derivation. Kept byte-for-byte so shares written before
// PBKDF2 was introduced still decrypt. See derive_key() and [[kdf-version]].
static const uint8_t HKDF_SALT[] = "keep-esp32-share-storage-v1";

static int derive_key_legacy(const uint8_t *device_id, size_t device_id_len, const uint8_t *pin,
                             size_t pin_len, uint8_t *key_out) {
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

static int derive_key_pbkdf2(const uint8_t *device_id, size_t device_id_len, const uint8_t *pin,
                             size_t pin_len, uint8_t *key_out) {
    if (init_or_load_salt() != 0) {
        return -1;
    }

    uint8_t pbkdf2_salt[PIN_PBKDF2_SALT_LEN + DEVICE_ID_SIZE];
    memcpy(pbkdf2_salt, pin_salt, PIN_PBKDF2_SALT_LEN);
    memcpy(pbkdf2_salt + PIN_PBKDF2_SALT_LEN, device_id, device_id_len);

    uint8_t stretched[32];
    int ret = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, pin, pin_len, pbkdf2_salt,
                                            PIN_PBKDF2_SALT_LEN + device_id_len,
                                            PIN_PBKDF2_ITERATIONS, sizeof(stretched), stretched);
    secure_memzero(pbkdf2_salt, sizeof(pbkdf2_salt));

    if (ret != 0) {
        secure_memzero(stretched, sizeof(stretched));
        return -1;
    }

    ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0, stretched,
                       sizeof(stretched), HKDF_INFO, sizeof(HKDF_INFO) - 1, key_out,
                       STORAGE_CRYPTO_KEY_SIZE);
    secure_memzero(stretched, sizeof(stretched));

    return (ret == 0) ? 0 : -1;
}

// [[kdf-version]] The active derivation is chosen by a persisted marker, default
// legacy so existing devices keep decrypting. PBKDF2 is staged but not yet
// activated at provisioning time (tracked separately); until then every device
// derives the proven legacy key.
static int derive_key(const uint8_t *device_id, size_t device_id_len, const uint8_t *pin,
                      size_t pin_len, uint8_t *key_out) {
    if (device_id_len > DEVICE_ID_SIZE || !pin || pin_len == 0) {
        return -1;
    }
    if (get_kdf_version() == KDF_VERSION_PBKDF2) {
        return derive_key_pbkdf2(device_id, device_id_len, pin, pin_len, key_out);
    }
    return derive_key_legacy(device_id, device_id_len, pin, pin_len, key_out);
}

static uint32_t get_delay_ms(uint8_t attempts) {
    if (attempts <= 3) {
        return 0;
    }
    if (attempts <= 6) {
        return 15 * 1000;
    }
    if (attempts <= 9) {
        return 60 * 1000;
    }
    if (attempts <= (PIN_MAX_ATTEMPTS - 1)) {
        return 15 * 60 * 1000;
    }
    return UINT32_MAX;
}

static void wipe_secrets(void) {
    secure_memzero(storage_key, sizeof(storage_key));
    key_initialized = false;

#ifdef ESP_PLATFORM
    nvs_handle_t handle;
    if (nvs_open("storage", NVS_READWRITE, &handle) == ESP_OK) {
        nvs_erase_all(handle);
        nvs_commit(handle);
        nvs_close(handle);
    }
#endif

    if (se_available) {
        uint8_t zeros[SE_SLOT_SIZE];
        memset(zeros, 0, sizeof(zeros));
        for (int i = 1; i < SE_SLOT_COUNT; i++) {
            se_write_slot(i, zeros, sizeof(zeros));
        }
    }
}

int storage_crypto_check_rate_limit(void) {
    load_pin_state();

    if (pin_state.bricked) {
        return ERR_PIN_BRICKED;
    }

    if (pin_state.failed_attempts >= PIN_MAX_ATTEMPTS) {
        return ERR_PIN_BRICKED;
    }

    uint32_t delay_ms = get_delay_ms(pin_state.failed_attempts);
    if (delay_ms == UINT32_MAX) {
        return ERR_PIN_BRICKED;
    }

    if (pin_state.lockout_deadline > 0) {
        uint64_t now = get_time_ms();
        if (now < pin_state.lockout_deadline) {
            return ERR_PIN_MUST_WAIT;
        }
    }

    return 0;
}

void storage_crypto_record_attempt(bool success) {
    load_pin_state();

    if (success) {
        pin_state.failed_attempts = 0;
        pin_state.lockout_deadline = 0;
    } else {
        if (pin_state.failed_attempts < UINT8_MAX) {
            pin_state.failed_attempts++;
        }

        if (pin_state.failed_attempts >= PIN_MAX_ATTEMPTS) {
            ESP_LOGE(TAG, "Max PIN attempts exceeded - wiping device");
            pin_state.bricked = 1;
            save_pin_state();
            wipe_secrets();
            return;
        }

        uint32_t delay_ms = get_delay_ms(pin_state.failed_attempts);
        if (delay_ms > 0 && delay_ms != UINT32_MAX) {
            pin_state.lockout_deadline = get_time_ms() + delay_ms;
            ESP_LOGW(TAG, "PIN attempt %d/%d - next attempt in %lu seconds",
                     pin_state.failed_attempts, PIN_MAX_ATTEMPTS, (unsigned long)(delay_ms / 1000));
        } else {
            pin_state.lockout_deadline = 0;
        }
    }
    save_pin_state();
}

uint8_t storage_crypto_get_attempts(void) {
    load_pin_state();
    return pin_state.failed_attempts;
}

uint8_t storage_crypto_get_max_attempts(void) {
    return PIN_MAX_ATTEMPTS;
}

uint32_t storage_crypto_get_delay_remaining(void) {
    load_pin_state();

    if (pin_state.bricked || pin_state.failed_attempts >= PIN_MAX_ATTEMPTS) {
        return UINT32_MAX;
    }

    if (pin_state.lockout_deadline == 0) {
        return 0;
    }

    uint64_t now = get_time_ms();
    if (now >= pin_state.lockout_deadline) {
        return 0;
    }
    return (uint32_t)(pin_state.lockout_deadline - now);
}

bool storage_crypto_is_bricked(void) {
    load_pin_state();
    return pin_state.bricked != 0 || pin_state.failed_attempts >= PIN_MAX_ATTEMPTS;
}

int storage_crypto_init(const char *pin) {
    load_pin_state();

    if (pin_state.bricked || pin_state.failed_attempts >= PIN_MAX_ATTEMPTS) {
        return ERR_PIN_BRICKED;
    }

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
    KEEP_ASSERT(plaintext != NULL);
    KEEP_ASSERT(nonce != NULL);
    KEEP_ASSERT(ciphertext != NULL);
    KEEP_ASSERT(tag != NULL);
    KEEP_ASSERT(plaintext_len > 0);

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
    KEEP_ASSERT(ciphertext != NULL);
    KEEP_ASSERT(nonce != NULL);
    KEEP_ASSERT(tag != NULL);
    KEEP_ASSERT(plaintext != NULL);
    KEEP_ASSERT(ciphertext_len > 0);

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

#ifdef UNIT_TEST
void storage_crypto_reset_rate_limit(void) {
    memcpy(pin_state.magic, PIN_STATE_MAGIC, 4);
    pin_state.failed_attempts = 0;
    pin_state.lockout_deadline = 0;
    pin_state.bricked = 0;
    memset(pin_state.reserved, 0, sizeof(pin_state.reserved));
    pin_state_loaded = true;
    salt_initialized = false;
    se_available = false;
}

void storage_crypto_set_attempts_for_test(uint8_t attempts) {
    load_pin_state();
    pin_state.failed_attempts = attempts;
    uint32_t delay_ms = get_delay_ms(attempts);
    if (delay_ms > 0 && delay_ms != UINT32_MAX) {
        pin_state.lockout_deadline = get_time_ms() + delay_ms;
    } else {
        pin_state.lockout_deadline = 0;
    }
}

void storage_crypto_set_bricked_for_test(bool bricked) {
    load_pin_state();
    pin_state.bricked = bricked ? 1 : 0;
}
#endif
