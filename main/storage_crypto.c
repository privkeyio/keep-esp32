#include "storage_crypto.h"
#include "random_utils.h"
#include "crypto_asm.h"
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <string.h>

#ifdef ESP_PLATFORM
#include "esp_mac.h"
#include "esp_log.h"
#else
#include <stdio.h>
#define ESP_LOGW(tag, ...) fprintf(stderr, "W (%s): ", tag); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n")
#endif

#define TAG "storage_crypto"

#define DEVICE_ID_SIZE 6

static uint8_t storage_key[STORAGE_CRYPTO_KEY_SIZE];
static int key_initialized = 0;

static int get_device_id(uint8_t device_id[DEVICE_ID_SIZE]) {
#ifdef ESP_PLATFORM
    return esp_read_mac(device_id, ESP_MAC_EFUSE_FACTORY) == ESP_OK ? 0 : -1;
#else
    memset(device_id, 0x42, DEVICE_ID_SIZE);
    FILE *fp = fopen("/etc/machine-id", "r");
    if (!fp) return 0;

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

static int derive_key(const uint8_t *device_id, size_t device_id_len,
                      const uint8_t *pin, size_t pin_len,
                      uint8_t *key_out) {
    uint8_t ikm[DEVICE_ID_SIZE + STORAGE_CRYPTO_MAX_PIN_LEN];
    size_t ikm_len = device_id_len;

    memcpy(ikm, device_id, device_id_len);
    if (pin && pin_len > 0) {
        size_t copy_len = pin_len < STORAGE_CRYPTO_MAX_PIN_LEN ? pin_len : STORAGE_CRYPTO_MAX_PIN_LEN;
        memcpy(ikm + device_id_len, pin, copy_len);
        ikm_len += copy_len;
    }

    static const uint8_t salt[] = "keep-esp32-share-storage-v1";
    static const uint8_t info[] = "share-encryption-key";

    int ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                           salt, sizeof(salt) - 1,
                           ikm, ikm_len,
                           info, sizeof(info) - 1,
                           key_out, STORAGE_CRYPTO_KEY_SIZE);

    secure_memzero(ikm, sizeof(ikm));
    return ret == 0 ? 0 : -1;
}

int storage_crypto_init(const char *pin) {
    uint8_t device_id[DEVICE_ID_SIZE];

    if (get_device_id(device_id) != 0) {
        return -1;
    }

    size_t pin_len = pin ? strnlen(pin, STORAGE_CRYPTO_MAX_PIN_LEN + 1) : 0;
    if (pin_len > STORAGE_CRYPTO_MAX_PIN_LEN) {
        secure_memzero(device_id, sizeof(device_id));
        return -1;
    }

    if (!pin || pin_len == 0) {
        ESP_LOGW(TAG, "No PIN provided - using device-derived key only (not PIN-protected)");
    }

    int ret = derive_key(device_id, sizeof(device_id),
                         (const uint8_t *)pin, pin_len,
                         storage_key);
    secure_memzero(device_id, sizeof(device_id));

    key_initialized = (ret == 0);
    return ret;
}

int storage_crypto_is_initialized(void) {
    return key_initialized;
}

void storage_crypto_clear(void) {
    secure_memzero(storage_key, sizeof(storage_key));
    key_initialized = 0;
}

static int gcm_init_with_key(mbedtls_gcm_context *gcm) {
    mbedtls_gcm_init(gcm);
    return mbedtls_gcm_setkey(gcm, MBEDTLS_CIPHER_ID_AES,
                               storage_key, STORAGE_CRYPTO_KEY_SIZE * 8);
}

int storage_crypto_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                           uint8_t nonce[STORAGE_CRYPTO_NONCE_SIZE],
                           uint8_t *ciphertext,
                           uint8_t tag[STORAGE_CRYPTO_TAG_SIZE]) {
    if (!key_initialized || !plaintext || !nonce || !ciphertext || !tag) return -1;
    if (secure_random_fill(nonce, STORAGE_CRYPTO_NONCE_SIZE) != 0) return -1;

    mbedtls_gcm_context gcm;
    if (gcm_init_with_key(&gcm) != 0) {
        mbedtls_gcm_free(&gcm);
        return -1;
    }

    int ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
                                         plaintext_len,
                                         nonce, STORAGE_CRYPTO_NONCE_SIZE,
                                         NULL, 0,
                                         plaintext, ciphertext,
                                         STORAGE_CRYPTO_TAG_SIZE, tag);
    mbedtls_gcm_free(&gcm);
    return ret == 0 ? 0 : -1;
}

int storage_crypto_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                           const uint8_t nonce[STORAGE_CRYPTO_NONCE_SIZE],
                           const uint8_t tag[STORAGE_CRYPTO_TAG_SIZE],
                           uint8_t *plaintext) {
    if (!key_initialized || !ciphertext || !nonce || !tag || !plaintext) return -1;

    mbedtls_gcm_context gcm;
    if (gcm_init_with_key(&gcm) != 0) {
        mbedtls_gcm_free(&gcm);
        return -1;
    }

    int ret = mbedtls_gcm_auth_decrypt(&gcm, ciphertext_len,
                                        nonce, STORAGE_CRYPTO_NONCE_SIZE,
                                        NULL, 0,
                                        tag, STORAGE_CRYPTO_TAG_SIZE,
                                        ciphertext, plaintext);
    mbedtls_gcm_free(&gcm);
    return ret == 0 ? 0 : -1;
}
