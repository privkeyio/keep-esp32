#ifndef STORAGE_CRYPTO_H
#define STORAGE_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define STORAGE_CRYPTO_KEY_SIZE 32
#define STORAGE_CRYPTO_NONCE_SIZE 12
#define STORAGE_CRYPTO_TAG_SIZE 16
#define STORAGE_CRYPTO_MAX_PIN_LEN 64

static bool mock_crypto_initialized = true;

static inline int storage_crypto_init(const char *pin) {
    (void)pin;
    mock_crypto_initialized = true;
    return 0;
}

static inline bool storage_crypto_is_initialized(void) {
    return mock_crypto_initialized;
}

static inline void storage_crypto_clear(void) {
    mock_crypto_initialized = false;
}

static inline int storage_crypto_encrypt(const uint8_t *plaintext, size_t len,
                                         uint8_t nonce[STORAGE_CRYPTO_NONCE_SIZE],
                                         uint8_t *ciphertext,
                                         uint8_t tag[STORAGE_CRYPTO_TAG_SIZE]) {
    memset(nonce, 0x42, STORAGE_CRYPTO_NONCE_SIZE);
    memcpy(ciphertext, plaintext, len);
    memset(tag, 0x43, STORAGE_CRYPTO_TAG_SIZE);
    return 0;
}

static inline int storage_crypto_decrypt(const uint8_t *ciphertext, size_t len,
                                         const uint8_t nonce[STORAGE_CRYPTO_NONCE_SIZE],
                                         const uint8_t tag[STORAGE_CRYPTO_TAG_SIZE],
                                         uint8_t *plaintext) {
    (void)nonce;
    (void)tag;
    memcpy(plaintext, ciphertext, len);
    return 0;
}

#endif
