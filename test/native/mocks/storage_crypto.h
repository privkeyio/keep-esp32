// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef STORAGE_CRYPTO_H
#define STORAGE_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define STORAGE_CRYPTO_KEY_SIZE    32
#define STORAGE_CRYPTO_NONCE_SIZE  12
#define STORAGE_CRYPTO_TAG_SIZE    16
#define STORAGE_CRYPTO_MAX_PIN_LEN 64

static bool mock_crypto_initialized = true;

static uint8_t mock_last_encrypt_aad[128];
static size_t mock_last_encrypt_aad_len = 0;
static uint8_t mock_last_decrypt_aad[128];
static size_t mock_last_decrypt_aad_len = 0;

static inline void mock_crypto_reset_aad(void) {
    memset(mock_last_encrypt_aad, 0, sizeof(mock_last_encrypt_aad));
    mock_last_encrypt_aad_len = 0;
    memset(mock_last_decrypt_aad, 0, sizeof(mock_last_decrypt_aad));
    mock_last_decrypt_aad_len = 0;
}

static inline int storage_crypto_init(const char *pin) {
    size_t pin_len = pin ? strlen(pin) : 0;
    if (pin_len == 0 || pin_len > STORAGE_CRYPTO_MAX_PIN_LEN) {
        return -1;
    }
    mock_crypto_initialized = true;
    return 0;
}

static inline bool storage_crypto_is_initialized(void) {
    return mock_crypto_initialized;
}

static inline void storage_crypto_clear(void) {
    mock_crypto_initialized = false;
}

static inline int storage_crypto_encrypt(const uint8_t *plaintext, size_t len, const uint8_t *aad,
                                         size_t aad_len, uint8_t nonce[STORAGE_CRYPTO_NONCE_SIZE],
                                         uint8_t *ciphertext,
                                         uint8_t tag[STORAGE_CRYPTO_TAG_SIZE]) {
    if (aad && aad_len > 0 && aad_len <= sizeof(mock_last_encrypt_aad)) {
        memcpy(mock_last_encrypt_aad, aad, aad_len);
        mock_last_encrypt_aad_len = aad_len;
    } else {
        mock_last_encrypt_aad_len = 0;
    }
    memset(nonce, 0x42, STORAGE_CRYPTO_NONCE_SIZE);
    memcpy(ciphertext, plaintext, len);
    memset(tag, 0x43, STORAGE_CRYPTO_TAG_SIZE);
    return 0;
}

static inline int storage_crypto_decrypt(const uint8_t *ciphertext, size_t len, const uint8_t *aad,
                                         size_t aad_len,
                                         const uint8_t nonce[STORAGE_CRYPTO_NONCE_SIZE],
                                         const uint8_t tag[STORAGE_CRYPTO_TAG_SIZE],
                                         uint8_t *plaintext) {
    if (aad && aad_len > 0 && aad_len <= sizeof(mock_last_decrypt_aad)) {
        memcpy(mock_last_decrypt_aad, aad, aad_len);
        mock_last_decrypt_aad_len = aad_len;
    } else {
        mock_last_decrypt_aad_len = 0;
    }
    (void)nonce;
    (void)tag;
    memcpy(plaintext, ciphertext, len);
    return 0;
}

#endif
