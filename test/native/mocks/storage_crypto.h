// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

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
static int mock_rate_limit_result = 0;
static uint8_t mock_pin_attempts = 0;
static bool mock_is_bricked = false;

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

static inline int storage_crypto_check_rate_limit(void) {
    return mock_rate_limit_result;
}

static int mock_record_success_calls = 0;
static int mock_record_failure_calls = 0;

static inline void storage_crypto_record_attempt(bool success) {
    if (success) {
        mock_record_success_calls++;
        mock_pin_attempts = 0;
    } else {
        mock_record_failure_calls++;
        mock_pin_attempts++;
    }
}

static inline uint8_t storage_crypto_get_attempts(void) {
    return mock_pin_attempts;
}

static inline uint8_t storage_crypto_get_max_attempts(void) {
    return 21;
}

static inline uint32_t storage_crypto_get_delay_remaining(void) {
    return 0;
}

static inline bool storage_crypto_is_bricked(void) {
    return mock_is_bricked;
}

#ifdef UNIT_TEST
static inline void storage_crypto_reset_rate_limit(void) {
    mock_rate_limit_result = 0;
    mock_pin_attempts = 0;
    mock_is_bricked = false;
    mock_record_success_calls = 0;
    mock_record_failure_calls = 0;
}
#endif

static inline int storage_crypto_init(const char *pin) {
    int rate_limit = storage_crypto_check_rate_limit();
    if (rate_limit != 0) {
        return rate_limit;
    }
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
