// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef STORAGE_CRYPTO_H
#define STORAGE_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define STORAGE_CRYPTO_KEY_SIZE    32
#define STORAGE_CRYPTO_NONCE_SIZE  12
#define STORAGE_CRYPTO_TAG_SIZE    16
#define STORAGE_CRYPTO_MAX_PIN_LEN 64

int storage_crypto_init(const char *pin);
bool storage_crypto_is_initialized(void);
void storage_crypto_clear(void);

int storage_crypto_check_rate_limit(void);
void storage_crypto_record_attempt(bool success);
void storage_crypto_reset_rate_limit(void);

int storage_crypto_encrypt(const uint8_t *plaintext, size_t plaintext_len, const uint8_t *aad,
                           size_t aad_len, uint8_t nonce[STORAGE_CRYPTO_NONCE_SIZE],
                           uint8_t *ciphertext, uint8_t tag[STORAGE_CRYPTO_TAG_SIZE]);

int storage_crypto_decrypt(const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t *aad,
                           size_t aad_len, const uint8_t nonce[STORAGE_CRYPTO_NONCE_SIZE],
                           const uint8_t tag[STORAGE_CRYPTO_TAG_SIZE], uint8_t *plaintext);

#endif
