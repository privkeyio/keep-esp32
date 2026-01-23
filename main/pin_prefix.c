// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "pin_prefix.h"
#include "bip39_wordlist.h"
#include "crypto_asm.h"
#include <mbedtls/md.h>
#include <stdbool.h>
#include <string.h>

_Static_assert(sizeof(BIP39_WORDLIST) / sizeof(BIP39_WORDLIST[0]) == BIP39_WORD_COUNT,
               "BIP39_WORDLIST size mismatch");

#define HMAC_OUTPUT_SIZE      32
#define ANTI_PHISHING_CONTEXT "anti-phishing"
#define CONTEXT_LEN           13
#define SECRET_LEN_MAX        1024

int pin_prefix_derive_words(const pin_prefix_t *prefix, const uint8_t *device_secret,
                            size_t secret_len, uint16_t *word1_index, uint16_t *word2_index) {
    if (!prefix || !device_secret || !word1_index || !word2_index) {
        return -1;
    }
    if (prefix->len < PIN_PREFIX_MIN_LEN || prefix->len > PIN_PREFIX_MAX_LEN) {
        return -1;
    }
    if (secret_len == 0 || secret_len > SECRET_LEN_MAX) {
        return -1;
    }

    uint8_t input[CONTEXT_LEN + PIN_PREFIX_MAX_LEN];
    memcpy(input, ANTI_PHISHING_CONTEXT, CONTEXT_LEN);
    memcpy(input + CONTEXT_LEN, prefix->digits, prefix->len);
    size_t input_len = CONTEXT_LEN + prefix->len;

    uint8_t hmac_out[HMAC_OUTPUT_SIZE];
    int ret = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), device_secret,
                              secret_len, input, input_len, hmac_out);

    secure_memzero(input, sizeof(input));

    if (ret != 0) {
        secure_memzero(hmac_out, sizeof(hmac_out));
        return -1;
    }

    *word1_index = ((uint16_t)hmac_out[0] << 3 | hmac_out[1] >> 5) & 0x7FF;
    *word2_index = ((uint16_t)(hmac_out[1] & 0x1F) << 6 | hmac_out[2] >> 2) & 0x7FF;

    secure_memzero(hmac_out, sizeof(hmac_out));
    return 0;
}

const char *bip39_get_word(uint16_t index) {
    if (index >= BIP39_WORD_COUNT) {
        return NULL;
    }
    return BIP39_WORDLIST[index];
}

int pin_prefix_get_words(const pin_prefix_t *prefix, const uint8_t *device_secret,
                         size_t secret_len, char *word1, size_t word1_size, char *word2,
                         size_t word2_size) {
    if (!word1 || !word2 || word1_size == 0 || word2_size == 0) {
        return -1;
    }

    uint16_t idx1, idx2;
    if (pin_prefix_derive_words(prefix, device_secret, secret_len, &idx1, &idx2) != 0) {
        return -1;
    }

    const char *w1 = bip39_get_word(idx1);
    const char *w2 = bip39_get_word(idx2);
    if (!w1 || !w2) {
        return -1;
    }

    size_t len1 = strlen(w1);
    size_t len2 = strlen(w2);
    if (len1 >= word1_size || len2 >= word2_size) {
        return -1;
    }

    memcpy(word1, w1, len1 + 1);
    memcpy(word2, w2, len2 + 1);
    return 0;
}

int pin_prefix_set_digit(pin_prefix_t *prefix, uint8_t digit) {
    if (!prefix) {
        return -1;
    }
    if (digit > 9) {
        return -1;
    }
    if (prefix->len >= PIN_PREFIX_MAX_LEN) {
        return -1;
    }
    prefix->digits[prefix->len++] = digit;
    return 0;
}

void pin_prefix_clear(pin_prefix_t *prefix) {
    if (prefix) {
        secure_memzero(prefix, sizeof(*prefix));
    }
}

bool pin_prefix_is_ready(const pin_prefix_t *prefix) {
    if (!prefix) {
        return false;
    }
    return prefix->len >= PIN_PREFIX_MIN_LEN;
}
