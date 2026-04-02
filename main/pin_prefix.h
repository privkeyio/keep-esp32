// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef PIN_PREFIX_H
#define PIN_PREFIX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PIN_PREFIX_MAX_LEN    4
#define PIN_PREFIX_MIN_LEN    2
#define PIN_PREFIX_WORD_COUNT 2
#define BIP39_WORD_COUNT      2048
#define BIP39_MAX_WORD_LEN    8

typedef struct {
    uint8_t digits[PIN_PREFIX_MAX_LEN];
    uint8_t len;
} pin_prefix_t;

int pin_prefix_derive_words(const pin_prefix_t *prefix, const uint8_t *device_secret,
                            size_t secret_len, uint16_t *word1_index, uint16_t *word2_index);

const char *bip39_get_word(uint16_t index);

int pin_prefix_get_words(const pin_prefix_t *prefix, const uint8_t *device_secret,
                         size_t secret_len, char *word1, size_t word1_size, char *word2,
                         size_t word2_size);

int pin_prefix_set_digit(pin_prefix_t *prefix, uint8_t digit);

void pin_prefix_clear(pin_prefix_t *prefix);

bool pin_prefix_is_ready(const pin_prefix_t *prefix);

#endif
