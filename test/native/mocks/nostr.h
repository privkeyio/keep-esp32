// SPDX-FileCopyrightText: © 2026 Privkey Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef NOSTR_H
#define NOSTR_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

static inline int nostr_random_bytes(uint8_t *buf, size_t len) {
    FILE *fp = fopen("/dev/urandom", "r");
    if (!fp)
        return 0;
    size_t n = fread(buf, 1, len, fp);
    fclose(fp);
    return n == len ? 1 : 0;
}

static inline int hex_char_value(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static inline int nostr_hex_decode(const char *hex, uint8_t *out, size_t out_len) {
    if (!hex || !out)
        return -1;
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0)
        return -1;
    size_t byte_len = hex_len / 2;
    if (byte_len > out_len)
        return -1;

    for (size_t i = 0; i < byte_len; i++) {
        int hi = hex_char_value(hex[i * 2]);
        int lo = hex_char_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)byte_len;
}

static inline void nostr_hex_encode(const uint8_t *bytes, size_t len, char *out) {
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex_chars[(bytes[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex_chars[bytes[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

#endif
