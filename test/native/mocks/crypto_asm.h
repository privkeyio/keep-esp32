// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#ifndef CRYPTO_ASM_H
#define CRYPTO_ASM_H

#include <stddef.h>
#include <stdint.h>

static inline void secure_memzero(void *ptr, size_t len) {
    volatile uint8_t *p = ptr;
    while (len--)
        *p++ = 0;
}

static inline int ct_compare(const void *a, const void *b, size_t len) {
    const uint8_t *pa = a;
    const uint8_t *pb = b;
    uint8_t acc = 0;
    for (size_t i = 0; i < len; i++) {
        acc |= pa[i] ^ pb[i];
    }
    return acc;
}

static inline int secure_memcmp(const void *a, const void *b, size_t len) {
    return ct_compare(a, b, len);
}

static inline int ct_is_zero(const void *ptr, size_t len) {
    const uint8_t *p = ptr;
    uint8_t acc = 0;
    for (size_t i = 0; i < len; i++) {
        acc |= p[i];
    }
    return acc == 0 ? 1 : 0;
}

static inline uint32_t ct_select32(uint32_t a, uint32_t b, uint32_t condition) {
    uint32_t mask = (uint32_t)(-(int32_t)(condition != 0));
    return (a & ~mask) | (b & mask);
}

static inline void ct_select_bytes(void *out, const void *a, const void *b, size_t len,
                                   uint32_t condition) {
    const uint8_t *pa = a;
    const uint8_t *pb = b;
    uint8_t *po = out;
    uint8_t mask = (uint8_t)(-(int8_t)(condition != 0));
    for (size_t i = 0; i < len; i++) {
        po[i] = (pa[i] & ~mask) | (pb[i] & mask);
    }
}

#endif
