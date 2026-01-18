#ifndef CRYPTO_ASM_H
#define CRYPTO_ASM_H

#include <stddef.h>
#include <stdint.h>

static inline void secure_memzero(void *ptr, size_t len) {
    volatile uint8_t *p = ptr;
    while (len--) *p++ = 0;
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

static inline int ct_is_zero(const void *ptr, size_t len) {
    const uint8_t *p = ptr;
    uint8_t acc = 0;
    for (size_t i = 0; i < len; i++) {
        acc |= p[i];
    }
    return acc == 0 ? 1 : 0;
}

#endif
