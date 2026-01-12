#ifndef CRYPTO_ASM_H
#define CRYPTO_ASM_H

#include <stddef.h>
#include <stdint.h>

static inline void secure_memzero(void *ptr, size_t len) {
    volatile uint8_t *p = ptr;
    while (len--) *p++ = 0;
}

#endif
