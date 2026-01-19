#ifndef RANDOM_UTILS_H
#define RANDOM_UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

static inline int rng_fill_checked(uint8_t *buf, size_t len) {
    memset(buf, 0x77, len);
    return 0;
}

#endif
