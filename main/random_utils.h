#ifndef RANDOM_UTILS_H
#define RANDOM_UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <nostr.h>

static inline int secure_random_fill(uint8_t *buf, size_t len) {
    return nostr_random_bytes(buf, len) == 1 ? 0 : -1;
}

#endif
