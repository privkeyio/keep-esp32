#ifndef HEX_UTILS_H
#define HEX_UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <nostr.h>

static inline int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    return nostr_hex_decode(hex, out, out_len);
}

static inline void bytes_to_hex(const uint8_t *bytes, size_t len, char *out) {
    nostr_hex_encode(bytes, len, out);
}

#endif
