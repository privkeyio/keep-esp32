#ifndef HEX_UTILS_H
#define HEX_UTILS_H

#include <stdint.h>
#include <stddef.h>

#if defined(ESP_PLATFORM) && ESP_PLATFORM
#include <nostr.h>

static inline int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    return nostr_hex_decode(hex, out, out_len);
}

static inline int bytes_to_hex(const uint8_t *bytes, size_t len, char *out, size_t out_size) {
    size_t required = len * 2 + 1;
    if (out_size < required)
        return -1;
    nostr_hex_encode(bytes, len, out);
    return 0;
}

#else

static inline int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    if (!hex || !out)
        return -1;
    size_t hex_len = 0;
    while (hex[hex_len])
        hex_len++;
    if (hex_len % 2 != 0)
        return -1;
    size_t byte_len = hex_len / 2;
    if (byte_len > out_len)
        return -1;
    for (size_t i = 0; i < byte_len; i++) {
        uint8_t hi, lo;
        char c = hex[i * 2];
        if (c >= '0' && c <= '9')
            hi = (uint8_t)(c - '0');
        else if (c >= 'a' && c <= 'f')
            hi = (uint8_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            hi = (uint8_t)(c - 'A' + 10);
        else
            return -1;
        c = hex[i * 2 + 1];
        if (c >= '0' && c <= '9')
            lo = (uint8_t)(c - '0');
        else if (c >= 'a' && c <= 'f')
            lo = (uint8_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            lo = (uint8_t)(c - 'A' + 10);
        else
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)byte_len;
}

static inline int bytes_to_hex(const uint8_t *bytes, size_t len, char *out, size_t out_size) {
    static const char hex_chars[] = "0123456789abcdef";
    size_t required = len * 2 + 1;
    if (out_size < required)
        return -1;
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex_chars[(bytes[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex_chars[bytes[i] & 0x0F];
    }
    out[len * 2] = '\0';
    return 0;
}

#endif

#endif
