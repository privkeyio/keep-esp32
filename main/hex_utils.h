#ifndef HEX_UTILS_H
#define HEX_UTILS_H

#include <stdint.h>
#include <stddef.h>

int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len);
void bytes_to_hex(const uint8_t *bytes, size_t len, char *out);

#endif
