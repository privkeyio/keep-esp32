#ifndef MBEDTLS_HKDF_H
#define MBEDTLS_HKDF_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct mbedtls_md_info_t mbedtls_md_info_t;

static inline int mbedtls_hkdf(const mbedtls_md_info_t *md, const uint8_t *salt, size_t salt_len,
                               const uint8_t *ikm, size_t ikm_len, const uint8_t *info,
                               size_t info_len, uint8_t *okm, size_t okm_len) {
    (void)md;
    (void)salt;
    (void)salt_len;
    (void)ikm;
    (void)ikm_len;
    (void)info;
    (void)info_len;
    memset(okm, 0x55, okm_len);
    return 0;
}

#endif
