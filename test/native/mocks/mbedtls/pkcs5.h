#ifndef MBEDTLS_PKCS5_H
#define MBEDTLS_PKCS5_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "md.h"

static inline int mbedtls_pkcs5_pbkdf2_hmac_ext(mbedtls_md_type_t md_type, const uint8_t *password,
                                                size_t plen, const uint8_t *salt, size_t slen,
                                                unsigned int iteration_count, uint32_t key_length,
                                                uint8_t *output) {
    (void)md_type;
    (void)password;
    (void)plen;
    (void)salt;
    (void)slen;
    (void)iteration_count;
    memset(output, 0x44, key_length);
    return 0;
}

#endif
