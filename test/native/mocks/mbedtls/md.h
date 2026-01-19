#ifndef MBEDTLS_MD_H
#define MBEDTLS_MD_H

#include <stddef.h>
#include <stdint.h>

typedef enum { MBEDTLS_MD_SHA256 = 6 } mbedtls_md_type_t;

typedef struct mbedtls_md_info_t {
    int type;
} mbedtls_md_info_t;

typedef struct {
    int dummy;
} mbedtls_md_context_t;

static const mbedtls_md_info_t mock_sha256_info = {MBEDTLS_MD_SHA256};

static inline const mbedtls_md_info_t *mbedtls_md_info_from_type(mbedtls_md_type_t type) {
    (void)type;
    return &mock_sha256_info;
}

static inline void mbedtls_md_init(mbedtls_md_context_t *ctx) {
    (void)ctx;
}

static inline void mbedtls_md_free(mbedtls_md_context_t *ctx) {
    (void)ctx;
}

static inline int mbedtls_md_setup(mbedtls_md_context_t *ctx, const mbedtls_md_info_t *info,
                                   int hmac) {
    (void)ctx;
    (void)info;
    (void)hmac;
    return 0;
}

#endif
