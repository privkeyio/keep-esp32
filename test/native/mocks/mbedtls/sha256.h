#ifndef MBEDTLS_SHA256_H
#define MBEDTLS_SHA256_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    int dummy;
} mbedtls_sha256_context;

static inline void mbedtls_sha256_init(mbedtls_sha256_context *ctx) {
    (void)ctx;
}

static inline void mbedtls_sha256_free(mbedtls_sha256_context *ctx) {
    (void)ctx;
}

static inline int mbedtls_sha256_starts(mbedtls_sha256_context *ctx, int is224) {
    (void)ctx;
    (void)is224;
    return 0;
}

static inline int mbedtls_sha256_update(mbedtls_sha256_context *ctx, const uint8_t *input,
                                        size_t ilen) {
    (void)ctx;
    (void)input;
    (void)ilen;
    return 0;
}

static inline int mbedtls_sha256_finish(mbedtls_sha256_context *ctx, uint8_t *output) {
    (void)ctx;
    memset(output, 0x33, 32);
    return 0;
}

#endif
