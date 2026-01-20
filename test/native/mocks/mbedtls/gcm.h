#ifndef MBEDTLS_GCM_H
#define MBEDTLS_GCM_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define MBEDTLS_GCM_ENCRYPT   1
#define MBEDTLS_CIPHER_ID_AES 0

typedef struct {
    int dummy;
} mbedtls_gcm_context;

static inline void mbedtls_gcm_init(mbedtls_gcm_context *ctx) {
    (void)ctx;
}

static inline void mbedtls_gcm_free(mbedtls_gcm_context *ctx) {
    (void)ctx;
}

static inline int mbedtls_gcm_setkey(mbedtls_gcm_context *ctx, int cipher, const uint8_t *key,
                                     unsigned int keybits) {
    (void)ctx;
    (void)cipher;
    (void)key;
    (void)keybits;
    return 0;
}

static inline int mbedtls_gcm_crypt_and_tag(mbedtls_gcm_context *ctx, int mode, size_t length,
                                            const uint8_t *iv, size_t iv_len, const uint8_t *add,
                                            size_t add_len, const uint8_t *input, uint8_t *output,
                                            size_t tag_len, uint8_t *tag) {
    (void)ctx;
    (void)mode;
    (void)iv;
    (void)iv_len;
    (void)add;
    (void)add_len;
    memcpy(output, input, length);
    memset(tag, 0x42, tag_len);
    return 0;
}

#endif
