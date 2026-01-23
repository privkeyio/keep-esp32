#ifndef MBEDTLS_GCM_H
#define MBEDTLS_GCM_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define MBEDTLS_GCM_ENCRYPT   1
#define MBEDTLS_CIPHER_ID_AES 0

static uint8_t mock_gcm_key[32];
static uint8_t mock_gcm_expected_ct[16];
static uint8_t mock_gcm_expected_tag[16];

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
    (void)keybits;
    memcpy(mock_gcm_key, key, 32);
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
    static const uint8_t expected_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const uint8_t expected_ct[16] = {
        0x0e, 0xbc, 0xb5, 0xde, 0xb5, 0x2c, 0x83, 0xbd,
        0x08, 0xa8, 0xa9, 0x35, 0x18, 0x2c, 0x91, 0x99
    };
    static const uint8_t expected_tag_v[16] = {
        0x38, 0x62, 0x64, 0x29, 0x86, 0xc9, 0x53, 0xe8,
        0x7b, 0x3c, 0xe9, 0x9b, 0x0d, 0xec, 0xdf, 0x34
    };
    if (length == 16 && memcmp(mock_gcm_key, expected_key, 32) == 0) {
        memcpy(output, expected_ct, 16);
        memcpy(tag, expected_tag_v, 16);
        memcpy(mock_gcm_expected_ct, expected_ct, 16);
        memcpy(mock_gcm_expected_tag, expected_tag_v, 16);
    } else {
        memcpy(output, input, length);
        memset(tag, 0x42, tag_len);
    }
    return 0;
}

static inline int mbedtls_gcm_auth_decrypt(mbedtls_gcm_context *ctx, size_t length,
                                            const uint8_t *iv, size_t iv_len,
                                            const uint8_t *add, size_t add_len,
                                            const uint8_t *tag, size_t tag_len,
                                            const uint8_t *input, uint8_t *output) {
    (void)ctx;
    (void)iv;
    (void)iv_len;
    (void)add;
    (void)add_len;
    if (length == 16 && memcmp(input, mock_gcm_expected_ct, 16) == 0 &&
        memcmp(tag, mock_gcm_expected_tag, tag_len) == 0) {
        memset(output, 0, 16);
        return 0;
    }
    memcpy(output, input, length);
    return 0;
}

#endif
