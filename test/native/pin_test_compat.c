// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

// Native-only support for test_pin_attempt_limit so it exercises the REAL
// storage_crypto crypto (SHA-256, HMAC, GCM, HKDF, PBKDF2) instead of stubs.
//
//   - crypto_asm is hand-written assembly on device; provide C equivalents here.
//   - mbedtls_pkcs5_pbkdf2_hmac_ext is mbedtls 3.x (what ESP-IDF ships). Host
//     mbedtls is often 2.28, which only has the older context-based API, so
//     bridge to it when the _ext symbol is absent.

#include <stddef.h>
#include <stdint.h>

void secure_memzero(void *ptr, size_t len) {
    volatile uint8_t *p = ptr;
    while (len--)
        *p++ = 0;
}

int ct_compare(const void *a, const void *b, size_t len) {
    const uint8_t *pa = a;
    const uint8_t *pb = b;
    uint8_t acc = 0;
    for (size_t i = 0; i < len; i++)
        acc |= pa[i] ^ pb[i];
    return acc;
}

#include <mbedtls/version.h>

#if MBEDTLS_VERSION_NUMBER < 0x03000000
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>

int mbedtls_pkcs5_pbkdf2_hmac_ext(mbedtls_md_type_t md_type, const unsigned char *password,
                                  size_t plen, const unsigned char *salt, size_t slen,
                                  unsigned int iteration_count, uint32_t key_length,
                                  unsigned char *output) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    int ret = mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
    if (ret == 0) {
        ret = mbedtls_pkcs5_pbkdf2_hmac(&ctx, password, plen, salt, slen, iteration_count,
                                        key_length, output);
    }
    mbedtls_md_free(&ctx);
    return ret;
}
#endif
