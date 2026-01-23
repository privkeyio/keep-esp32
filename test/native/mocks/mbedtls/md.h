#ifndef MBEDTLS_MD_H
#define MBEDTLS_MD_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

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

#ifdef HAS_OPENSSL
#include <openssl/hmac.h>
#include <openssl/evp.h>

static inline int mbedtls_md_hmac(const mbedtls_md_info_t *md_info, const unsigned char *key,
                                  size_t keylen, const unsigned char *input, size_t ilen,
                                  unsigned char *output) {
    (void)md_info;
    unsigned int out_len = 32;
    if (HMAC(EVP_sha256(), key, (int)keylen, input, ilen, output, &out_len) == NULL) {
        return -1;
    }
    return 0;
}

#else

static inline uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static inline void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    static const uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2};
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) | block[i * 4 + 3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + k[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

static inline void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint32_t state[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint8_t block[64];
    size_t i;
    for (i = 0; i + 64 <= len; i += 64) {
        sha256_transform(state, data + i);
    }
    size_t rem = len - i;
    memset(block, 0, 64);
    memcpy(block, data + i, rem);
    block[rem] = 0x80;
    if (rem >= 56) {
        sha256_transform(state, block);
        memset(block, 0, 64);
    }
    uint64_t bits = (uint64_t)len * 8;
    for (int j = 0; j < 8; j++) {
        block[63 - j] = (uint8_t)(bits >> (j * 8));
    }
    sha256_transform(state, block);
    for (int j = 0; j < 8; j++) {
        out[j * 4] = (uint8_t)(state[j] >> 24);
        out[j * 4 + 1] = (uint8_t)(state[j] >> 16);
        out[j * 4 + 2] = (uint8_t)(state[j] >> 8);
        out[j * 4 + 3] = (uint8_t)state[j];
    }
}

static inline int mbedtls_md_hmac(const mbedtls_md_info_t *md_info, const unsigned char *key,
                                  size_t keylen, const unsigned char *input, size_t ilen,
                                  unsigned char *output) {
    (void)md_info;
    uint8_t k_ipad[64], k_opad[64];
    uint8_t tk[32];
    if (keylen > 64) {
        sha256(key, keylen, tk);
        key = tk;
        keylen = 32;
    }
    memset(k_ipad, 0x36, 64);
    memset(k_opad, 0x5c, 64);
    for (size_t i = 0; i < keylen; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }
    uint8_t inner[64 + 1024];
    if (ilen > 1024)
        return -1;
    memcpy(inner, k_ipad, 64);
    memcpy(inner + 64, input, ilen);
    uint8_t inner_hash[32];
    sha256(inner, 64 + ilen, inner_hash);
    uint8_t outer[64 + 32];
    memcpy(outer, k_opad, 64);
    memcpy(outer + 64, inner_hash, 32);
    sha256(outer, 64 + 32, output);
    return 0;
}

#endif

#endif
