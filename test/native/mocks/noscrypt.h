// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#ifndef NOSCRYPT_MOCK_H
#define NOSCRYPT_MOCK_H

#include <stdint.h>
#include <string.h>

#define NC_SUCCESS              0
#define NC_CONTEXT_ENTROPY_SIZE 32

typedef struct {
    uint8_t opaque[16];
} NCContext;

typedef struct {
    uint8_t key[32];
} NCSecretKey;

typedef struct {
    uint8_t key[32];
} NCPublicKey;

static inline uint32_t NCGetContextStructSize(void) {
    return (uint32_t)sizeof(NCContext);
}

static inline int NCInitContext(NCContext *ctx, const uint8_t entropy[NC_CONTEXT_ENTROPY_SIZE]) {
    (void)entropy;
    memset(ctx, 0, sizeof(*ctx));
    return NC_SUCCESS;
}

static inline int NCDestroyContext(NCContext *ctx) {
    (void)ctx;
    return NC_SUCCESS;
}

// Deterministic stand-in: pubkey mirrors the secret so tests can assert on it.
static inline int NCGetPublicKey(NCContext *ctx, const NCSecretKey *sk, NCPublicKey *pk) {
    (void)ctx;
    memcpy(pk->key, sk->key, 32);
    return NC_SUCCESS;
}

#endif
