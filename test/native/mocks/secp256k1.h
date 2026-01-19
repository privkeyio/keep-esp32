#ifndef SECP256K1_H
#define SECP256K1_H

#include <stddef.h>

#define SECP256K1_CONTEXT_SIGN   1
#define SECP256K1_CONTEXT_VERIFY 2

#ifndef SECP256K1_API
#define SECP256K1_API
#endif

#ifndef SECP256K1_WARN_UNUSED_RESULT
#if defined(__GNUC__)
#define SECP256K1_WARN_UNUSED_RESULT __attribute__((__warn_unused_result__))
#else
#define SECP256K1_WARN_UNUSED_RESULT
#endif
#endif

#ifndef SECP256K1_ARG_NONNULL
#define SECP256K1_ARG_NONNULL(_x)
#endif

typedef struct secp256k1_context_struct {
    int dummy;
} secp256k1_context;
typedef struct {
    unsigned char data[64];
} secp256k1_pubkey;

SECP256K1_API secp256k1_context *secp256k1_context_create(unsigned int flags);
SECP256K1_API void secp256k1_context_destroy(secp256k1_context *ctx);

#endif
