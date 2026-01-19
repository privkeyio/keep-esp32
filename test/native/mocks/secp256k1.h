#ifndef SECP256K1_H
#define SECP256K1_H

#include <stddef.h>

#define SECP256K1_CONTEXT_SIGN   1
#define SECP256K1_CONTEXT_VERIFY 2

typedef struct secp256k1_context_struct {
    int dummy;
} secp256k1_context;
typedef struct {
    unsigned char data[64];
} secp256k1_pubkey;

#endif
