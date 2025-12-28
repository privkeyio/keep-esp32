#ifndef SECP256K1_FROST_ESP_H
#define SECP256K1_FROST_ESP_H

#include "secp256k1.h"
#include "secp256k1_schnorrsig.h"
#include "secp256k1_frost.h"

secp256k1_context *frost_context_create(void);
void frost_context_destroy(secp256k1_context *ctx);

#endif
