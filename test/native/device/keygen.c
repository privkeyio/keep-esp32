// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

/* Test-only trusted-dealer keygen for the native device harness. Prints a 2-of-3
 * group as JSON, each share in the layout frost_init() reads. The argument picks
 * the group key's y parity: even, odd or any. */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "secp256k1.h"
#include "secp256k1_frost.h"

static void put_u16(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void print_hex(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        printf("%02x", b[i]);
    }
}

int main(int argc, char **argv) {
    const char *parity = argc > 1 ? argv[1] : "any";
    uint8_t want = strcmp(parity, "even") == 0 ? 0x02 : strcmp(parity, "odd") == 0 ? 0x03 : 0;
    secp256k1_context *ctx =
        secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_frost_keygen_secret_share shares[3];
    secp256k1_frost_keypair keypairs[3];
    uint8_t pk33[33], gpk33[33];
    for (int attempt = 0; attempt < 256; attempt++) {
        secp256k1_frost_vss_commitments *vss = secp256k1_frost_vss_commitments_create(2);
        int ok = vss && secp256k1_frost_keygen_with_dealer(ctx, vss, shares, keypairs, 3, 2) == 1;
        secp256k1_frost_vss_commitments_destroy(vss);
        if (!ok || secp256k1_frost_pubkey_save(pk33, gpk33, &keypairs[0].public_keys) != 1) {
            return 1;
        }
        if (!want || gpk33[0] == want) {
            printf("{\"group33\":\"");
            print_hex(gpk33, 33);
            printf("\",\"shares\":[");
            for (int i = 0; i < 3; i++) {
                uint8_t buf[104];
                memcpy(buf, keypairs[i].secret, 32);
                secp256k1_frost_pubkey_save(buf + 32, buf + 65, &keypairs[i].public_keys);
                put_u16(buf + 98, keypairs[i].public_keys.index);
                put_u16(buf + 100, keypairs[i].public_keys.max_participants);
                put_u16(buf + 102, 2);
                printf("%s{\"index\":%u,\"share\":\"", i ? "," : "",
                       (unsigned)keypairs[i].public_keys.index);
                print_hex(buf, sizeof(buf));
                printf("\"}");
            }
            printf("]}\n");
            secp256k1_context_destroy(ctx);
            return 0;
        }
    }
    return 1;
}
