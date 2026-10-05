// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

/* Test-only coordinator for the native device harness: aggregates the signature
 * shares devices return, using every signer's own verification key. Arguments:
 *   message-hex  then, per signer in index order:  share-hex commitment-hex sigshare-hex
 * where share-hex is the keygen share (only its public part is used). Prints the
 * 64-byte signature as hex. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "secp256k1.h"
#include "secp256k1_frost.h"

#define MAX_SIGNERS 8

static int unhex(const char *s, uint8_t *out, size_t len) {
    if (strlen(s) != len * 2) {
        return -1;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) {
            return -1;
        }
        out[i] = (uint8_t)v;
    }
    return 0;
}

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int main(int argc, char **argv) {
    int n = (argc - 2) / 3;
    uint8_t msg[32];
    if (argc < 5 || (argc - 2) % 3 != 0 || n > MAX_SIGNERS || unhex(argv[1], msg, 32) != 0) {
        fprintf(stderr, "usage: message-hex (share-hex commitment-hex sigshare-hex)...\n");
        return 2;
    }
    secp256k1_context *ctx =
        secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_frost_pubkey pubkeys[MAX_SIGNERS];
    secp256k1_frost_nonce_commitment commits[MAX_SIGNERS];
    secp256k1_frost_signature_share shares[MAX_SIGNERS];
    secp256k1_frost_keypair *kp = NULL;
    for (int i = 0; i < n; i++) {
        uint8_t share[104], commit[132], sig_share[36];
        if (unhex(argv[2 + 3 * i], share, sizeof(share)) != 0 ||
            unhex(argv[3 + 3 * i], commit, sizeof(commit)) != 0 ||
            unhex(argv[4 + 3 * i], sig_share, sizeof(sig_share)) != 0) {
            return 3;
        }
        uint32_t index = share[98] | (share[99] << 8);
        uint32_t max_participants = share[100] | (share[101] << 8);
        if (!secp256k1_frost_pubkey_load(&pubkeys[i], index, max_participants, share + 32,
                                         share + 65)) {
            return 4;
        }
        if (!kp) {
            kp = secp256k1_frost_keypair_create(index);
            kp->public_keys = pubkeys[i];
        }
        commits[i].index = le32(commit);
        memcpy(commits[i].hiding, commit + 4, 64);
        memcpy(commits[i].binding, commit + 68, 64);
        shares[i].index = le32(sig_share);
        memcpy(shares[i].response, sig_share + 4, 32);
    }
    uint8_t sig[64];
    if (secp256k1_frost_aggregate(ctx, sig, msg, 32, kp, pubkeys, commits, shares, (uint32_t)n) !=
        1) {
        fprintf(stderr, "aggregation failed\n");
        return 1;
    }
    for (int i = 0; i < 64; i++) {
        printf("%02x", sig[i]);
    }
    printf("\n");
    secp256k1_frost_keypair_destroy(kp);
    secp256k1_context_destroy(ctx);
    return 0;
}
