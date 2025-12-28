#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "secp256k1.h"
#include "secp256k1_frost.h"

static void fill_random(uint8_t *buf, size_t len) {
    FILE *fp = fopen("/dev/urandom", "r");
    if (fp) {
        size_t total = 0;
        while (total < len) {
            size_t n = fread(buf + total, 1, len - total, fp);
            if (n == 0) break;
            total += n;
        }
        fclose(fp);
        if (total == len) return;
        buf += total;
        len -= total;
    }
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)buf;
    srand(seed);
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(rand() & 0xff);
    }
}

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

int main(void) {
    printf("=== FROST Native Test ===\n\n");

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        printf("FAIL: Failed to create context\n");
        return 1;
    }
    printf("OK: Created secp256k1 context\n");

    uint32_t num_participants = 3;
    uint32_t threshold = 2;

    secp256k1_frost_vss_commitments *vss = secp256k1_frost_vss_commitments_create(threshold);
    secp256k1_frost_keygen_secret_share shares[3];
    secp256k1_frost_keypair keypairs[3];

    printf("Generating keys with dealer (t=%d, n=%d)...\n", threshold, num_participants);
    int ret = secp256k1_frost_keygen_with_dealer(ctx, vss, shares, keypairs, num_participants, threshold);
    if (ret != 1) {
        printf("FAIL: Key generation failed\n");
        return 1;
    }
    printf("OK: Generated %d keypairs\n", num_participants);

    uint8_t gpk33[33], pk33[33];
    secp256k1_frost_pubkey_save(pk33, gpk33, &keypairs[0].public_keys);
    print_hex("Group pubkey", gpk33 + 1, 32);

    uint8_t message[32];
    fill_random(message, 32);
    print_hex("Message", message, 32);

    printf("\n--- Round 1: Commitments ---\n");
    secp256k1_frost_nonce *nonces[2];
    secp256k1_frost_nonce_commitment commits[2];

    for (int i = 0; i < 2; i++) {
        uint8_t binding[32], hiding[32];
        fill_random(binding, 32);
        fill_random(hiding, 32);
        nonces[i] = secp256k1_frost_nonce_create(ctx, &keypairs[i], binding, hiding);
        if (!nonces[i]) {
            printf("FAIL: Failed to create nonce for signer %d\n", i);
            return 1;
        }
        commits[i] = nonces[i]->commitments;
        printf("OK: Signer %d created commitment (index=%d)\n", i, commits[i].index);
    }

    printf("\n--- Round 2: Signature Shares ---\n");
    secp256k1_frost_signature_share sig_shares[2];

    for (int i = 0; i < 2; i++) {
        ret = secp256k1_frost_sign(ctx, &sig_shares[i], message, 32, 2, &keypairs[i], nonces[i], commits);
        if (ret != 1) {
            printf("FAIL: Signing failed for signer %d\n", i);
            return 1;
        }
        printf("OK: Signer %d created signature share (index=%d)\n", i, sig_shares[i].index);
    }

    printf("\n--- Aggregation ---\n");
    secp256k1_frost_pubkey pubkeys[2];
    for (int i = 0; i < 2; i++) {
        secp256k1_frost_pubkey_from_keypair(&pubkeys[i], &keypairs[i]);
    }

    uint8_t signature[64];
    ret = secp256k1_frost_aggregate(ctx, signature, message, 32, &keypairs[0], pubkeys, commits, sig_shares, 2);
    if (ret != 1) {
        printf("FAIL: Aggregation failed\n");
        return 1;
    }
    print_hex("Signature", signature, 64);

    printf("\n--- Verification ---\n");
    ret = secp256k1_frost_verify(ctx, signature, message, 32, &pubkeys[0]);
    if (ret != 1) {
        printf("FAIL: Verification failed\n");
        return 1;
    }
    printf("OK: Signature verified!\n");

    for (int i = 0; i < 2; i++) {
        secp256k1_frost_nonce_destroy(nonces[i]);
    }
    secp256k1_frost_vss_commitments_destroy(vss);
    secp256k1_context_destroy(ctx);

    printf("\n=== All Tests Passed ===\n");
    return 0;
}
