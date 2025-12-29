#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "secp256k1.h"
#include "secp256k1_frost.h"

#define TEST(name) printf("  TEST: %s\n", name)
#define PASS() printf("    PASS\n")
#define FAIL(msg) do { printf("    FAIL: %s\n", msg); return 1; } while(0)

static void fill_random(uint8_t *buf, size_t len) {
    FILE *fp = fopen("/dev/urandom", "r");
    if (fp) {
        size_t n = fread(buf, 1, len, fp);
        fclose(fp);
        if (n == len) return;
    }
    unsigned int seed = (unsigned int)time(NULL);
    srand(seed);
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(rand() & 0xff);
    }
}

static int test_context_create(void) {
    TEST("secp256k1 context creation");
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY
    );
    if (ctx == NULL) FAIL("context is NULL");
    secp256k1_context_destroy(ctx);
    PASS();
    return 0;
}

static int test_keygen_with_dealer(void) {
    TEST("FROST key generation with dealer");

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY
    );
    if (!ctx) FAIL("failed to create context");

    uint32_t n = 3, t = 2;
    secp256k1_frost_vss_commitments *vss = secp256k1_frost_vss_commitments_create(t);
    if (!vss) {
        secp256k1_context_destroy(ctx);
        FAIL("failed to create vss commitments");
    }

    secp256k1_frost_keygen_secret_share shares[3];
    secp256k1_frost_keypair keypairs[3];

    int ret = secp256k1_frost_keygen_with_dealer(ctx, vss, shares, keypairs, n, t);
    if (ret != 1) {
        secp256k1_frost_vss_commitments_destroy(vss);
        secp256k1_context_destroy(ctx);
        FAIL("key generation failed");
    }

    uint8_t pk33[33], gpk33[33];
    ret = secp256k1_frost_pubkey_save(pk33, gpk33, &keypairs[0].public_keys);
    if (ret != 1) {
        secp256k1_frost_vss_commitments_destroy(vss);
        secp256k1_context_destroy(ctx);
        FAIL("pubkey save failed");
    }

    secp256k1_frost_vss_commitments_destroy(vss);
    secp256k1_context_destroy(ctx);
    PASS();
    return 0;
}

static int test_two_round_signing(void) {
    TEST("FROST two-round signing protocol");

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY
    );
    if (!ctx) FAIL("failed to create context");

    uint32_t n = 3, t = 2;
    secp256k1_frost_vss_commitments *vss = secp256k1_frost_vss_commitments_create(t);
    if (!vss) {
        secp256k1_context_destroy(ctx);
        FAIL("failed to create vss commitments");
    }

    secp256k1_frost_keygen_secret_share shares[3];
    secp256k1_frost_keypair keypairs[3];

    if (secp256k1_frost_keygen_with_dealer(ctx, vss, shares, keypairs, n, t) != 1) {
        secp256k1_frost_vss_commitments_destroy(vss);
        secp256k1_context_destroy(ctx);
        FAIL("key generation failed");
    }

    uint8_t message[32];
    fill_random(message, 32);

    secp256k1_frost_nonce *nonces[2];
    secp256k1_frost_nonce_commitment commits[2];

    for (int i = 0; i < 2; i++) {
        uint8_t binding[32], hiding[32];
        fill_random(binding, 32);
        fill_random(hiding, 32);
        nonces[i] = secp256k1_frost_nonce_create(ctx, &keypairs[i], binding, hiding);
        if (!nonces[i]) {
            for (int j = 0; j < i; j++) secp256k1_frost_nonce_destroy(nonces[j]);
            secp256k1_frost_vss_commitments_destroy(vss);
            secp256k1_context_destroy(ctx);
            FAIL("failed to create nonce");
        }
        commits[i] = nonces[i]->commitments;
    }

    secp256k1_frost_signature_share sig_shares[2];
    for (int i = 0; i < 2; i++) {
        int ret = secp256k1_frost_sign(ctx, &sig_shares[i], message, 32, 2, &keypairs[i], nonces[i], commits);
        if (ret != 1) {
            for (int j = 0; j < 2; j++) secp256k1_frost_nonce_destroy(nonces[j]);
            secp256k1_frost_vss_commitments_destroy(vss);
            secp256k1_context_destroy(ctx);
            FAIL("signing failed");
        }
    }

    secp256k1_frost_pubkey pubkeys[2];
    for (int i = 0; i < 2; i++) {
        secp256k1_frost_pubkey_from_keypair(&pubkeys[i], &keypairs[i]);
    }

    uint8_t signature[64];
    int ret = secp256k1_frost_aggregate(ctx, signature, message, 32, &keypairs[0], pubkeys, commits, sig_shares, 2);
    if (ret != 1) {
        for (int i = 0; i < 2; i++) secp256k1_frost_nonce_destroy(nonces[i]);
        secp256k1_frost_vss_commitments_destroy(vss);
        secp256k1_context_destroy(ctx);
        FAIL("aggregation failed");
    }

    ret = secp256k1_frost_verify(ctx, signature, message, 32, &pubkeys[0]);
    if (ret != 1) {
        for (int i = 0; i < 2; i++) secp256k1_frost_nonce_destroy(nonces[i]);
        secp256k1_frost_vss_commitments_destroy(vss);
        secp256k1_context_destroy(ctx);
        FAIL("verification failed");
    }

    for (int i = 0; i < 2; i++) secp256k1_frost_nonce_destroy(nonces[i]);
    secp256k1_frost_vss_commitments_destroy(vss);
    secp256k1_context_destroy(ctx);
    PASS();
    return 0;
}

static int test_pubkey_serialization(void) {
    TEST("public key serialization roundtrip");

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY
    );
    if (!ctx) FAIL("failed to create context");

    secp256k1_frost_vss_commitments *vss = secp256k1_frost_vss_commitments_create(2);
    if (!vss) {
        secp256k1_context_destroy(ctx);
        FAIL("failed to create vss commitments");
    }

    secp256k1_frost_keygen_secret_share shares[3];
    secp256k1_frost_keypair keypairs[3];
    if (secp256k1_frost_keygen_with_dealer(ctx, vss, shares, keypairs, 3, 2) != 1) {
        secp256k1_frost_vss_commitments_destroy(vss);
        secp256k1_context_destroy(ctx);
        FAIL("keygen failed");
    }

    uint8_t pk33[33], gpk33[33];
    int save_ret = secp256k1_frost_pubkey_save(pk33, gpk33, &keypairs[0].public_keys);
    if (save_ret != 1) {
        secp256k1_frost_vss_commitments_destroy(vss);
        secp256k1_context_destroy(ctx);
        FAIL("pubkey save failed");
    }

    secp256k1_frost_pubkey loaded;
    int ret = secp256k1_frost_pubkey_load(&loaded,
        keypairs[0].public_keys.index,
        keypairs[0].public_keys.max_participants,
        pk33, gpk33);

    if (ret != 1) {
        secp256k1_frost_vss_commitments_destroy(vss);
        secp256k1_context_destroy(ctx);
        FAIL("pubkey load failed");
    }

    if (loaded.index != keypairs[0].public_keys.index) {
        secp256k1_frost_vss_commitments_destroy(vss);
        secp256k1_context_destroy(ctx);
        FAIL("index mismatch");
    }

    secp256k1_frost_vss_commitments_destroy(vss);
    secp256k1_context_destroy(ctx);
    PASS();
    return 0;
}

int main(void) {
    printf("\n=== FROST Native Tests ===\n\n");

    int failures = 0;
    failures += test_context_create();
    failures += test_keygen_with_dealer();
    failures += test_two_round_signing();
    failures += test_pubkey_serialization();

    printf("\n");
    if (failures == 0) {
        printf("=== All tests passed ===\n\n");
        return 0;
    } else {
        printf("=== %d test(s) failed ===\n\n", failures);
        return 1;
    }
}
