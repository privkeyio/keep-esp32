#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "secp256k1.h"
#include "secp256k1_frost.h"

#define KEYPAIR_SERIALIZED_LEN 102

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
    for (size_t i = 0; i < len && i < 32; i++) printf("%02x", data[i]);
    if (len > 32) printf("...");
    printf(" (%zu bytes)\n", len);
}

static int serialize_keypair(const secp256k1_frost_keypair *kp, uint8_t *out, size_t *out_len) {
    uint8_t *p = out;
    memcpy(p, kp->secret, 32); p += 32;

    uint8_t pk33[33], gpk33[33];
    secp256k1_frost_pubkey_save(pk33, gpk33, &kp->public_keys);
    memcpy(p, pk33, 33); p += 33;
    memcpy(p, gpk33, 33); p += 33;

    uint32_t idx = kp->public_keys.index;
    p[0] = idx & 0xff;
    p[1] = (idx >> 8) & 0xff;
    p += 2;

    uint32_t max = kp->public_keys.max_participants;
    p[0] = max & 0xff;
    p[1] = (max >> 8) & 0xff;
    p += 2;

    *out_len = KEYPAIR_SERIALIZED_LEN;
    return 0;
}

static int deserialize_keypair(const uint8_t *data, size_t len, secp256k1_frost_keypair **kp_out) {
    if (len < KEYPAIR_SERIALIZED_LEN) return -1;

    const uint8_t *p = data;
    uint8_t secret[32];
    memcpy(secret, p, 32); p += 32;

    uint8_t pk33[33], gpk33[33];
    memcpy(pk33, p, 33); p += 33;
    memcpy(gpk33, p, 33); p += 33;

    uint32_t index = p[0] | (p[1] << 8); p += 2;
    uint32_t max_participants = p[0] | (p[1] << 8);

    secp256k1_frost_keypair *kp = secp256k1_frost_keypair_create(index);
    if (!kp) return -2;

    memcpy(kp->secret, secret, 32);

    if (!secp256k1_frost_pubkey_load(&kp->public_keys, index, max_participants, pk33, gpk33)) {
        secp256k1_frost_keypair_destroy(kp);
        return -3;
    }

    *kp_out = kp;
    return 0;
}

int main(void) {
    printf("=== Firmware Flow Test ===\n\n");

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    uint32_t n = 3, t = 2;
    secp256k1_frost_vss_commitments *vss = secp256k1_frost_vss_commitments_create(t);
    secp256k1_frost_keygen_secret_share shares[3];
    secp256k1_frost_keypair keypairs[3];

    printf("1. Generate keys (t=%d, n=%d)\n", t, n);
    secp256k1_frost_keygen_with_dealer(ctx, vss, shares, keypairs, n, t);

    printf("2. Serialize keypairs (firmware storage format)\n");
    uint8_t serialized[3][KEYPAIR_SERIALIZED_LEN];
    size_t serialized_len;
    for (int i = 0; i < 3; i++) {
        serialize_keypair(&keypairs[i], serialized[i], &serialized_len);
        printf("   Signer %d: ", i);
        print_hex("share", serialized[i], serialized_len);
    }

    printf("3. Deserialize keypairs (firmware load)\n");
    secp256k1_frost_keypair *loaded[2];
    for (int i = 0; i < 2; i++) {
        if (deserialize_keypair(serialized[i], KEYPAIR_SERIALIZED_LEN, &loaded[i]) != 0) {
            printf("   FAIL: Failed to deserialize signer %d\n", i);
            return 1;
        }
        printf("   OK: Loaded signer %d (index=%d)\n", i, loaded[i]->public_keys.index);
    }

    uint8_t message[32];
    fill_random(message, 32);
    printf("4. Message to sign: ");
    print_hex("", message, 32);

    printf("5. Round 1: frost_commit (generate commitments)\n");
    secp256k1_frost_nonce *nonces[2];
    secp256k1_frost_nonce_commitment commits[2];
    uint8_t commitment_bytes[2][132];

    for (int i = 0; i < 2; i++) {
        uint8_t b[32], h[32];
        fill_random(b, 32);
        fill_random(h, 32);
        nonces[i] = secp256k1_frost_nonce_create(ctx, loaded[i], b, h);
        commits[i] = nonces[i]->commitments;

        uint8_t *p = commitment_bytes[i];
        p[0] = commits[i].index & 0xff;
        p[1] = (commits[i].index >> 8) & 0xff;
        p[2] = (commits[i].index >> 16) & 0xff;
        p[3] = (commits[i].index >> 24) & 0xff;
        memcpy(p + 4, commits[i].hiding, 64);
        memcpy(p + 68, commits[i].binding, 64);

        printf("   Signer %d commitment: ", i);
        print_hex("", commitment_bytes[i], 132);
    }

    printf("6. Round 2: frost_sign (generate signature shares)\n");
    secp256k1_frost_signature_share sig_shares[2];
    uint8_t sig_share_bytes[2][36];

    for (int i = 0; i < 2; i++) {
        int ret = secp256k1_frost_sign(ctx, &sig_shares[i], message, 32, 2, loaded[i], nonces[i], commits);
        if (ret != 1) {
            printf("   FAIL: Signing failed for signer %d\n", i);
            return 1;
        }

        uint8_t *p = sig_share_bytes[i];
        p[0] = sig_shares[i].index & 0xff;
        p[1] = (sig_shares[i].index >> 8) & 0xff;
        p[2] = (sig_shares[i].index >> 16) & 0xff;
        p[3] = (sig_shares[i].index >> 24) & 0xff;
        memcpy(p + 4, sig_shares[i].response, 32);

        printf("   Signer %d sig_share: ", i);
        print_hex("", sig_share_bytes[i], 36);
    }

    printf("7. Aggregate signature shares\n");
    secp256k1_frost_pubkey pubkeys[2];
    for (int i = 0; i < 2; i++) {
        secp256k1_frost_pubkey_from_keypair(&pubkeys[i], loaded[i]);
    }

    uint8_t signature[64];
    int ret = secp256k1_frost_aggregate(ctx, signature, message, 32, loaded[0], pubkeys, commits, sig_shares, 2);
    if (ret != 1) {
        printf("   FAIL: Aggregation failed\n");
        return 1;
    }
    printf("   Signature: ");
    print_hex("", signature, 64);

    printf("8. Verify signature\n");
    ret = secp256k1_frost_verify(ctx, signature, message, 32, &pubkeys[0]);
    if (ret != 1) {
        printf("   FAIL: Verification failed\n");
        return 1;
    }
    printf("   OK: Signature verified!\n");

    for (int i = 0; i < 2; i++) {
        secp256k1_frost_nonce_destroy(nonces[i]);
        secp256k1_frost_keypair_destroy(loaded[i]);
    }
    secp256k1_frost_vss_commitments_destroy(vss);
    secp256k1_context_destroy(ctx);

    printf("\n=== Firmware Flow Test Passed ===\n");
    return 0;
}
