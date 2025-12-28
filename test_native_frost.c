#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <secp256k1.h>
#include <secp256k1_frost.h>
#include <nostr.h>

#define THRESHOLD 2
#define TOTAL_SHARES 3

static void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

static int fill_random(unsigned char *buf, size_t len) {
    FILE *fp = fopen("/dev/urandom", "r");
    if (!fp) return 0;
    size_t r = fread(buf, 1, len, fp);
    fclose(fp);
    return r == len;
}

static int test_frost_signing(void) {
    printf("\n=== Test 1: FROST 2-of-3 Signing ===\n");

    unsigned char msg[32] = "test message to sign 0123456789";
    unsigned char msg_hash[32], tag[] = "frost_test";
    unsigned char binding_seed[32], hiding_seed[32], signature[64];

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_frost_vss_commitments *dealer = secp256k1_frost_vss_commitments_create(THRESHOLD);
    secp256k1_frost_keygen_secret_share shares[TOTAL_SHARES];
    secp256k1_frost_keypair keypairs[TOTAL_SHARES];
    secp256k1_frost_pubkey pubkeys[THRESHOLD];
    secp256k1_frost_signature_share sig_shares[THRESHOLD];
    secp256k1_frost_nonce *nonces[THRESHOLD];
    secp256k1_frost_nonce_commitment commits[THRESHOLD];

    if (secp256k1_frost_keygen_with_dealer(ctx, dealer, shares, keypairs, TOTAL_SHARES, THRESHOLD) != 1) {
        printf("  FAIL: keygen\n"); return 0;
    }
    printf("  Key generation: OK\n");
    printf("  Group pubkey: "); print_hex(keypairs[0].public_keys.group_public_key, 64);

    for (int i = 0; i < THRESHOLD; i++) {
        secp256k1_frost_pubkey_from_keypair(&pubkeys[i], &keypairs[i]);
        fill_random(binding_seed, 32); fill_random(hiding_seed, 32);
        nonces[i] = secp256k1_frost_nonce_create(ctx, &keypairs[i], binding_seed, hiding_seed);
        memcpy(&commits[i], &nonces[i]->commitments, sizeof(commits[0]));
    }

    secp256k1_tagged_sha256(ctx, msg_hash, tag, sizeof(tag), msg, sizeof(msg));
    for (int i = 0; i < THRESHOLD; i++)
        secp256k1_frost_sign(ctx, &sig_shares[i], msg_hash, 32, THRESHOLD, &keypairs[i], nonces[i], commits);

    secp256k1_frost_aggregate(ctx, signature, msg_hash, 32, &keypairs[0], pubkeys, commits, sig_shares, THRESHOLD);
    int valid = secp256k1_frost_verify(ctx, signature, msg_hash, 32, &keypairs[0].public_keys);
    printf("  Signature: "); print_hex(signature, 64);
    printf("  Verification: %s\n", valid ? "PASS" : "FAIL");

    for (int i = 0; i < THRESHOLD; i++) secp256k1_frost_nonce_destroy(nonces[i]);
    secp256k1_frost_vss_commitments_destroy(dealer);
    secp256k1_context_destroy(ctx);
    return valid;
}

static int test_nip44_encryption(void) {
    printf("\n=== Test 2: NIP-44 Encryption ===\n");

    nostr_privkey sender_priv, recv_priv;
    nostr_key sender_pub, recv_pub;
    nostr_key_generate(&sender_priv, &sender_pub);
    nostr_key_generate(&recv_priv, &recv_pub);

    printf("  Sender pubkey: "); print_hex(sender_pub.data, 32);
    printf("  Receiver pubkey: "); print_hex(recv_pub.data, 32);

    const char *plaintext = "{\"type\":\"commitment\",\"session_id\":\"abc123\",\"share_index\":1,\"commitment\":\"deadbeef\"}";
    printf("  Plaintext: %s\n", plaintext);

    char *ciphertext = NULL, *decrypted = NULL;
    size_t dec_len = 0;

    if (nostr_nip44_encrypt(&sender_priv, &recv_pub, plaintext, strlen(plaintext), &ciphertext) != NOSTR_OK) {
        printf("  FAIL: encrypt\n"); return 0;
    }
    printf("  Encrypted: %.60s...\n", ciphertext);

    if (nostr_nip44_decrypt(&recv_priv, &sender_pub, ciphertext, &decrypted, &dec_len) != NOSTR_OK) {
        printf("  FAIL: decrypt\n"); free(ciphertext); return 0;
    }
    printf("  Decrypted: %s\n", decrypted);

    int result = (strcmp(plaintext, decrypted) == 0);
    printf("  Verification: %s\n", result ? "PASS" : "FAIL");
    free(ciphertext); free(decrypted);
    return result;
}

static int test_kfp_roundtrip(void) {
    printf("\n=== Test 3: KFP Round-Trip (FROST + NIP-44) ===\n");

    // FROST keygen
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_frost_vss_commitments *dealer = secp256k1_frost_vss_commitments_create(THRESHOLD);
    secp256k1_frost_keygen_secret_share shares[TOTAL_SHARES];
    secp256k1_frost_keypair keypairs[TOTAL_SHARES];
    secp256k1_frost_keygen_with_dealer(ctx, dealer, shares, keypairs, TOTAL_SHARES, THRESHOLD);
    printf("  FROST keygen: OK\n");

    // NIP-44 with dynamic session
    nostr_privkey sender_priv, recv_priv;
    nostr_key sender_pub, recv_pub;
    nostr_key_generate(&sender_priv, &sender_pub);
    nostr_key_generate(&recv_priv, &recv_pub);

    printf("  Sender pubkey: "); print_hex(sender_pub.data, 32);
    printf("  Receiver pubkey: "); print_hex(recv_pub.data, 32);

    unsigned char session_id[32];
    fill_random(session_id, 32);
    char session_hex[65], sign_request[512];
    for (int i = 0; i < 32; i++) sprintf(session_hex + i*2, "%02x", session_id[i]);
    session_hex[64] = '\0';
    snprintf(sign_request, sizeof(sign_request),
             "{\"type\":\"sign_request\",\"session_id\":\"%s\",\"message\":\"48656c6c6f\",\"participants\":[0,1]}",
             session_hex);
    const char *plaintext = sign_request;
    printf("  Plaintext: %s\n", plaintext);

    char *ciphertext = NULL, *decrypted = NULL;
    size_t dec_len = 0;

    if (nostr_nip44_encrypt(&sender_priv, &recv_pub, plaintext, strlen(plaintext), &ciphertext) != NOSTR_OK) {
        printf("  FAIL: encrypt\n"); return 0;
    }
    printf("  Encrypted: %.60s...\n", ciphertext);

    if (nostr_nip44_decrypt(&recv_priv, &sender_pub, ciphertext, &decrypted, &dec_len) != NOSTR_OK) {
        printf("  FAIL: decrypt\n"); free(ciphertext); return 0;
    }
    printf("  Decrypted: %s\n", decrypted);

    int result = (strcmp(plaintext, decrypted) == 0);
    printf("  Verification: %s\n", result ? "PASS" : "FAIL");
    free(ciphertext); free(decrypted);
    secp256k1_frost_vss_commitments_destroy(dealer);
    secp256k1_context_destroy(ctx);
    return result;
}

int main(void) {
    printf("===========================================\n");
    printf("  Native FROST Test Harness for ESP32\n");
    printf("===========================================\n");

    int passed = 0;
    if (test_frost_signing()) passed++;
    if (test_nip44_encryption()) passed++;
    if (test_kfp_roundtrip()) passed++;

    printf("\n===========================================\n");
    printf("  Results: %d/3 tests passed\n", passed);
    printf("===========================================\n");
    return (passed == 3) ? 0 : 1;
}
