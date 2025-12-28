#include "frost.h"
#include <string.h>
#include <stdlib.h>
#include <secp256k1.h>
#include <secp256k1_frost.h>

#ifndef ESP_PLATFORM
#include <stdio.h>
static void fill_random(uint8_t *buf, size_t len) {
    FILE *fp = fopen("/dev/urandom", "r");
    if (fp) { fread(buf, 1, len, fp); fclose(fp); }
}
static void secure_zero(void *buf, size_t len) {
    volatile uint8_t *p = buf;
    while (len--) *p++ = 0;
}
#else
#include "esp_random.h"
#include "mbedtls/platform_util.h"
static void fill_random(uint8_t *buf, size_t len) { esp_fill_random(buf, len); }
#define secure_zero(buf, len) mbedtls_platform_zeroize(buf, len)
#endif

#define KEYPAIR_SERIALIZED_LEN 102

int frost_init(frost_state_t *state, const uint8_t *share_bytes, size_t share_len) {
    memset(state, 0, sizeof(*state));
    if (share_len < KEYPAIR_SERIALIZED_LEN) return -1;

    state->ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!state->ctx) return -2;

    const uint8_t *p = share_bytes;
    uint8_t secret[32];
    memcpy(secret, p, 32); p += 32;

    uint8_t pubkey33[33], group_pubkey33[33];
    memcpy(pubkey33, p, 33); p += 33;
    memcpy(group_pubkey33, p, 33); p += 33;

    uint32_t index = p[0] | (p[1] << 8); p += 2;
    uint32_t max_participants = p[0] | (p[1] << 8);

    state->share_index = (uint16_t)index;

    secp256k1_frost_keypair *kp = secp256k1_frost_keypair_create(index);
    if (!kp) {
        secp256k1_context_destroy(state->ctx);
        return -3;
    }

    memcpy(kp->secret, secret, 32);
    secure_zero(secret, sizeof(secret));

    if (!secp256k1_frost_pubkey_load(&kp->public_keys, index, max_participants, pubkey33, group_pubkey33)) {
        secp256k1_frost_keypair_destroy(kp);
        secp256k1_context_destroy(state->ctx);
        return -4;
    }

    state->keypair = kp;

    uint8_t gpk33[33], dummy[33];
    secp256k1_frost_pubkey_save(dummy, gpk33, &kp->public_keys);
    memcpy(state->group_pubkey, gpk33 + 1, 32);

    return 0;
}

void frost_free(frost_state_t *state) {
    if (state->keypair) {
        secp256k1_frost_keypair_destroy(state->keypair);
        state->keypair = NULL;
    }
    if (state->ctx) {
        secp256k1_context_destroy(state->ctx);
        state->ctx = NULL;
    }
}

int frost_create_commitment(frost_state_t *state, session_t *session,
                            uint8_t *commitment_out, size_t *commitment_len) {
    uint8_t binding_seed[32], hiding_seed[32];
    fill_random(binding_seed, 32);
    fill_random(hiding_seed, 32);

    secp256k1_frost_nonce *nonce = secp256k1_frost_nonce_create(
        state->ctx, state->keypair, binding_seed, hiding_seed);
    secure_zero(binding_seed, sizeof(binding_seed));
    secure_zero(hiding_seed, sizeof(hiding_seed));
    if (!nonce) return -1;

    memcpy(session->our_nonce, nonce->hiding, 32);
    memcpy(session->our_nonce + 32, nonce->binding, 32);

    secp256k1_frost_nonce_commitment *c = &nonce->commitments;
    uint8_t *p = commitment_out;
    p[0] = c->index & 0xff;
    p[1] = (c->index >> 8) & 0xff;
    p[2] = (c->index >> 16) & 0xff;
    p[3] = (c->index >> 24) & 0xff;
    p += 4;
    memcpy(p, c->hiding, 64); p += 64;
    memcpy(p, c->binding, 64);

    *commitment_len = 132;
    session->our_commitment_len = 132;
    memcpy(session->our_commitment, commitment_out, 132);

    secp256k1_frost_nonce_destroy(nonce);
    return 0;
}

static void deserialize_commitment(const uint8_t *data, secp256k1_frost_nonce_commitment *c) {
    c->index = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
    memcpy(c->hiding, data + 4, 64);
    memcpy(c->binding, data + 68, 64);
}

int frost_sign(frost_state_t *state, session_t *session,
               const uint8_t *msg_hash, size_t hash_len,
               uint8_t *sig_share_out, size_t *sig_share_len) {
    if (!session_has_all_commitments(session)) return -1;

    secp256k1_frost_nonce nonce;
    nonce.used = 0;
    memcpy(nonce.hiding, session->our_nonce, 32);
    memcpy(nonce.binding, session->our_nonce + 32, 32);
    deserialize_commitment(session->our_commitment, &nonce.commitments);

    secp256k1_frost_nonce_commitment commits[KFP_MAX_PARTICIPANTS];
    deserialize_commitment(session->our_commitment, &commits[0]);
    for (int i = 0; i < session->commitment_count; i++) {
        deserialize_commitment(session->commitments[i], &commits[i + 1]);
    }
    int total_commits = session->commitment_count + 1;

    secp256k1_frost_signature_share share;
    int ret = secp256k1_frost_sign(state->ctx, &share, msg_hash, hash_len,
                                   total_commits, state->keypair,
                                   &nonce, commits);
    if (ret != 1) return -2;

    uint8_t *p = sig_share_out;
    p[0] = share.index & 0xff;
    p[1] = (share.index >> 8) & 0xff;
    p[2] = (share.index >> 16) & 0xff;
    p[3] = (share.index >> 24) & 0xff;
    memcpy(p + 4, share.response, 32);
    *sig_share_len = 36;

    return 0;
}

static void deserialize_sig_share(const uint8_t *data, secp256k1_frost_signature_share *s) {
    s->index = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
    memcpy(s->response, data + 4, 32);
}

int frost_aggregate(frost_state_t *state, session_t *session,
                    const uint8_t *msg_hash, size_t hash_len,
                    uint8_t *signature_out) {
    if (!session_has_all_shares(session)) return -1;

    secp256k1_frost_nonce_commitment commits[KFP_MAX_PARTICIPANTS];
    for (int i = 0; i < session->commitment_count; i++) {
        deserialize_commitment(session->commitments[i], &commits[i]);
    }

    secp256k1_frost_signature_share shares[KFP_MAX_PARTICIPANTS];
    for (int i = 0; i < session->sig_share_count; i++) {
        deserialize_sig_share(session->sig_shares[i], &shares[i]);
    }

    secp256k1_frost_pubkey pubkeys[KFP_MAX_PARTICIPANTS];
    for (int i = 0; i < session->commitment_count; i++) {
        secp256k1_frost_pubkey_from_keypair(&pubkeys[i], state->keypair);
        pubkeys[i].index = commits[i].index;
    }

    int ret = secp256k1_frost_aggregate(state->ctx, signature_out, msg_hash, hash_len,
                                        state->keypair, pubkeys, commits, shares,
                                        session->threshold);
    return ret == 1 ? 0 : -2;
}

int frost_verify(frost_state_t *state, const uint8_t *signature,
                 const uint8_t *msg_hash, size_t hash_len) {
    secp256k1_frost_pubkey pk;
    secp256k1_frost_pubkey_from_keypair(&pk, state->keypair);
    int ret = secp256k1_frost_verify(state->ctx, signature, msg_hash, hash_len, &pk);
    return ret == 1 ? 0 : -1;
}
