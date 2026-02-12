// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "nostr_frost.h"
#include "error_codes.h"
#include "random_utils.h"
#include "crypto_asm.h"
#include <secp256k1.h>
#include <secp256k1_frost.h>
#include <mbedtls/sha256.h>
#include <string.h>

static void safe_str_copy(char *dest, size_t dest_size, const char *src) {
    if (dest_size == 0)
        return;
    if (!src) {
        dest[0] = '\0';
        return;
    }
    size_t src_len = strlen(src);
    size_t copy_len = (src_len < dest_size - 1) ? src_len : (dest_size - 1);
    memcpy(dest, src, copy_len);
    dest[copy_len] = '\0';
}

#ifdef ESP_PLATFORM
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
static StaticSemaphore_t g_secp_mutex_buf;
static SemaphoreHandle_t g_secp_mutex = NULL;
static volatile int g_secp_mutex_init = 0;
static portMUX_TYPE g_secp_init_spinlock = portMUX_INITIALIZER_UNLOCKED;
#else
#include <pthread.h>
static pthread_mutex_t g_secp_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

static secp256k1_context *g_secp_ctx = NULL;

static secp256k1_context *get_secp_ctx(void) {
#ifdef ESP_PLATFORM
    if (!g_secp_mutex_init) {
        taskENTER_CRITICAL(&g_secp_init_spinlock);
        if (!g_secp_mutex_init) {
            g_secp_mutex = xSemaphoreCreateMutexStatic(&g_secp_mutex_buf);
            g_secp_mutex_init = 1;
        }
        taskEXIT_CRITICAL(&g_secp_init_spinlock);
    }
    if (!g_secp_mutex)
        return NULL;
    xSemaphoreTake(g_secp_mutex, portMAX_DELAY);
#else
    pthread_mutex_lock(&g_secp_mutex);
#endif
    if (!g_secp_ctx) {
        g_secp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }
#ifdef ESP_PLATFORM
    xSemaphoreGive(g_secp_mutex);
#else
    pthread_mutex_unlock(&g_secp_mutex);
#endif
    return g_secp_ctx;
}

int frost_dkg_round1_generate(const frost_group_t *group, uint8_t our_index,
                              frost_dkg_round1_t *round1, uint8_t *secret_shares_out,
                              size_t *share_count) {
    KEEP_ASSERT(group != NULL);
    KEEP_ASSERT(round1 != NULL);
    KEEP_ASSERT(secret_shares_out != NULL);
    KEEP_ASSERT(share_count != NULL);
    KEEP_ASSERT(group->participant_count > 0);
    KEEP_ASSERT(group->threshold > 0);

    secp256k1_context *ctx = get_secp_ctx();
    if (!ctx)
        return -1;
    if (group->threshold > MAX_THRESHOLD || group->participant_count > MAX_GROUP_PARTICIPANTS)
        return -2;

    secp256k1_frost_vss_commitments *vss = secp256k1_frost_vss_commitments_create(group->threshold);
    if (!vss)
        return -3;
    secp256k1_frost_keygen_secret_share shares[MAX_GROUP_PARTICIPANTS];

    int ret = secp256k1_frost_keygen_dkg_begin(
        ctx, vss, shares, group->participant_count, group->threshold, our_index,
        (const unsigned char *)DKG_CONTEXT_TAG, strlen(DKG_CONTEXT_TAG));

    if (ret != 1) {
        secp256k1_frost_vss_commitments_destroy(vss);
        return -5;
    }

    memset(round1, 0, sizeof(*round1));
    memcpy(round1->group_id, group->group_id, GROUP_ID_LEN);
    round1->participant_index = our_index;
    round1->num_coefficients = group->threshold;

    for (uint8_t i = 0; i < group->threshold; i++) {
        memcpy(round1->coefficient_commitments[i], vss->coefficient_commitments[i].data, 64);
    }
    memcpy(round1->zkp_r, vss->zkp_r, 64);
    memcpy(round1->zkp_z, vss->zkp_z, 32);

    frost_dkg_share_t *out = (frost_dkg_share_t *)secret_shares_out;
    for (uint8_t i = 0; i < group->participant_count; i++) {
        out[i].generator_index = (uint8_t)shares[i].generator_index;
        out[i].receiver_index = (uint8_t)shares[i].receiver_index;
        memcpy(out[i].value, shares[i].value, 32);
    }
    *share_count = group->participant_count;

    secp256k1_frost_vss_commitments_destroy(vss);
    return 0;
}

int frost_dkg_round1_validate(const frost_dkg_round1_t *peer_round1) {
    secp256k1_context *ctx = get_secp_ctx();
    if (!ctx || !peer_round1)
        return -1;
    if (peer_round1->num_coefficients == 0 || peer_round1->num_coefficients > MAX_THRESHOLD)
        return -2;

    secp256k1_frost_vss_commitments *vss =
        secp256k1_frost_vss_commitments_create(peer_round1->num_coefficients);
    if (!vss)
        return -3;

    vss->index = peer_round1->participant_index;
    vss->num_coefficients = peer_round1->num_coefficients;
    for (uint8_t i = 0; i < peer_round1->num_coefficients; i++) {
        memcpy(vss->coefficient_commitments[i].data, peer_round1->coefficient_commitments[i], 64);
    }
    memcpy(vss->zkp_r, peer_round1->zkp_r, 64);
    memcpy(vss->zkp_z, peer_round1->zkp_z, 32);

    int ret = secp256k1_frost_keygen_dkg_commitment_validate(
        ctx, vss, (const unsigned char *)DKG_CONTEXT_TAG, strlen(DKG_CONTEXT_TAG));

    secp256k1_frost_vss_commitments_destroy(vss);
    return ret == 1 ? 0 : -4;
}

int frost_dkg_finalize(const frost_group_t *group, const frost_dkg_round1_t *all_round1,
                       size_t round1_count, const frost_dkg_share_t *received_shares,
                       size_t share_count, uint8_t our_index, uint8_t our_share[32],
                       uint8_t group_pubkey[33]) {
    KEEP_ASSERT(group != NULL);
    KEEP_ASSERT(all_round1 != NULL);
    KEEP_ASSERT(received_shares != NULL);
    KEEP_ASSERT(our_share != NULL);
    KEEP_ASSERT(group_pubkey != NULL);
    KEEP_ASSERT(round1_count > 0);
    KEEP_ASSERT(share_count > 0);

    secp256k1_context *ctx = get_secp_ctx();
    if (!ctx)
        return -1;
    if (round1_count != group->participant_count || share_count != group->participant_count)
        return -2;

    if (round1_count > MAX_GROUP_PARTICIPANTS)
        return -3;
    secp256k1_frost_vss_commitments *commitments[MAX_GROUP_PARTICIPANTS];

    for (size_t i = 0; i < round1_count; i++) {
        if (all_round1[i].num_coefficients == 0 || all_round1[i].num_coefficients > MAX_THRESHOLD) {
            for (size_t j = 0; j < i; j++)
                secp256k1_frost_vss_commitments_destroy(commitments[j]);
            return -4;
        }
        commitments[i] = secp256k1_frost_vss_commitments_create(all_round1[i].num_coefficients);
        if (!commitments[i]) {
            for (size_t j = 0; j < i; j++)
                secp256k1_frost_vss_commitments_destroy(commitments[j]);
            return -5;
        }
        commitments[i]->index = all_round1[i].participant_index;
        commitments[i]->num_coefficients = all_round1[i].num_coefficients;
        for (uint8_t k = 0; k < all_round1[i].num_coefficients; k++) {
            memcpy(commitments[i]->coefficient_commitments[k].data,
                   all_round1[i].coefficient_commitments[k], 64);
        }
        memcpy(commitments[i]->zkp_r, all_round1[i].zkp_r, 64);
        memcpy(commitments[i]->zkp_z, all_round1[i].zkp_z, 32);
    }

    secp256k1_frost_keygen_secret_share shares[MAX_GROUP_PARTICIPANTS];

    for (size_t i = 0; i < share_count; i++) {
        shares[i].generator_index = received_shares[i].generator_index;
        shares[i].receiver_index = received_shares[i].receiver_index;
        memcpy(shares[i].value, received_shares[i].value, 32);
    }

    secp256k1_frost_keypair *keypair = secp256k1_frost_keypair_create(our_index);
    if (!keypair) {
        for (size_t i = 0; i < round1_count; i++)
            secp256k1_frost_vss_commitments_destroy(commitments[i]);
        return -7;
    }

    int ret = secp256k1_frost_keygen_dkg_finalize(ctx, keypair, our_index, (uint32_t)round1_count,
                                                  shares, commitments);

    if (ret == 1) {
        memcpy(our_share, keypair->secret, 32);
        secure_memzero(keypair->secret, 32);
        uint8_t pubkey33[33], group33[33];
        secp256k1_frost_pubkey_save(pubkey33, group33, &keypair->public_keys);
        memcpy(group_pubkey, group33, 33);
    }

    secp256k1_frost_keypair_destroy(keypair);
    for (size_t i = 0; i < round1_count; i++)
        secp256k1_frost_vss_commitments_destroy(commitments[i]);

    return ret == 1 ? 0 : -8;
}

int frost_sign_partial(const frost_group_t *group, const frost_sign_request_t *request,
                       const uint8_t our_share[32], uint8_t our_index,
                       frost_sign_response_t *response) {
    KEEP_ASSERT(group != NULL);
    KEEP_ASSERT(request != NULL);
    KEEP_ASSERT(our_share != NULL);
    KEEP_ASSERT(response != NULL);

    memset(response, 0, sizeof(*response));
    memcpy(response->request_id, request->request_id, 32);
    response->participant_index = our_index;
    response->status = FROST_SIGN_STATUS_SIGNED;

    secp256k1_context *ctx = get_secp_ctx();
    if (!ctx) {
        response->status = FROST_SIGN_STATUS_REJECTED;
        safe_str_copy(response->rejection_reason, sizeof(response->rejection_reason),
                      "Crypto context unavailable");
        return -2;
    }

    uint8_t msg_hash[32];
    if (request->message_type == FROST_MSG_TYPE_RAW && request->payload_len == 32) {
        memcpy(msg_hash, request->payload, 32);
    } else {
        mbedtls_sha256(request->payload, request->payload_len, msg_hash, 0);
    }

    secp256k1_frost_keypair *kp = secp256k1_frost_keypair_create(our_index);
    if (!kp) {
        response->status = FROST_SIGN_STATUS_REJECTED;
        safe_str_copy(response->rejection_reason, sizeof(response->rejection_reason),
                      "Keypair creation failed");
        return -3;
    }

    memcpy(kp->secret, our_share, 32);

    uint8_t binding_seed[32], hiding_seed[32];
    if (rng_fill_checked(binding_seed, 32) != 0 || rng_fill_checked(hiding_seed, 32) != 0) {
        secure_memzero(kp->secret, 32);
        secp256k1_frost_keypair_destroy(kp);
        response->status = FROST_SIGN_STATUS_REJECTED;
        safe_str_copy(response->rejection_reason, sizeof(response->rejection_reason),
                      "RNG health check failed");
        return -4;
    }

    secp256k1_frost_nonce *nonce = secp256k1_frost_nonce_create(ctx, kp, binding_seed, hiding_seed);
    secure_memzero(binding_seed, 32);
    secure_memzero(hiding_seed, 32);

    if (!nonce) {
        secure_memzero(kp->secret, 32);
        secp256k1_frost_keypair_destroy(kp);
        response->status = FROST_SIGN_STATUS_REJECTED;
        safe_str_copy(response->rejection_reason, sizeof(response->rejection_reason),
                      "Nonce creation failed");
        return -4;
    }

    response->nonce_commitment[0] = 0x02 | (nonce->commitments.hiding[63] & 0x01);
    memcpy(response->nonce_commitment + 1, nonce->commitments.hiding, 32);

    secp256k1_frost_signature_share sig_share;
    secp256k1_frost_nonce_commitment commits[MAX_GROUP_PARTICIPANTS];
    size_t commit_count = 0;

    commits[commit_count++] = nonce->commitments;

    int ret =
        secp256k1_frost_sign(ctx, &sig_share, msg_hash, 32, (int)commit_count, kp, nonce, commits);

    secp256k1_frost_nonce_destroy(nonce);
    secure_memzero(kp->secret, 32);
    secp256k1_frost_keypair_destroy(kp);

    if (ret != 1) {
        response->status = FROST_SIGN_STATUS_REJECTED;
        safe_str_copy(response->rejection_reason, sizeof(response->rejection_reason),
                      "Signing failed");
        return -5;
    }

    memcpy(response->partial_signature, sig_share.response, 32);
    return 0;
}
