#include "nostr_frost.h"
#include "crypto_asm.h"
#include <secp256k1.h>
#include <secp256k1_frost.h>
#include <mbedtls/sha256.h>
#include <string.h>
#include <stdlib.h>

#ifdef ESP_PLATFORM
#include "esp_random.h"
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
static SemaphoreHandle_t g_secp_mutex = NULL;
#else
#include <stdio.h>
#include <pthread.h>
static pthread_mutex_t g_secp_mutex = PTHREAD_MUTEX_INITIALIZER;
static int secure_random_fill(uint8_t *buf, size_t len) {
    FILE *fp = fopen("/dev/urandom", "r");
    if (!fp) return -1;
    size_t total = 0;
    while (total < len) {
        size_t n = fread(buf + total, 1, len - total, fp);
        if (n == 0) { fclose(fp); return -1; }
        total += n;
    }
    fclose(fp);
    return 0;
}
#endif

static secp256k1_context *g_secp_ctx = NULL;

static secp256k1_context *get_secp_ctx(void) {
#ifdef ESP_PLATFORM
    if (!g_secp_mutex) {
        g_secp_mutex = xSemaphoreCreateMutex();
    }
    if (g_secp_mutex) xSemaphoreTake(g_secp_mutex, portMAX_DELAY);
#else
    pthread_mutex_lock(&g_secp_mutex);
#endif
    if (!g_secp_ctx) {
        g_secp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }
#ifdef ESP_PLATFORM
    if (g_secp_mutex) xSemaphoreGive(g_secp_mutex);
#else
    pthread_mutex_unlock(&g_secp_mutex);
#endif
    return g_secp_ctx;
}

int frost_dkg_round1_generate(const frost_group_t *group,
                               uint8_t our_index,
                               frost_dkg_round1_t *round1,
                               uint8_t *secret_shares_out,
                               size_t *share_count) {
    secp256k1_context *ctx = get_secp_ctx();
    if (!ctx || !group || !round1 || !secret_shares_out || !share_count) return -1;
    if (group->threshold > MAX_THRESHOLD || group->participant_count > MAX_GROUP_PARTICIPANTS) return -2;

    secp256k1_frost_vss_commitments *vss = secp256k1_frost_vss_commitments_create(group->threshold);
    if (!vss) return -3;

    secp256k1_frost_keygen_secret_share *shares = malloc(
        sizeof(secp256k1_frost_keygen_secret_share) * group->participant_count);
    if (!shares) {
        secp256k1_frost_vss_commitments_destroy(vss);
        return -4;
    }

    int ret = secp256k1_frost_keygen_dkg_begin(ctx, vss, shares,
        group->participant_count, group->threshold, our_index,
        (const unsigned char *)DKG_CONTEXT_TAG, strlen(DKG_CONTEXT_TAG));

    if (ret != 1) {
        free(shares);
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

    free(shares);
    secp256k1_frost_vss_commitments_destroy(vss);
    return 0;
}

int frost_dkg_round1_validate(const frost_dkg_round1_t *peer_round1) {
    secp256k1_context *ctx = get_secp_ctx();
    if (!ctx || !peer_round1) return -1;

    secp256k1_frost_vss_commitments *vss = secp256k1_frost_vss_commitments_create(peer_round1->num_coefficients);
    if (!vss) return -2;

    vss->index = peer_round1->participant_index;
    vss->num_coefficients = peer_round1->num_coefficients;
    for (uint8_t i = 0; i < peer_round1->num_coefficients; i++) {
        memcpy(vss->coefficient_commitments[i].data, peer_round1->coefficient_commitments[i], 64);
    }
    memcpy(vss->zkp_r, peer_round1->zkp_r, 64);
    memcpy(vss->zkp_z, peer_round1->zkp_z, 32);

    int ret = secp256k1_frost_keygen_dkg_commitment_validate(ctx, vss,
        (const unsigned char *)DKG_CONTEXT_TAG, strlen(DKG_CONTEXT_TAG));

    secp256k1_frost_vss_commitments_destroy(vss);
    return ret == 1 ? 0 : -3;
}

int frost_dkg_finalize(const frost_group_t *group,
                        const frost_dkg_round1_t *all_round1,
                        size_t round1_count,
                        const frost_dkg_share_t *received_shares,
                        size_t share_count,
                        uint8_t our_index,
                        uint8_t our_share[32],
                        uint8_t group_pubkey[33]) {
    secp256k1_context *ctx = get_secp_ctx();
    if (!ctx || !group || !all_round1 || !received_shares || !our_share || !group_pubkey) return -1;
    if (round1_count != group->participant_count || share_count != group->participant_count) return -2;

    secp256k1_frost_vss_commitments **commitments = malloc(
        sizeof(secp256k1_frost_vss_commitments *) * round1_count);
    if (!commitments) return -3;

    for (size_t i = 0; i < round1_count; i++) {
        commitments[i] = secp256k1_frost_vss_commitments_create(all_round1[i].num_coefficients);
        if (!commitments[i]) {
            for (size_t j = 0; j < i; j++) secp256k1_frost_vss_commitments_destroy(commitments[j]);
            free(commitments);
            return -4;
        }
        commitments[i]->index = all_round1[i].participant_index;
        commitments[i]->num_coefficients = all_round1[i].num_coefficients;
        for (uint8_t k = 0; k < all_round1[i].num_coefficients; k++) {
            memcpy(commitments[i]->coefficient_commitments[k].data, all_round1[i].coefficient_commitments[k], 64);
        }
        memcpy(commitments[i]->zkp_r, all_round1[i].zkp_r, 64);
        memcpy(commitments[i]->zkp_z, all_round1[i].zkp_z, 32);
    }

    secp256k1_frost_keygen_secret_share *shares = malloc(
        sizeof(secp256k1_frost_keygen_secret_share) * share_count);
    if (!shares) {
        for (size_t i = 0; i < round1_count; i++) secp256k1_frost_vss_commitments_destroy(commitments[i]);
        free(commitments);
        return -5;
    }

    for (size_t i = 0; i < share_count; i++) {
        shares[i].generator_index = received_shares[i].generator_index;
        shares[i].receiver_index = received_shares[i].receiver_index;
        memcpy(shares[i].value, received_shares[i].value, 32);
    }

    secp256k1_frost_keypair *keypair = secp256k1_frost_keypair_create(our_index);
    if (!keypair) {
        free(shares);
        for (size_t i = 0; i < round1_count; i++) secp256k1_frost_vss_commitments_destroy(commitments[i]);
        free(commitments);
        return -6;
    }

    int ret = secp256k1_frost_keygen_dkg_finalize(ctx, keypair, our_index,
        (uint32_t)round1_count, shares, commitments);

    if (ret == 1) {
        memcpy(our_share, keypair->secret, 32);
        secure_memzero(keypair->secret, 32);
        uint8_t pubkey33[33], group33[33];
        secp256k1_frost_pubkey_save(pubkey33, group33, &keypair->public_keys);
        memcpy(group_pubkey, group33, 33);
    }

    secp256k1_frost_keypair_destroy(keypair);
    free(shares);
    for (size_t i = 0; i < round1_count; i++) secp256k1_frost_vss_commitments_destroy(commitments[i]);
    free(commitments);

    return ret == 1 ? 0 : -7;
}

int frost_sign_partial(const frost_group_t *group,
                        const frost_sign_request_t *request,
                        const uint8_t our_share[32],
                        uint8_t our_index,
                        frost_sign_response_t *response) {
    if (!group || !request || !our_share || !response) {
        return -1;
    }

    memset(response, 0, sizeof(*response));
    memcpy(response->request_id, request->request_id, 32);
    response->participant_index = our_index;
    response->status = FROST_SIGN_STATUS_SIGNED;

    secp256k1_context *ctx = get_secp_ctx();
    if (!ctx) {
        response->status = FROST_SIGN_STATUS_REJECTED;
        strncpy(response->rejection_reason, "Crypto context unavailable", sizeof(response->rejection_reason) - 1);
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
        strncpy(response->rejection_reason, "Keypair creation failed", sizeof(response->rejection_reason) - 1);
        return -3;
    }

    memcpy(kp->secret, our_share, 32);

    uint8_t binding_seed[32], hiding_seed[32];
#ifdef ESP_PLATFORM
    esp_fill_random(binding_seed, 32);
    esp_fill_random(hiding_seed, 32);
#else
    if (secure_random_fill(binding_seed, 32) != 0 || secure_random_fill(hiding_seed, 32) != 0) {
        secure_memzero(kp->secret, 32);
        secp256k1_frost_keypair_destroy(kp);
        response->status = FROST_SIGN_STATUS_REJECTED;
        strncpy(response->rejection_reason, "Failed to get secure random", sizeof(response->rejection_reason) - 1);
        return -4;
    }
#endif

    secp256k1_frost_nonce *nonce = secp256k1_frost_nonce_create(ctx, kp, binding_seed, hiding_seed);
    secure_memzero(binding_seed, 32);
    secure_memzero(hiding_seed, 32);

    if (!nonce) {
        secure_memzero(kp->secret, 32);
        secp256k1_frost_keypair_destroy(kp);
        response->status = FROST_SIGN_STATUS_REJECTED;
        strncpy(response->rejection_reason, "Nonce creation failed", sizeof(response->rejection_reason) - 1);
        return -4;
    }

    response->nonce_commitment[0] = 0x02 | (nonce->commitments.hiding[63] & 0x01);
    memcpy(response->nonce_commitment + 1, nonce->commitments.hiding, 32);

    secp256k1_frost_signature_share sig_share;
    secp256k1_frost_nonce_commitment commits[MAX_GROUP_PARTICIPANTS];
    size_t commit_count = 0;

    commits[commit_count++] = nonce->commitments;

    int ret = secp256k1_frost_sign(ctx, &sig_share, msg_hash, 32, (int)commit_count, kp, nonce, commits);

    secp256k1_frost_nonce_destroy(nonce);
    secure_memzero(kp->secret, 32);
    secp256k1_frost_keypair_destroy(kp);

    if (ret != 1) {
        response->status = FROST_SIGN_STATUS_REJECTED;
        strncpy(response->rejection_reason, "Signing failed", sizeof(response->rejection_reason) - 1);
        return -5;
    }

    memcpy(response->partial_signature, sig_share.response, 32);
    return 0;
}
