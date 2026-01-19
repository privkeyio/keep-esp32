// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "frost_dkg.h"
#include "nostr_frost.h"
#include "storage.h"
#include "crypto_asm.h"
#include "hex_utils.h"
#include "random_utils.h"
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef ESP_PLATFORM
#include "esp_log.h"
#include <sys/time.h>
#else
#include <time.h>
#define ESP_LOGI(tag, fmt, ...) printf("[%s] " fmt "\n", tag, ##__VA_ARGS__)
#define ESP_LOGW(tag, fmt, ...) printf("[%s] WARN: " fmt "\n", tag, ##__VA_ARGS__)
#define ESP_LOGE(tag, fmt, ...) printf("[%s] ERROR: " fmt "\n", tag, ##__VA_ARGS__)
#endif

static uint64_t get_unix_time(void) {
#ifdef ESP_PLATFORM
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec;
#else
    return (uint64_t)time(NULL);
#endif
}

#define TAG "frost_dkg"

typedef struct {
    dkg_state_t state;
    char group[65];
    uint8_t threshold;
    uint8_t participant_count;
    uint8_t our_index;
    frost_dkg_round1_t our_round1;
    uint8_t secret_shares[DKG_MAX_PARTICIPANTS][32];
    size_t secret_share_count;
    frost_dkg_round1_t peer_round1[DKG_MAX_PARTICIPANTS];
    uint8_t peer_round1_count;
    frost_dkg_share_t received_shares[DKG_MAX_PARTICIPANTS];
    uint8_t received_share_count;
} dkg_session_t;

static dkg_session_t g_session;

static const char *dkg_state_name(dkg_state_t state) {
    switch (state) {
    case DKG_IDLE:
        return "IDLE";
    case DKG_ROUND1:
        return "ROUND1";
    case DKG_ROUND2:
        return "ROUND2";
    case DKG_COMPLETE:
        return "COMPLETE";
    }
    return "UNKNOWN";
}

static bool check_state(dkg_state_t expected, const char *func_name, const rpc_request_t *req,
                        rpc_response_t *resp) {
    if (g_session.state == expected) {
        return true;
    }
    char err[64];
    snprintf(err, sizeof(err), "Invalid state %s for %s", dkg_state_name(g_session.state),
             func_name);
    PROTOCOL_ERROR(resp, req->id, -1, err);
    return false;
}

static bool check_can_init(const rpc_request_t *req, rpc_response_t *resp) {
    if (g_session.state == DKG_IDLE || g_session.state == DKG_COMPLETE) {
        return true;
    }
    char err[64];
    snprintf(err, sizeof(err), "Invalid state %s for init", dkg_state_name(g_session.state));
    PROTOCOL_ERROR(resp, req->id, -1, err);
    return false;
}

static void clear_sensitive_session_data(void) {
    secure_memzero(g_session.secret_shares, sizeof(g_session.secret_shares));
    secure_memzero(&g_session.our_round1, sizeof(g_session.our_round1));
    secure_memzero(g_session.received_shares, sizeof(g_session.received_shares));
    secure_memzero(g_session.peer_round1, sizeof(g_session.peer_round1));
    g_session.peer_round1_count = 0;
    g_session.received_share_count = 0;
    g_session.secret_share_count = 0;
}

void dkg_init(const rpc_request_t *req, rpc_response_t *resp) {
    if (!check_can_init(req, resp)) {
        return;
    }
    if (req->threshold < 2 || req->threshold > DKG_MAX_THRESHOLD) {
        PROTOCOL_ERROR(resp, req->id, -1, "Invalid threshold");
        return;
    }
    if (req->participant_count < req->threshold || req->participant_count > DKG_MAX_PARTICIPANTS) {
        PROTOCOL_ERROR(resp, req->id, -1, "Invalid participant count");
        return;
    }
    if (req->our_index < 1 || req->our_index > req->participant_count) {
        PROTOCOL_ERROR(resp, req->id, -1, "Invalid our_index");
        return;
    }
    if (strlen(req->group) == 0) {
        PROTOCOL_ERROR(resp, req->id, -1, "Group required");
        return;
    }

    memset(&g_session, 0, sizeof(g_session));
    g_session.state = DKG_ROUND1;
    strncpy(g_session.group, req->group, sizeof(g_session.group) - 1);
    g_session.threshold = req->threshold;
    g_session.participant_count = req->participant_count;
    g_session.our_index = req->our_index;

    ESP_LOGI(TAG, "DKG init -> ROUND1 (group=%s t=%d n=%d idx=%d)", g_session.group,
             g_session.threshold, g_session.participant_count, g_session.our_index);

    protocol_success(resp, req->id, "{\"ok\":true}");
}

void dkg_round1(const rpc_request_t *req, rpc_response_t *resp) {
    if (!rng_is_healthy()) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_INTERNAL,
                       "RNG health check failed, device in safe mode");
        return;
    }

    if (!check_state(DKG_ROUND1, "round1", req, resp)) {
        return;
    }

    frost_group_t group = {.threshold = g_session.threshold,
                           .participant_count = g_session.participant_count};

    int ret = frost_dkg_round1_generate(&group, g_session.our_index, &g_session.our_round1,
                                        (uint8_t *)g_session.secret_shares,
                                        &g_session.secret_share_count);
    if (ret != 0) {
        PROTOCOL_ERROR(resp, req->id, -1, "Round 1 generation failed");
        return;
    }

    g_session.state = DKG_ROUND2;
    ESP_LOGI(TAG, "DKG state: ROUND1 -> ROUND2");

    char result[2400];
    char coeffs_hex[MAX_THRESHOLD * 129];
    size_t offset = 0;
    for (uint8_t i = 0; i < g_session.our_round1.num_coefficients && i < MAX_THRESHOLD; i++) {
        bytes_to_hex(g_session.our_round1.coefficient_commitments[i], 64, coeffs_hex + offset,
                     sizeof(coeffs_hex) - offset);
        offset += 128;
        if (i < g_session.our_round1.num_coefficients - 1) {
            coeffs_hex[offset++] = ',';
        }
    }
    coeffs_hex[offset] = '\0';

    char zkp_r_hex[129], zkp_z_hex[65];
    bytes_to_hex(g_session.our_round1.zkp_r, 64, zkp_r_hex, sizeof(zkp_r_hex));
    bytes_to_hex(g_session.our_round1.zkp_z, 32, zkp_z_hex, sizeof(zkp_z_hex));

    snprintf(result, sizeof(result),
             "{\"participant_index\":%d,\"num_coefficients\":%d,"
             "\"coefficient_commitments\":\"%s\","
             "\"zkp_r\":\"%s\",\"zkp_z\":\"%s\"}",
             g_session.our_index, g_session.our_round1.num_coefficients, coeffs_hex, zkp_r_hex,
             zkp_z_hex);

    protocol_success(resp, req->id, result);
}

void dkg_round1_peer(const rpc_request_t *req, rpc_response_t *resp) {
    if (!check_state(DKG_ROUND2, "round1_peer", req, resp)) {
        return;
    }
    if (g_session.peer_round1_count >= DKG_MAX_PARTICIPANTS) {
        PROTOCOL_ERROR(resp, req->id, -1, "Too many peer round1 entries");
        return;
    }
    if (req->peer_index < 1 || req->peer_index > g_session.participant_count) {
        PROTOCOL_ERROR(resp, req->id, -1, "Invalid peer_index");
        return;
    }
    for (uint8_t i = 0; i < g_session.peer_round1_count; i++) {
        if (g_session.peer_round1[i].participant_index == req->peer_index) {
            PROTOCOL_ERROR(resp, req->id, -1, "Duplicate peer_index");
            return;
        }
    }
    if (strlen(req->dkg_data) == 0) {
        PROTOCOL_ERROR(resp, req->id, -1, "dkg_data required");
        return;
    }

    frost_dkg_round1_t *peer = &g_session.peer_round1[g_session.peer_round1_count];
    memset(peer, 0, sizeof(*peer));
    peer->participant_index = req->peer_index;

    char *data = strdup(req->dkg_data);
    if (!data) {
        PROTOCOL_ERROR(resp, req->id, -1, "Memory error");
        return;
    }

    char *num_coeff_str = strstr(data, "num_coefficients\":");
    char *coeffs_str = strstr(data, "coefficient_commitments\":\"");
    char *zkp_r_str = strstr(data, "zkp_r\":\"");
    char *zkp_z_str = strstr(data, "zkp_z\":\"");

    if (!num_coeff_str || !coeffs_str || !zkp_r_str || !zkp_z_str) {
        free(data);
        PROTOCOL_ERROR(resp, req->id, -1, "Malformed dkg_data");
        return;
    }

    char *endptr;
    long num_coeff_tmp = strtol(num_coeff_str + 18, &endptr, 10);
    if (endptr == num_coeff_str + 18 || num_coeff_tmp <= 0 || num_coeff_tmp > MAX_THRESHOLD) {
        free(data);
        PROTOCOL_ERROR(resp, req->id, -1, "Invalid num_coefficients");
        return;
    }
    peer->num_coefficients = (uint8_t)num_coeff_tmp;

    char *coeffs_start = coeffs_str + 26;
    char *coeffs_end = strchr(coeffs_start, '"');
    if (!coeffs_end) {
        free(data);
        PROTOCOL_ERROR(resp, req->id, -1, "Parse error");
        return;
    }
    *coeffs_end = '\0';

    size_t coeffs_len = strlen(coeffs_start);
    size_t coeff_offset = 0;
    for (uint8_t i = 0; i < peer->num_coefficients; i++) {
        if (coeff_offset + 128 > coeffs_len)
            break;
        char coeff_hex[129];
        strncpy(coeff_hex, coeffs_start + coeff_offset, 128);
        coeff_hex[128] = '\0';
        if (hex_to_bytes(coeff_hex, peer->coefficient_commitments[i], 64) != 64) {
            free(data);
            PROTOCOL_ERROR(resp, req->id, -1, "Invalid coefficient hex");
            return;
        }
        coeff_offset += 128;
        if (coeff_offset < coeffs_len && coeffs_start[coeff_offset] == ',')
            coeff_offset++;
    }

    char *zkp_r_start = zkp_r_str + 8;
    size_t zkp_r_remaining = strlen(zkp_r_start);
    if (zkp_r_remaining < 128) {
        free(data);
        PROTOCOL_ERROR(resp, req->id, -1, "zkp_r too short");
        return;
    }
    char zkp_r_hex[129];
    strncpy(zkp_r_hex, zkp_r_start, 128);
    zkp_r_hex[128] = '\0';
    if (hex_to_bytes(zkp_r_hex, peer->zkp_r, 64) != 64) {
        free(data);
        PROTOCOL_ERROR(resp, req->id, -1, "Invalid zkp_r hex");
        return;
    }

    char *zkp_z_start = zkp_z_str + 8;
    size_t zkp_z_remaining = strlen(zkp_z_start);
    if (zkp_z_remaining < 64) {
        free(data);
        PROTOCOL_ERROR(resp, req->id, -1, "zkp_z too short");
        return;
    }
    char zkp_z_hex[65];
    strncpy(zkp_z_hex, zkp_z_start, 64);
    zkp_z_hex[64] = '\0';
    if (hex_to_bytes(zkp_z_hex, peer->zkp_z, 32) != 32) {
        free(data);
        PROTOCOL_ERROR(resp, req->id, -1, "Invalid zkp_z hex");
        return;
    }

    free(data);

    int ret = frost_dkg_round1_validate(peer);
    if (ret != 0) {
        PROTOCOL_ERROR(resp, req->id, -1, "Round 1 validation failed");
        return;
    }

    g_session.peer_round1_count++;
    ESP_LOGI(TAG, "Stored peer %d round1 data", req->peer_index);

    protocol_success(resp, req->id, "{\"ok\":true,\"validated\":true}");
}

void dkg_round2(const rpc_request_t *req, rpc_response_t *resp) {
    if (!check_state(DKG_ROUND2, "round2", req, resp)) {
        return;
    }

    char result[1600];
    size_t offset = 0;
    bool first = true;
    offset += snprintf(result + offset, sizeof(result) - offset, "{\"shares\":[");

    for (uint8_t i = 0; i < g_session.participant_count && i < DKG_MAX_PARTICIPANTS; i++) {
        if (i + 1 == g_session.our_index) {
            continue;
        }

        char share_hex[65];
        bytes_to_hex(g_session.secret_shares[i], 32, share_hex, sizeof(share_hex));

        if (!first) {
            offset += snprintf(result + offset, sizeof(result) - offset, ",");
        }
        first = false;
        offset += snprintf(result + offset, sizeof(result) - offset,
                           "{\"recipient_index\":%d,\"share\":\"%s\"}", i + 1, share_hex);
    }

    offset += snprintf(result + offset, sizeof(result) - offset, "]}");
    protocol_success(resp, req->id, result);
}

void dkg_receive_share(const rpc_request_t *req, rpc_response_t *resp) {
    if (!check_state(DKG_ROUND2, "receive_share", req, resp)) {
        return;
    }
    if (g_session.received_share_count >= DKG_MAX_PARTICIPANTS) {
        PROTOCOL_ERROR(resp, req->id, -1, "Too many received shares");
        return;
    }
    if (req->peer_index < 1 || req->peer_index > g_session.participant_count) {
        PROTOCOL_ERROR(resp, req->id, -1, "Invalid peer_index");
        return;
    }
    for (uint8_t i = 0; i < g_session.received_share_count; i++) {
        if (g_session.received_shares[i].generator_index == req->peer_index) {
            PROTOCOL_ERROR(resp, req->id, -1, "Duplicate share from peer");
            return;
        }
    }
    if (strlen(req->share) != 64) {
        PROTOCOL_ERROR(resp, req->id, -1, "Invalid share length");
        return;
    }

    frost_dkg_share_t *share = &g_session.received_shares[g_session.received_share_count];
    share->generator_index = req->peer_index;
    share->receiver_index = g_session.our_index;
    if (hex_to_bytes(req->share, share->value, 32) != 32) {
        PROTOCOL_ERROR(resp, req->id, -1, "Invalid share hex");
        return;
    }

    g_session.received_share_count++;
    ESP_LOGI(TAG, "Received share from peer %d", req->peer_index);

    protocol_success(resp, req->id, "{\"ok\":true}");
}

void dkg_finalize(const rpc_request_t *req, rpc_response_t *resp) {
    if (!check_state(DKG_ROUND2, "finalize", req, resp)) {
        return;
    }

    frost_dkg_round1_t all_round1[DKG_MAX_PARTICIPANTS];
    size_t round1_count = 0;
    all_round1[round1_count++] = g_session.our_round1;
    for (uint8_t i = 0; i < g_session.peer_round1_count; i++) {
        all_round1[round1_count++] = g_session.peer_round1[i];
    }

    if (g_session.our_index < 1 || g_session.our_index > DKG_MAX_PARTICIPANTS) {
        PROTOCOL_ERROR(resp, req->id, -1, "Invalid session state: our_index");
        return;
    }

    frost_dkg_share_t all_shares[DKG_MAX_PARTICIPANTS];
    size_t share_count = 0;
    all_shares[share_count++] = (frost_dkg_share_t){.generator_index = g_session.our_index,
                                                    .receiver_index = g_session.our_index};
    memcpy(all_shares[0].value, g_session.secret_shares[g_session.our_index - 1], 32);
    for (uint8_t i = 0; i < g_session.received_share_count; i++) {
        all_shares[share_count++] = g_session.received_shares[i];
    }

    frost_group_t group = {.threshold = g_session.threshold,
                           .participant_count = g_session.participant_count};

    uint8_t final_share[32];
    uint8_t group_pubkey[33];

    int ret = frost_dkg_finalize(&group, all_round1, round1_count, all_shares, share_count,
                                 g_session.our_index, final_share, group_pubkey);
    if (ret != 0) {
        char err[64];
        snprintf(err, sizeof(err), "DKG finalize failed: %d", ret);
        PROTOCOL_ERROR(resp, req->id, -1, err);
        return;
    }

    char share_hex[65];
    bytes_to_hex(final_share, 32, share_hex, sizeof(share_hex));

    if (storage_save_share(g_session.group, share_hex) != 0) {
        secure_memzero(final_share, sizeof(final_share));
        secure_memzero(share_hex, sizeof(share_hex));
        PROTOCOL_ERROR(resp, req->id, -1, "Failed to store share");
        return;
    }

    group_metadata_t metadata;
    memset(&metadata, 0, sizeof(metadata));
    metadata.threshold = g_session.threshold;
    metadata.participant_count = g_session.participant_count;
    metadata.our_index = g_session.our_index;
    metadata.created_at = get_unix_time();
    memcpy(metadata.group_pubkey, group_pubkey, 33);

    for (uint8_t i = 0; i < g_session.participant_count && i < STORAGE_MAX_PARTICIPANTS; i++) {
        metadata.participants[i].index = i + 1;
    }

    int meta_ret = storage_save_metadata(g_session.group, &metadata);
    if (meta_ret != 0) {
        ESP_LOGW(TAG, "Failed to save metadata: %d (share saved successfully)", meta_ret);
    }

    char pubkey_hex[67];
    bytes_to_hex(group_pubkey, 33, pubkey_hex, sizeof(pubkey_hex));

    secure_memzero(final_share, sizeof(final_share));
    secure_memzero(share_hex, sizeof(share_hex));
    clear_sensitive_session_data();

    g_session.state = DKG_COMPLETE;
    ESP_LOGI(TAG, "DKG state: ROUND2 -> COMPLETE (group=%s)", g_session.group);

    char result[200];
    snprintf(result, sizeof(result), "{\"ok\":true,\"group_pubkey\":\"%s\",\"our_index\":%d}",
             pubkey_hex, g_session.our_index);

    protocol_success(resp, req->id, result);
}
