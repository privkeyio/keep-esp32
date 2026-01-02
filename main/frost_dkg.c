#include "frost_dkg.h"
#include "nostr_frost.h"
#include "storage.h"
#include "crypto_asm.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef ESP_PLATFORM
#include "esp_log.h"
#else
#define ESP_LOGI(tag, fmt, ...) printf("[%s] " fmt "\n", tag, ##__VA_ARGS__)
#define ESP_LOGE(tag, fmt, ...) printf("[%s] ERROR: " fmt "\n", tag, ##__VA_ARGS__)
#endif

#define TAG "frost_dkg"

typedef struct {
    bool active;
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

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > out_len) return -1;
    for (size_t i = 0; i < hex_len / 2; i++) {
        unsigned int byte;
        if (sscanf(hex + 2*i, "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return (int)(hex_len / 2);
}

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + i*2, "%02x", bytes[i]);
    }
    hex[len*2] = '\0';
}

void dkg_init(const rpc_request_t *req, rpc_response_t *resp) {
    if (req->threshold < 2 || req->threshold > DKG_MAX_THRESHOLD) {
        protocol_error(resp, req->id, -1, "Invalid threshold");
        return;
    }
    if (req->participant_count < req->threshold || req->participant_count > DKG_MAX_PARTICIPANTS) {
        protocol_error(resp, req->id, -1, "Invalid participant count");
        return;
    }
    if (req->our_index < 1 || req->our_index > req->participant_count) {
        protocol_error(resp, req->id, -1, "Invalid our_index");
        return;
    }
    if (strlen(req->group) == 0) {
        protocol_error(resp, req->id, -1, "Group required");
        return;
    }

    memset(&g_session, 0, sizeof(g_session));
    g_session.active = true;
    strncpy(g_session.group, req->group, sizeof(g_session.group) - 1);
    g_session.threshold = req->threshold;
    g_session.participant_count = req->participant_count;
    g_session.our_index = req->our_index;

    ESP_LOGI(TAG, "DKG init: group=%s t=%d n=%d our_index=%d",
             g_session.group, g_session.threshold, g_session.participant_count, g_session.our_index);

    protocol_success(resp, req->id, "{\"ok\":true}");
}

void dkg_round1(const rpc_request_t *req, rpc_response_t *resp) {
    if (!g_session.active) {
        protocol_error(resp, req->id, -1, "No active DKG session");
        return;
    }

    frost_group_t group;
    memset(&group, 0, sizeof(group));
    group.threshold = g_session.threshold;
    group.participant_count = g_session.participant_count;

    int ret = frost_dkg_round1_generate(&group, g_session.our_index,
                                         &g_session.our_round1,
                                         (uint8_t*)g_session.secret_shares,
                                         &g_session.secret_share_count);
    if (ret != 0) {
        protocol_error(resp, req->id, -1, "Round 1 generation failed");
        return;
    }

    char result[2400];
    char coeffs_hex[MAX_THRESHOLD * 129];
    size_t offset = 0;
    for (uint8_t i = 0; i < g_session.our_round1.num_coefficients && i < MAX_THRESHOLD; i++) {
        bytes_to_hex(g_session.our_round1.coefficient_commitments[i], 64, coeffs_hex + offset);
        offset += 128;
        if (i < g_session.our_round1.num_coefficients - 1) {
            coeffs_hex[offset++] = ',';
        }
    }
    coeffs_hex[offset] = '\0';

    char zkp_r_hex[129], zkp_z_hex[65];
    bytes_to_hex(g_session.our_round1.zkp_r, 64, zkp_r_hex);
    bytes_to_hex(g_session.our_round1.zkp_z, 32, zkp_z_hex);

    snprintf(result, sizeof(result),
             "{\"participant_index\":%d,\"num_coefficients\":%d,"
             "\"coefficient_commitments\":\"%s\","
             "\"zkp_r\":\"%s\",\"zkp_z\":\"%s\"}",
             g_session.our_index,
             g_session.our_round1.num_coefficients,
             coeffs_hex, zkp_r_hex, zkp_z_hex);

    protocol_success(resp, req->id, result);
}

void dkg_round1_peer(const rpc_request_t *req, rpc_response_t *resp) {
    if (!g_session.active) {
        protocol_error(resp, req->id, -1, "No active DKG session");
        return;
    }
    if (g_session.peer_round1_count >= DKG_MAX_PARTICIPANTS) {
        protocol_error(resp, req->id, -1, "Too many peer round1 entries");
        return;
    }
    if (req->peer_index < 1 || req->peer_index > g_session.participant_count) {
        protocol_error(resp, req->id, -1, "Invalid peer_index");
        return;
    }
    for (uint8_t i = 0; i < g_session.peer_round1_count; i++) {
        if (g_session.peer_round1[i].participant_index == req->peer_index) {
            protocol_error(resp, req->id, -1, "Duplicate peer_index");
            return;
        }
    }
    if (strlen(req->dkg_data) == 0) {
        protocol_error(resp, req->id, -1, "dkg_data required");
        return;
    }

    frost_dkg_round1_t *peer = &g_session.peer_round1[g_session.peer_round1_count];
    memset(peer, 0, sizeof(*peer));
    peer->participant_index = req->peer_index;

    char *data = strdup(req->dkg_data);
    if (!data) {
        protocol_error(resp, req->id, -1, "Memory error");
        return;
    }

    char *num_coeff_str = strstr(data, "num_coefficients\":");
    char *coeffs_str = strstr(data, "coefficient_commitments\":\"");
    char *zkp_r_str = strstr(data, "zkp_r\":\"");
    char *zkp_z_str = strstr(data, "zkp_z\":\"");

    if (!num_coeff_str || !coeffs_str || !zkp_r_str || !zkp_z_str) {
        free(data);
        protocol_error(resp, req->id, -1, "Malformed dkg_data");
        return;
    }

    peer->num_coefficients = (uint8_t)atoi(num_coeff_str + 18);
    if (peer->num_coefficients > MAX_THRESHOLD) {
        free(data);
        protocol_error(resp, req->id, -1, "Too many coefficients");
        return;
    }

    char *coeffs_start = coeffs_str + 26;
    char *coeffs_end = strchr(coeffs_start, '"');
    if (!coeffs_end) { free(data); protocol_error(resp, req->id, -1, "Parse error"); return; }
    *coeffs_end = '\0';

    size_t coeff_offset = 0;
    for (uint8_t i = 0; i < peer->num_coefficients; i++) {
        if (coeff_offset + 128 > strlen(coeffs_start) + 1) break;
        char coeff_hex[129];
        strncpy(coeff_hex, coeffs_start + coeff_offset, 128);
        coeff_hex[128] = '\0';
        hex_to_bytes(coeff_hex, peer->coefficient_commitments[i], 64);
        coeff_offset += 128;
        if (coeffs_start[coeff_offset] == ',') coeff_offset++;
    }

    char *zkp_r_start = zkp_r_str + 8;
    char zkp_r_hex[129];
    strncpy(zkp_r_hex, zkp_r_start, 128);
    zkp_r_hex[128] = '\0';
    hex_to_bytes(zkp_r_hex, peer->zkp_r, 64);

    char *zkp_z_start = zkp_z_str + 8;
    char zkp_z_hex[65];
    strncpy(zkp_z_hex, zkp_z_start, 64);
    zkp_z_hex[64] = '\0';
    hex_to_bytes(zkp_z_hex, peer->zkp_z, 32);

    free(data);

    int ret = frost_dkg_round1_validate(peer);
    if (ret != 0) {
        protocol_error(resp, req->id, -1, "Round 1 validation failed");
        return;
    }

    g_session.peer_round1_count++;
    ESP_LOGI(TAG, "Stored peer %d round1 data", req->peer_index);

    protocol_success(resp, req->id, "{\"ok\":true,\"validated\":true}");
}

void dkg_round2(const rpc_request_t *req, rpc_response_t *resp) {
    if (!g_session.active) {
        protocol_error(resp, req->id, -1, "No active DKG session");
        return;
    }
    if (g_session.secret_share_count == 0) {
        protocol_error(resp, req->id, -1, "Round 1 not completed");
        return;
    }

    char result[1600];
    size_t offset = 0;
    offset += snprintf(result + offset, sizeof(result) - offset, "{\"shares\":[");

    for (uint8_t i = 0; i < g_session.participant_count && i < DKG_MAX_PARTICIPANTS; i++) {
        if (i + 1 == g_session.our_index) continue;

        char share_hex[65];
        bytes_to_hex(g_session.secret_shares[i], 32, share_hex);

        if (offset > 12) {
            offset += snprintf(result + offset, sizeof(result) - offset, ",");
        }
        offset += snprintf(result + offset, sizeof(result) - offset,
                           "{\"recipient_index\":%d,\"share\":\"%s\"}",
                           i + 1, share_hex);
    }

    offset += snprintf(result + offset, sizeof(result) - offset, "]}");

    protocol_success(resp, req->id, result);
}

void dkg_receive_share(const rpc_request_t *req, rpc_response_t *resp) {
    if (!g_session.active) {
        protocol_error(resp, req->id, -1, "No active DKG session");
        return;
    }
    if (g_session.received_share_count >= DKG_MAX_PARTICIPANTS) {
        protocol_error(resp, req->id, -1, "Too many received shares");
        return;
    }
    if (req->peer_index < 1 || req->peer_index > g_session.participant_count) {
        protocol_error(resp, req->id, -1, "Invalid peer_index");
        return;
    }
    for (uint8_t i = 0; i < g_session.received_share_count; i++) {
        if (g_session.received_shares[i].generator_index == req->peer_index) {
            protocol_error(resp, req->id, -1, "Duplicate share from peer");
            return;
        }
    }
    if (strlen(req->share) != 64) {
        protocol_error(resp, req->id, -1, "Invalid share length");
        return;
    }

    frost_dkg_share_t *share = &g_session.received_shares[g_session.received_share_count];
    share->generator_index = req->peer_index;
    share->receiver_index = g_session.our_index;
    hex_to_bytes(req->share, share->value, 32);

    g_session.received_share_count++;
    ESP_LOGI(TAG, "Received share from peer %d", req->peer_index);

    protocol_success(resp, req->id, "{\"ok\":true}");
}

void dkg_finalize(const rpc_request_t *req, rpc_response_t *resp) {
    if (!g_session.active) {
        protocol_error(resp, req->id, -1, "No active DKG session");
        return;
    }

    frost_dkg_round1_t all_round1[DKG_MAX_PARTICIPANTS];
    size_t round1_count = 0;

    memcpy(&all_round1[round1_count++], &g_session.our_round1, sizeof(frost_dkg_round1_t));
    for (uint8_t i = 0; i < g_session.peer_round1_count; i++) {
        memcpy(&all_round1[round1_count++], &g_session.peer_round1[i], sizeof(frost_dkg_round1_t));
    }

    frost_dkg_share_t all_shares[DKG_MAX_PARTICIPANTS];
    size_t share_count = 0;

    frost_dkg_share_t our_share_entry;
    our_share_entry.generator_index = g_session.our_index;
    our_share_entry.receiver_index = g_session.our_index;
    memcpy(our_share_entry.value, g_session.secret_shares[g_session.our_index - 1], 32);
    memcpy(&all_shares[share_count++], &our_share_entry, sizeof(frost_dkg_share_t));

    for (uint8_t i = 0; i < g_session.received_share_count; i++) {
        memcpy(&all_shares[share_count++], &g_session.received_shares[i], sizeof(frost_dkg_share_t));
    }

    frost_group_t group;
    memset(&group, 0, sizeof(group));
    group.threshold = g_session.threshold;
    group.participant_count = g_session.participant_count;

    uint8_t final_share[32];
    uint8_t group_pubkey[33];

    int ret = frost_dkg_finalize(&group, all_round1, round1_count,
                                  all_shares, share_count,
                                  g_session.our_index,
                                  final_share, group_pubkey);
    if (ret != 0) {
        char err[64];
        snprintf(err, sizeof(err), "DKG finalize failed: %d", ret);
        protocol_error(resp, req->id, -1, err);
        return;
    }

    char share_hex[65];
    bytes_to_hex(final_share, 32, share_hex);

    if (storage_save_share(g_session.group, share_hex) != 0) {
        protocol_error(resp, req->id, -1, "Failed to store share");
        return;
    }

    char pubkey_hex[67];
    bytes_to_hex(group_pubkey, 33, pubkey_hex);

    secure_memzero(final_share, sizeof(final_share));
    secure_memzero(share_hex, sizeof(share_hex));
    secure_memzero(g_session.secret_shares, sizeof(g_session.secret_shares));
    secure_memzero(&g_session.our_round1, sizeof(g_session.our_round1));
    secure_memzero(g_session.received_shares, sizeof(g_session.received_shares));
    for (uint8_t i = 0; i < g_session.peer_round1_count; i++) {
        secure_memzero(&g_session.peer_round1[i], sizeof(frost_dkg_round1_t));
    }
    g_session.peer_round1_count = 0;
    g_session.received_share_count = 0;
    g_session.secret_share_count = 0;

    g_session.active = false;
    ESP_LOGI(TAG, "DKG complete, share stored for group %s", g_session.group);

    char result[200];
    snprintf(result, sizeof(result),
             "{\"ok\":true,\"group_pubkey\":\"%s\",\"our_index\":%d}",
             pubkey_hex, g_session.our_index);

    protocol_success(resp, req->id, result);
}
