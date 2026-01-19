// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "frost_signer.h"
#include "frost_signer_core.h"
#include "frost_signer_storage.h"
#include "storage.h"
#include "frost.h"
#include "session.h"
#include "policy.h"
#include "hex_utils.h"
#include "random_utils.h"
#include "crypto_asm.h"
#include "secresult.h"
#include "esp_log.h"
#include <string.h>
#include <stdio.h>

#ifdef ESP_PLATFORM
#include "esp_timer.h"
static uint32_t get_time_ms(void) {
    return (uint32_t)(esp_timer_get_time() / 1000);
}
#else
#include <time.h>
#include <stdlib.h>
static uint32_t get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}
#endif

#define TAG                        "frost_signer"
#define MAX_SESSIONS               4
#define CONSUMED_SESSION_RING_SIZE 64

static uint8_t consumed_sessions[CONSUMED_SESSION_RING_SIZE][SESSION_ID_LEN];
static uint8_t consumed_count = 0;
static uint8_t consumed_head = 0;

static bool is_session_consumed(const uint8_t *session_id) {
    uint8_t count =
        (consumed_count < CONSUMED_SESSION_RING_SIZE) ? consumed_count : CONSUMED_SESSION_RING_SIZE;
    for (uint8_t i = 0; i < count; i++) {
        if (ct_compare(consumed_sessions[i], session_id, SESSION_ID_LEN) == 0) {
            return true;
        }
    }
    return false;
}

static void record_consumed_session(const uint8_t *session_id) {
    memcpy(consumed_sessions[consumed_head], session_id, SESSION_ID_LEN);
    consumed_head = (consumed_head + 1) % CONSUMED_SESSION_RING_SIZE;
    if (consumed_count < CONSUMED_SESSION_RING_SIZE) {
        consumed_count++;
    }
}

#ifdef FROST_SIGNER_QUIET_LOGS
#define FROST_LOGI(tag, ...) \
    do {                     \
    } while (0)
#define FROST_LOGW(tag, ...) \
    do {                     \
    } while (0)
#else
#ifdef ESP_PLATFORM
#define FROST_LOGI(tag, ...) ESP_LOGI(tag, __VA_ARGS__)
#define FROST_LOGW(tag, ...) ESP_LOGW(tag, __VA_ARGS__)
#else
#define FROST_LOGI(tag, fmt, ...) printf("[%s] " fmt "\n", tag, ##__VA_ARGS__)
#define FROST_LOGW(tag, fmt, ...) printf("[%s] WARN: " fmt "\n", tag, ##__VA_ARGS__)
#endif
#endif

typedef struct {
    bool active;
    uint8_t session_id[SESSION_ID_LEN];
    session_t session;
    frost_state_t frost_state;
    char group[STORAGE_GROUP_LEN + 1];
    bool has_policy;
    uint8_t policy_hash[32];
} signing_session_t;

static signing_session_t sessions[MAX_SESSIONS];

static signing_session_t *find_session(const uint8_t *session_id) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].active) {
            if (ct_compare(sessions[i].session_id, session_id, SESSION_ID_LEN) == 0) {
                return &sessions[i];
            }
        }
    }
    return NULL;
}

static signing_session_t *alloc_session(const uint8_t *session_id) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!sessions[i].active) {
            memset(&sessions[i], 0, sizeof(signing_session_t));
            sessions[i].active = true;
            memcpy(sessions[i].session_id, session_id, SESSION_ID_LEN);
            return &sessions[i];
        }
    }
    return NULL;
}

static void free_session(signing_session_t *s) {
    if (s) {
        frost_free(&s->frost_state);
        session_destroy(&s->session);
        secure_memzero(s, sizeof(signing_session_t));
    }
}

static secresult_t capture_policy_snapshot_secure(bool *has_policy, uint8_t policy_hash[32]) {
    *has_policy = false;
    memset(policy_hash, 0, 32);

    if (!policy_has_bundle()) {
        return SECRESULT_TRUE;
    }

    policy_bundle_t bundle;
    int ret = policy_load_bundle(&bundle);
    if (ret != 0) {
        secure_memzero(&bundle, sizeof(bundle));
        return SECRESULT_ERR_LOAD_FAILED;
    }

    secresult_t sig_result = policy_verify_signature_secure(&bundle);
    if (!SECRESULT_IS_TRUE(sig_result)) {
        secure_memzero(&bundle, sizeof(bundle));
        return sig_result;
    }

    *has_policy = true;
    memcpy(policy_hash, bundle.policy_hash, 32);
    secure_memzero(&bundle, sizeof(bundle));
    return SECRESULT_TRUE;
}

static secresult_t verify_policy_unchanged_secure(bool has_policy, const uint8_t policy_hash[32]) {
    bool current_has_policy = false;
    uint8_t current_hash[32];
    secresult_t result = capture_policy_snapshot_secure(&current_has_policy, current_hash);

    if (!SECRESULT_IS_TRUE(result)) {
        secure_memzero(current_hash, sizeof(current_hash));
        return result;
    }

    bool policy_changed = (has_policy != current_has_policy) ||
                          (has_policy && ct_compare(policy_hash, current_hash, 32) != 0);
    secure_memzero(current_hash, sizeof(current_hash));

    return policy_changed ? SECRESULT_ERR_POLICY_CHANGED : SECRESULT_TRUE;
}

static int parse_session_id(const char *hex, uint8_t *out, rpc_response_t *resp) {
    if (strlen(hex) != SESSION_ID_HEX_LEN) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_PARAMS, "session_id must be 32 bytes");
        return -1;
    }
    if (hex_to_bytes(hex, out, SESSION_ID_LEN) != SESSION_ID_LEN) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_PARAMS, "Invalid session_id hex");
        return -1;
    }
    if (!frost_is_session_id_valid(out)) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_PARAMS, "Invalid session_id value");
        return -1;
    }
    return 0;
}

int frost_signer_init(void) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        sessions[i].active = false;
    }
    memset(consumed_sessions, 0, sizeof(consumed_sessions));
    consumed_count = 0;
    consumed_head = 0;
    FROST_LOGI(TAG, "FROST signer ready");
    return 0;
}

void frost_signer_cleanup(void) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].active) {
            free_session(&sessions[i]);
        }
    }
}

void frost_get_pubkey(const char *group, rpc_response_t *resp) {
    const share_store_t *store = share_store_default();
    frost_state_t state;

    if (share_store_load_frost_state(store, group, &state) != 0) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SHARE, "Share not found");
        return;
    }

    char pubkey_hex[67];
    bytes_to_hex(state.group_pubkey, sizeof(state.group_pubkey), pubkey_hex, sizeof(pubkey_hex));

    char result[128];
    snprintf(result, sizeof(result), "{\"pubkey\":\"%s\",\"index\":%d}", pubkey_hex,
             state.share_index);
    protocol_success(resp, resp->id, result);

    frost_free(&state);
}

void frost_get_share_info(const char *group, rpc_response_t *resp) {
    const share_store_t *store = share_store_default();
    frost_state_t state;

    if (share_store_load_frost_state(store, group, &state) != 0) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SHARE, "Share not found");
        return;
    }

    char pubkey_hex[67];
    bytes_to_hex(state.group_pubkey, sizeof(state.group_pubkey), pubkey_hex, sizeof(pubkey_hex));

    char result[192];
    snprintf(result, sizeof(result),
             "{\"pubkey\":\"%s\",\"index\":%d,\"threshold\":%d,\"participants\":%d}", pubkey_hex,
             state.share_index, state.threshold, state.participants);
    protocol_success(resp, resp->id, result);

    frost_free(&state);
}

void frost_commit(const char *group, const char *session_id_hex, const char *message_hex,
                  rpc_response_t *resp) {
    if (!rng_is_healthy()) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_INTERNAL,
                       "RNG health check failed, device in safe mode");
        return;
    }

    uint8_t session_id[SESSION_ID_LEN];
    if (parse_session_id(session_id_hex, session_id, resp) != 0) {
        return;
    }

    if (strlen(message_hex) != SESSION_ID_HEX_LEN) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_PARAMS, "message must be 32 bytes");
        return;
    }

    uint8_t message[SESSION_ID_LEN];
    if (hex_to_bytes(message_hex, message, SESSION_ID_LEN) != SESSION_ID_LEN) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_PARAMS, "Invalid message hex");
        return;
    }

    if (is_session_consumed(session_id)) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Session ID already used");
        return;
    }

    if (find_session(session_id) != NULL) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Session ID already active");
        return;
    }

    bool has_policy = false;
    uint8_t policy_hash[32];
    secresult_t policy_ret = capture_policy_snapshot_secure(&has_policy, policy_hash);
    if (!SECRESULT_IS_TRUE(policy_ret)) {
        secure_memzero(policy_hash, sizeof(policy_hash));
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Policy bundle verification failed");
        return;
    }

    signing_session_t *s = alloc_session(session_id);
    if (!s) {
        secure_memzero(policy_hash, sizeof(policy_hash));
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "No free session slots");
        return;
    }

    s->has_policy = has_policy;
    memcpy(s->policy_hash, policy_hash, 32);
    secure_memzero(policy_hash, sizeof(policy_hash));

    const share_store_t *store = share_store_default();
    if (share_store_load_frost_state(store, group, &s->frost_state) != 0) {
        free_session(s);
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SHARE, "Share not found");
        return;
    }

    strncpy(s->group, group, STORAGE_GROUP_LEN);
    s->group[STORAGE_GROUP_LEN] = '\0';

    uint16_t threshold = s->frost_state.threshold > 0 ? s->frost_state.threshold : 2;
    if (frost_init_signing_session(&s->session, session_id, message, s->frost_state.share_index,
                                   threshold) != 0) {
        free_session(s);
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Failed to init session");
        return;
    }

    frost_commitment_result_t commit_result;
    if (frost_create_commitment_pure(&s->frost_state, &s->session, &commit_result) != 0) {
        free_session(s);
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Failed to create commitment");
        return;
    }

    int cp_ret = session_checkpoint_save(&s->session, s->session.our_nonce, s->group);
    if (cp_ret != 0) {
        FROST_LOGW(TAG, "Failed to checkpoint session: %d", cp_ret);
    }

    char commitment_hex[COMMITMENT_HEX_LEN + 1];
    bytes_to_hex(commit_result.commitment, commit_result.commitment_len, commitment_hex,
                 sizeof(commitment_hex));

    char result[512];
    snprintf(result, sizeof(result), "{\"commitment\":\"%s\",\"index\":%d}", commitment_hex,
             commit_result.index);
    protocol_success(resp, resp->id, result);

    FROST_LOGI(TAG, "Created commitment for session %.16s...", session_id_hex);
}

void frost_sign(const char *group, const char *session_id_hex, const char *commitments_hex,
                rpc_response_t *resp) {
    if (!rng_is_healthy()) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_INTERNAL,
                       "RNG health check failed, device in safe mode");
        return;
    }

    uint8_t session_id[SESSION_ID_LEN];
    if (parse_session_id(session_id_hex, session_id, resp) != 0) {
        return;
    }

    signing_session_t *s = find_session(session_id);
    if (!s) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Session not found");
        return;
    }

    if (ct_compare(s->group, group, strlen(group) + 1) != 0) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_PARAMS, "Group mismatch");
        return;
    }

    if (!SECRESULT_IS_TRUE(verify_policy_unchanged_secure(s->has_policy, s->policy_hash))) {
        free_session(s);
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Policy changed during session");
        return;
    }

    int parsed = frost_parse_commitments(commitments_hex, &s->session);
    if (parsed < 0) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_PARAMS, "Invalid commitments format");
        return;
    }

    uint8_t total_participants = s->session.commitment_count + 1;
    if (total_participants < s->frost_state.threshold) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Not enough commitments for threshold");
        return;
    }
    s->session.participant_count = total_participants;
    s->session.state = SESSION_AWAITING_SHARES;

    uint16_t our_index = s->frost_state.share_index;

    if (is_session_consumed(session_id)) {
        for (uint8_t i = 0; i < s->session.sig_share_count && i < MAX_PARTICIPANTS; i++) {
            if (s->session.sig_share_indices[i] == our_index) {
                char cached_share_hex[73];
                bytes_to_hex(s->session.sig_shares[i], s->session.sig_share_lens[i],
                             cached_share_hex, sizeof(cached_share_hex));

                char result[192];
                snprintf(result, sizeof(result), "{\"signature_share\":\"%s\",\"index\":%d}",
                         cached_share_hex, our_index);
                protocol_success(resp, resp->id, result);
                FROST_LOGI(TAG, "Returning cached signature share for session %.16s... (retry)",
                           session_id_hex);
                return;
            }
        }
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Session already consumed");
        return;
    }

    bool policy_snapshot = s->has_policy;
    uint8_t policy_hash_snapshot[32];
    memcpy(policy_hash_snapshot, s->policy_hash, 32);

    frost_sign_result_t sign_result;
    if (frost_sign_share_pure(&s->frost_state, &s->session, s->session.message,
                              s->session.message_len, &sign_result) != 0) {
        secure_memzero(policy_hash_snapshot, sizeof(policy_hash_snapshot));
        free_session(s);
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Signing failed");
        return;
    }

    if (!SECRESULT_IS_TRUE(verify_policy_unchanged_secure(policy_snapshot, policy_hash_snapshot))) {
        secure_memzero(policy_hash_snapshot, sizeof(policy_hash_snapshot));
        free_session(s);
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Policy changed during signing");
        return;
    }
    secure_memzero(policy_hash_snapshot, sizeof(policy_hash_snapshot));

    int share_idx = s->session.sig_share_count;
    if (share_idx >= MAX_PARTICIPANTS) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Maximum signature shares reached");
        return;
    }

    record_consumed_session(session_id);

    memcpy(s->session.sig_shares[share_idx], sign_result.sig_share, sign_result.sig_share_len);
    s->session.sig_share_lens[share_idx] = sign_result.sig_share_len;
    s->session.sig_share_indices[share_idx] = sign_result.index;
    s->session.sig_share_count++;

    session_checkpoint_clear(session_id);

    char sig_share_hex[73];
    bytes_to_hex(sign_result.sig_share, sign_result.sig_share_len, sig_share_hex,
                 sizeof(sig_share_hex));

    char result[192];
    snprintf(result, sizeof(result), "{\"signature_share\":\"%s\",\"index\":%d}", sig_share_hex,
             sign_result.index);
    protocol_success(resp, resp->id, result);

    FROST_LOGI(TAG, "Created signature share for session %.16s...", session_id_hex);
}

void frost_signer_cleanup_stale(void) {
    uint32_t now = get_time_ms();
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].active) {
            uint32_t created = sessions[i].session.created_at;
            uint32_t elapsed =
                (now >= created) ? (now - created) : (UINT32_MAX - created + now + 1);
            if (elapsed > SESSION_TIMEOUT_MS) {
                FROST_LOGW(TAG, "Cleaning up stale session");
                free_session(&sessions[i]);
            }
        }
    }
}

void frost_add_share(const char *session_id_hex, const char *sig_share_hex, uint16_t share_index,
                     rpc_response_t *resp) {
    uint8_t session_id[SESSION_ID_LEN];
    if (parse_session_id(session_id_hex, session_id, resp) != 0) {
        return;
    }

    signing_session_t *s = find_session(session_id);
    if (!s) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Session not found");
        return;
    }

    if (s->session.state != SESSION_AWAITING_SHARES) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Session not awaiting shares");
        return;
    }

    uint8_t share_bytes[SIG_SHARE_LEN];
    size_t share_len;
    if (frost_parse_sig_share(sig_share_hex, share_bytes, &share_len) != 0) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_PARAMS, "Invalid signature share");
        return;
    }

    int idx = s->session.sig_share_count;
    if (idx >= MAX_PARTICIPANTS) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Too many signature shares");
        return;
    }

    memcpy(s->session.sig_shares[idx], share_bytes, share_len);
    s->session.sig_share_lens[idx] = share_len;
    s->session.sig_share_indices[idx] = share_index;
    s->session.sig_share_count++;

    char result[64];
    snprintf(result, sizeof(result), "{\"shares_collected\":%d}", s->session.sig_share_count);
    protocol_success(resp, resp->id, result);
}

void frost_aggregate_shares(const char *session_id_hex, rpc_response_t *resp) {
    uint8_t session_id[SESSION_ID_LEN];
    if (parse_session_id(session_id_hex, session_id, resp) != 0) {
        return;
    }

    signing_session_t *s = find_session(session_id);
    if (!s) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Session not found");
        return;
    }

    if (s->session.sig_share_count < s->session.threshold) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Not enough shares");
        return;
    }

    frost_aggregate_result_t agg_result;
    if (frost_aggregate_pure(&s->frost_state, &s->session, s->session.message,
                             s->session.message_len, &agg_result) != 0) {
        free_session(s);
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Aggregation failed");
        return;
    }

    char sig_hex[SIGNATURE_LEN * 2 + 1];
    bytes_to_hex(agg_result.signature, SIGNATURE_LEN, sig_hex, sizeof(sig_hex));

    char result[192];
    snprintf(result, sizeof(result), "{\"signature\":\"%s\"}", sig_hex);
    protocol_success(resp, resp->id, result);

    s->session.state = SESSION_COMPLETE;
    memcpy(s->session.final_signature, agg_result.signature, SIGNATURE_LEN);
    s->session.has_signature = true;

    FROST_LOGI(TAG, "Aggregated signature for session %.16s...", session_id_hex);

    free_session(s);
}

void frost_export_share(const char *group, rpc_response_t *resp) {
    const share_store_t *store = share_store_default();
    frost_state_t state;

    if (share_store_load_frost_state(store, group, &state) != 0) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SHARE, "Share not found");
        return;
    }

    char pubkey_hex[67];
    bytes_to_hex(state.group_pubkey, sizeof(state.group_pubkey), pubkey_hex, sizeof(pubkey_hex));

    group_metadata_t metadata;
    bool has_metadata = storage_load_metadata(group, &metadata) == 0;

    char result[1024];
    int len;

    if (has_metadata && metadata.has_coordinator) {
        char coord_hex[65];
        bytes_to_hex(metadata.coordinator_npub, STORAGE_PUBKEY_LEN, coord_hex, sizeof(coord_hex));
        len = snprintf(result, sizeof(result),
                       "{\"pubkey\":\"%s\",\"index\":%d,\"threshold\":%d,\"participants\":%d,"
                       "\"created_at\":%llu,\"coordinator\":\"%s\"}",
                       pubkey_hex, state.share_index, state.threshold, state.participants,
                       (unsigned long long)metadata.created_at, coord_hex);
    } else if (has_metadata) {
        len = snprintf(result, sizeof(result),
                       "{\"pubkey\":\"%s\",\"index\":%d,\"threshold\":%d,\"participants\":%d,"
                       "\"created_at\":%llu}",
                       pubkey_hex, state.share_index, state.threshold, state.participants,
                       (unsigned long long)metadata.created_at);
    } else {
        len = snprintf(result, sizeof(result),
                       "{\"pubkey\":\"%s\",\"index\":%d,\"threshold\":%d,\"participants\":%d}",
                       pubkey_hex, state.share_index, state.threshold, state.participants);
    }

    if (len < 0 || (size_t)len >= sizeof(result)) {
        frost_free(&state);
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_INTERNAL, "Buffer overflow");
        return;
    }

    protocol_success(resp, resp->id, result);
    frost_free(&state);
}

void frost_session_resume(const char *session_id_hex, rpc_response_t *resp) {
    uint8_t session_id[SESSION_ID_LEN];
    if (parse_session_id(session_id_hex, session_id, resp) != 0) {
        return;
    }

    if (find_session(session_id) != NULL) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Session already active");
        return;
    }

    if (is_session_consumed(session_id)) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Session already used");
        return;
    }

    session_t restored_session;
    uint8_t nonce_backup[SIGNATURE_LEN];
    char restored_group[STORAGE_GROUP_LEN + 1];
    if (session_checkpoint_load(session_id, &restored_session, nonce_backup, restored_group,
                                sizeof(restored_group)) != 0) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "No checkpoint found");
        return;
    }

    if (restored_group[0] == '\0') {
        session_destroy(&restored_session);
        secure_memzero(nonce_backup, sizeof(nonce_backup));
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Checkpoint missing group");
        return;
    }

    uint32_t now = get_time_ms();
    uint32_t created = restored_session.created_at;
    uint32_t elapsed = (now >= created) ? (now - created) : (UINT32_MAX - created + now + 1);
    uint32_t extended_timeout = SESSION_TIMEOUT_MS * 10;

    if (elapsed > extended_timeout) {
        session_checkpoint_clear(session_id);
        session_destroy(&restored_session);
        secure_memzero(nonce_backup, sizeof(nonce_backup));
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Checkpoint expired");
        return;
    }

    signing_session_t *s = alloc_session(session_id);
    if (!s) {
        session_destroy(&restored_session);
        secure_memzero(nonce_backup, sizeof(nonce_backup));
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "No free session slots");
        return;
    }

    const share_store_t *store = share_store_default();
    if (share_store_load_frost_state(store, restored_group, &s->frost_state) != 0) {
        free_session(s);
        session_destroy(&restored_session);
        secure_memzero(nonce_backup, sizeof(nonce_backup));
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SHARE, "Share not found for group");
        return;
    }

    strncpy(s->group, restored_group, STORAGE_GROUP_LEN);
    s->group[STORAGE_GROUP_LEN] = '\0';

    bool has_policy = false;
    uint8_t policy_hash[32];
    secresult_t policy_ret = capture_policy_snapshot_secure(&has_policy, policy_hash);
    if (!SECRESULT_IS_TRUE(policy_ret)) {
        free_session(s);
        session_destroy(&restored_session);
        secure_memzero(nonce_backup, sizeof(nonce_backup));
        secure_memzero(policy_hash, sizeof(policy_hash));
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Policy verification failed");
        return;
    }
    s->has_policy = has_policy;
    memcpy(s->policy_hash, policy_hash, 32);
    secure_memzero(policy_hash, sizeof(policy_hash));

    int clear_ret = session_checkpoint_clear(session_id);
    if (clear_ret != 0) {
        free_session(s);
        secure_memzero(&restored_session, sizeof(restored_session));
        secure_memzero(nonce_backup, sizeof(nonce_backup));
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Failed to clear checkpoint");
        return;
    }

    memcpy(&s->session, &restored_session, sizeof(session_t));
    memcpy(s->session.our_nonce, nonce_backup, SIGNATURE_LEN);
    secure_memzero(&restored_session, sizeof(restored_session));
    secure_memzero(nonce_backup, sizeof(nonce_backup));

    s->session.created_at = now;

    char result[256];
    snprintf(result, sizeof(result),
             "{\"resumed\":true,\"state\":%d,\"commitment_count\":%d,\"sig_share_count\":%d}",
             (int)s->session.state, s->session.commitment_count, s->session.sig_share_count);
    protocol_success(resp, resp->id, result);

    FROST_LOGI(TAG, "Resumed session %.16s...", session_id_hex);
}

void frost_session_list(rpc_response_t *resp) {
    uint8_t session_ids[STORAGE_MAX_SESSION_CHECKPOINTS][SESSION_ID_LEN];
    int count = session_checkpoint_list(session_ids, STORAGE_MAX_SESSION_CHECKPOINTS);

    if (count < 0) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_INTERNAL, "Failed to list checkpoints");
        return;
    }

    char result[512];
    size_t offset = 0;
    int ret = snprintf(result, sizeof(result), "{\"checkpoints\":[");
    if (ret < 0 || (size_t)ret >= sizeof(result)) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_INTERNAL, "Buffer overflow");
        return;
    }
    offset = (size_t)ret;

    for (int i = 0; i < count; i++) {
        char id_hex[SESSION_ID_HEX_LEN + 1];
        bytes_to_hex(session_ids[i], SESSION_ID_LEN, id_hex, sizeof(id_hex));
        ret = snprintf(result + offset, sizeof(result) - offset, "%s\"%s\"", (i > 0) ? "," : "",
                       id_hex);
        if (ret < 0 || (size_t)ret >= sizeof(result) - offset) {
            PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_INTERNAL, "Buffer overflow");
            return;
        }
        offset += (size_t)ret;
    }

    ret = snprintf(result + offset, sizeof(result) - offset, "],\"count\":%d}", count);
    if (ret < 0 || (size_t)ret >= sizeof(result) - offset) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_INTERNAL, "Buffer overflow");
        return;
    }

    protocol_success(resp, resp->id, result);
}
