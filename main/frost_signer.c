#include "frost_signer.h"
#include "storage.h"
#include "frost.h"
#include "session.h"
#include "policy.h"
#include "hex_utils.h"
#include "esp_log.h"
#include <string.h>
#include <stdio.h>

#ifdef ESP_PLATFORM
#include "esp_timer.h"
#include "esp_random.h"
static uint32_t get_time_ms(void) { return (uint32_t)(esp_timer_get_time() / 1000); }
static void generate_random_bytes(uint8_t *buf, size_t len) { esp_fill_random(buf, len); }
#else
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
static uint32_t get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}
static void generate_random_bytes(uint8_t *buf, size_t len) {
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
    }
#ifdef FROST_ALLOW_WEAK_RNG
    fprintf(stderr, "WARNING: Using weak RNG fallback (test mode only)\n");
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(rand() & 0xff);
    }
#else
    fprintf(stderr, "FATAL: /dev/urandom unavailable and secure RNG required\n");
    abort();
#endif
}
#endif

#ifdef ESP_PLATFORM
#include "crypto_asm.h"
#define secure_zero(buf, len) secure_memzero(buf, len)
#else
static void secure_zero(void *buf, size_t len) {
    volatile uint8_t *p = buf;
    while (len--) *p++ = 0;
}
#endif

#define TAG "frost_signer"
#define MAX_SESSIONS 4

#ifdef FROST_SIGNER_QUIET_LOGS
#define FROST_LOGI(tag, ...) do {} while(0)
#define FROST_LOGW(tag, ...) do {} while(0)
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
        if (sessions[i].active && ct_compare(sessions[i].session_id, session_id, SESSION_ID_LEN) == 0) {
            return &sessions[i];
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

static int capture_policy_snapshot(bool *has_policy, uint8_t policy_hash[32]) {
    *has_policy = false;
    memset(policy_hash, 0, 32);

    if (!policy_has_bundle()) {
        return 0;
    }

    policy_bundle_t bundle;
    int ret = policy_load_bundle(&bundle);
    if (ret != 0) {
        secure_zero(&bundle, sizeof(bundle));
        return ret;
    }

    ret = policy_verify_signature(&bundle);
    if (ret != 0) {
        secure_zero(&bundle, sizeof(bundle));
        return ret;
    }

    *has_policy = true;
    memcpy(policy_hash, bundle.policy_hash, 32);
    secure_zero(&bundle, sizeof(bundle));
    return 0;
}

static int verify_policy_unchanged(bool has_policy, const uint8_t policy_hash[32]) {
    bool current_has_policy = false;
    uint8_t current_hash[32];

    int ret = capture_policy_snapshot(&current_has_policy, current_hash);
    if (ret != 0) {
        secure_zero(current_hash, sizeof(current_hash));
        return ret;
    }

    if (has_policy != current_has_policy) {
        secure_zero(current_hash, sizeof(current_hash));
        return -1;
    }

    if (has_policy && ct_compare(policy_hash, current_hash, 32) != 0) {
        secure_zero(current_hash, sizeof(current_hash));
        return -1;
    }

    secure_zero(current_hash, sizeof(current_hash));
    return 0;
}

static void free_session(signing_session_t *s) {
    if (s) {
        frost_free(&s->frost_state);
        session_destroy(&s->session);
        secure_zero(s, sizeof(signing_session_t));
    }
}

static const uint8_t SESSION_ID_ALL_ONES[SESSION_ID_LEN] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static bool is_session_id_valid(const uint8_t *session_id) {
    bool is_zero = ct_is_zero(session_id, SESSION_ID_LEN) == 1;
    bool is_all_ones = ct_compare(session_id, SESSION_ID_ALL_ONES, SESSION_ID_LEN) == 0;
    return !is_zero && !is_all_ones;
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
    if (!is_session_id_valid(out)) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_PARAMS, "Invalid session_id value");
        return -1;
    }
    return 0;
}

static int load_frost_state(frost_state_t *state, const char *group) {
    char share_hex[STORAGE_SHARE_LEN * 2 + 1];
    if (storage_load_share(group, share_hex, sizeof(share_hex)) != 0) {
        return -1;
    }
    uint8_t share_bytes[STORAGE_SHARE_LEN];
    int share_len = hex_to_bytes(share_hex, share_bytes, sizeof(share_bytes));
    if (share_len < 0) {
        secure_zero(share_hex, sizeof(share_hex));
        secure_zero(share_bytes, sizeof(share_bytes));
        return -1;
    }
    int ret = frost_init(state, share_bytes, (size_t)share_len);
    secure_zero(share_hex, sizeof(share_hex));
    secure_zero(share_bytes, sizeof(share_bytes));
    return ret;
}

int frost_signer_init(void) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        sessions[i].active = false;
    }
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
    frost_state_t state;
    if (load_frost_state(&state, group) != 0) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SHARE, "Share not found");
        return;
    }

    char pubkey_hex[67];
    bytes_to_hex(state.group_pubkey, sizeof(state.group_pubkey), pubkey_hex, sizeof(pubkey_hex));

    char result[128];
    snprintf(result, sizeof(result), "{\"pubkey\":\"%s\",\"index\":%d}",
             pubkey_hex, state.share_index);
    protocol_success(resp, resp->id, result);

    frost_free(&state);
}

void frost_get_share_info(const char *group, rpc_response_t *resp) {
    frost_state_t state;
    if (load_frost_state(&state, group) != 0) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SHARE, "Share not found");
        return;
    }

    char pubkey_hex[67];
    bytes_to_hex(state.group_pubkey, sizeof(state.group_pubkey), pubkey_hex, sizeof(pubkey_hex));

    char result[192];
    snprintf(result, sizeof(result),
             "{\"pubkey\":\"%s\",\"index\":%d,\"threshold\":%d,\"participants\":%d}",
             pubkey_hex, state.share_index, state.threshold, state.participants);
    protocol_success(resp, resp->id, result);

    frost_free(&state);
}

void frost_commit(const char *group, const char *session_id_hex, const char *message_hex, rpc_response_t *resp) {
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

    bool has_policy = false;
    uint8_t policy_hash[32];
    int policy_ret = capture_policy_snapshot(&has_policy, policy_hash);
    if (policy_ret != 0) {
        secure_zero(policy_hash, sizeof(policy_hash));
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Policy bundle verification failed");
        return;
    }

    signing_session_t *s = alloc_session(session_id);
    if (!s) {
        secure_zero(policy_hash, sizeof(policy_hash));
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "No free session slots");
        return;
    }

    s->has_policy = has_policy;
    memcpy(s->policy_hash, policy_hash, 32);
    secure_zero(policy_hash, sizeof(policy_hash));

    if (load_frost_state(&s->frost_state, group) != 0) {
        free_session(s);
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SHARE, "Share not found");
        return;
    }

    strncpy(s->group, group, STORAGE_GROUP_LEN);
    s->group[STORAGE_GROUP_LEN] = '\0';

    sign_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.session_id, session_id, SESSION_ID_LEN);
    memcpy(req.message, message, SESSION_ID_LEN);
    req.message_len = SESSION_ID_LEN;
    req.participants[0] = s->frost_state.share_index;
    req.participant_count = 1;

    uint16_t threshold = s->frost_state.threshold > 0 ? s->frost_state.threshold : 2;
    session_init(&s->session, &req, threshold);

    uint8_t commitment[COMMITMENT_LEN];
    size_t commitment_len = 0;
    if (frost_create_commitment(&s->frost_state, &s->session, commitment, &commitment_len) != 0) {
        free_session(s);
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Failed to create commitment");
        return;
    }

    char commitment_hex[COMMITMENT_HEX_LEN + 1];
    bytes_to_hex(commitment, commitment_len, commitment_hex, sizeof(commitment_hex));

    char result[512];
    snprintf(result, sizeof(result),
             "{\"commitment\":\"%s\",\"index\":%d}",
             commitment_hex, s->frost_state.share_index);
    protocol_success(resp, resp->id, result);

    FROST_LOGI(TAG, "Created commitment for session %.16s...", session_id_hex);
}

void frost_sign(const char *group, const char *session_id_hex, const char *commitments_hex, rpc_response_t *resp) {
    uint8_t session_id[SESSION_ID_LEN];
    if (parse_session_id(session_id_hex, session_id, resp) != 0) {
        return;
    }

    signing_session_t *s = find_session(session_id);
    if (!s) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Session not found");
        return;
    }

    if (strcmp(s->group, group) != 0) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_PARAMS, "Group mismatch");
        return;
    }

    if (verify_policy_unchanged(s->has_policy, s->policy_hash) != 0) {
        free_session(s);
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Policy changed during session");
        return;
    }

    size_t commits_hex_len = strlen(commitments_hex);
    size_t max_commits_hex = (size_t)(MAX_PARTICIPANTS - 1) * COMMITMENT_HEX_LEN;
    if (commits_hex_len > 0 && commits_hex_len <= max_commits_hex && commits_hex_len % COMMITMENT_HEX_LEN == 0) {
        int num_commits = (int)(commits_hex_len / COMMITMENT_HEX_LEN);
        for (int i = 0; i < num_commits; i++) {
            uint8_t commit_bytes[COMMITMENT_LEN];
            char commit_chunk[COMMITMENT_HEX_LEN + 1];
            memcpy(commit_chunk, commitments_hex + i * COMMITMENT_HEX_LEN, COMMITMENT_HEX_LEN);
            commit_chunk[COMMITMENT_HEX_LEN] = '\0';
            if (hex_to_bytes(commit_chunk, commit_bytes, COMMITMENT_LEN) == COMMITMENT_LEN) {
                int idx = s->session.commitment_count;
                if (idx >= MAX_PARTICIPANTS) {
                    break;
                }
                uint16_t commit_index = (uint16_t)commit_bytes[0] |
                                        ((uint16_t)commit_bytes[1] << 8);
                memcpy(s->session.commitments[idx], commit_bytes, COMMITMENT_LEN);
                s->session.commitment_lens[idx] = COMMITMENT_LEN;
                s->session.commitment_indices[idx] = commit_index;
                s->session.commitment_count++;
            }
        }
    }
    uint8_t total_participants = s->session.commitment_count + 1;
    if (total_participants < s->frost_state.threshold) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Not enough commitments for threshold");
        return;
    }
    s->session.participant_count = total_participants;
    s->session.state = SESSION_AWAITING_SHARES;

    uint8_t sig_share[SIG_SHARE_LEN];
    size_t sig_share_len = 0;
    if (frost_sign_share(&s->frost_state, &s->session, s->session.message, s->session.message_len,
                         sig_share, &sig_share_len) != 0) {
        free_session(s);
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Signing failed");
        return;
    }

    int share_idx = s->session.sig_share_count;
    if (share_idx < MAX_PARTICIPANTS) {
        memcpy(s->session.sig_shares[share_idx], sig_share, sig_share_len);
        s->session.sig_share_lens[share_idx] = sig_share_len;
        s->session.sig_share_indices[share_idx] = s->frost_state.share_index;
        s->session.sig_share_count++;
    }

    char sig_share_hex[73];
    bytes_to_hex(sig_share, sig_share_len, sig_share_hex, sizeof(sig_share_hex));

    char result[192];
    snprintf(result, sizeof(result),
             "{\"signature_share\":\"%s\",\"index\":%d}",
             sig_share_hex, s->frost_state.share_index);
    protocol_success(resp, resp->id, result);

    FROST_LOGI(TAG, "Created signature share for session %.16s...", session_id_hex);
}

void frost_signer_cleanup_stale(void) {
    uint32_t now = get_time_ms();
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].active) {
            uint32_t created = sessions[i].session.created_at;
            uint32_t elapsed = (now >= created) ? (now - created) : (UINT32_MAX - created + now + 1);
            if (elapsed > SESSION_TIMEOUT_MS) {
                FROST_LOGW(TAG, "Cleaning up stale session");
                free_session(&sessions[i]);
            }
        }
    }
}

void frost_add_share(const char *session_id_hex, const char *sig_share_hex, uint16_t share_index, rpc_response_t *resp) {
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

    size_t hex_len = strlen(sig_share_hex);
    if (hex_len == 0 || hex_len > 72) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_PARAMS, "Invalid signature share length");
        return;
    }

    uint8_t share_bytes[SIG_SHARE_LEN];
    int share_len = hex_to_bytes(sig_share_hex, share_bytes, sizeof(share_bytes));
    if (share_len < 0) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_PARAMS, "Invalid signature share hex");
        return;
    }

    int idx = s->session.sig_share_count;
    if (idx >= MAX_PARTICIPANTS) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Too many signature shares");
        return;
    }

    memcpy(s->session.sig_shares[idx], share_bytes, (size_t)share_len);
    s->session.sig_share_lens[idx] = (size_t)share_len;
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

    uint8_t signature[SIGNATURE_LEN];
    if (frost_aggregate(&s->frost_state, &s->session, s->session.message, s->session.message_len, signature) != 0) {
        free_session(s);
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Aggregation failed");
        return;
    }

    char sig_hex[SIGNATURE_LEN * 2 + 1];
    bytes_to_hex(signature, SIGNATURE_LEN, sig_hex, sizeof(sig_hex));

    char result[192];
    snprintf(result, sizeof(result), "{\"signature\":\"%s\"}", sig_hex);
    protocol_success(resp, resp->id, result);

    s->session.state = SESSION_COMPLETE;
    memcpy(s->session.final_signature, signature, SIGNATURE_LEN);
    s->session.has_signature = true;

    FROST_LOGI(TAG, "Aggregated signature for session %.16s...", session_id_hex);

    free_session(s);
}
