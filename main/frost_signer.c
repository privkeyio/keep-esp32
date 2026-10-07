// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include "frost_signer.h"
#include "frost_signer_storage.h"
#include "frost_tr.h"
#include "frost_tr_task.h"
#include "storage.h"
#include "policy.h"
#include "sign_approval.h"
#include "hex_utils.h"
#include "random_utils.h"
#include "crypto_asm.h"
#include "secresult.h"
#include "anti_glitch.h"
#include "log_compat.h"
#include <mbedtls/sha256.h>
#include <string.h>

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

static uint32_t elapsed_ms(uint32_t start, uint32_t now) {
    return (now >= start) ? (now - start) : (UINT32_MAX - start + now + 1);
}

#define TAG                        "frost_signer"
#define MAX_SESSIONS               4
#define CONSUMED_SESSION_RING_SIZE 64
#define SESSION_ID_LEN             32
#define SESSION_ID_HEX_LEN         64
#define SESSION_TIMEOUT_MS         30000

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
#define FROST_LOGI(tag, ...) ESP_LOGI(tag, __VA_ARGS__)
#define FROST_LOGW(tag, ...) ESP_LOGW(tag, __VA_ARGS__)
#endif

/* A signing round lives only in RAM. The nonces are never written to flash: after a reset
 * the host starts the round again with a fresh commit, so no stored nonce can be rolled
 * back and used for a second message. */
typedef struct {
    bool active;
    bool released;
    uint8_t session_id[SESSION_ID_LEN];
    char group[STORAGE_GROUP_LEN + 1];
    uint8_t message[FTR_MESSAGE_LEN];
    uint8_t nonces[FTR_NONCES_LEN];
    uint16_t index;
    uint8_t verifying_share[33];
    bool has_policy;
    uint8_t policy_hash[32];
    uint32_t created_at;
    uint8_t package_hash[32];
    uint8_t share[FTR_SIGNATURE_SHARE_LEN];
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

/* A free slot, or else the oldest session whose share was already released: its nonces
 * are gone and only the answer to a retry is lost. Rounds still waiting to sign are never
 * displaced. */
static signing_session_t *alloc_session(const uint8_t *session_id) {
    signing_session_t *slot = NULL;
    uint32_t now = get_time_ms(), oldest = 0;
    for (int i = 0; i < MAX_SESSIONS && (slot == NULL || slot->active); i++) {
        if (!sessions[i].active) {
            slot = &sessions[i];
        } else if (sessions[i].released && elapsed_ms(sessions[i].created_at, now) >= oldest) {
            oldest = elapsed_ms(sessions[i].created_at, now);
            slot = &sessions[i];
        }
    }
    if (slot != NULL) {
        secure_memzero(slot, sizeof(signing_session_t));
        slot->active = true;
        memcpy(slot->session_id, session_id, SESSION_ID_LEN);
    }
    return slot;
}

static void free_session(signing_session_t *s) {
    if (s) {
        secure_memzero(s, sizeof(signing_session_t));
    }
}

typedef struct {
    const uint8_t *kp;
    size_t kp_len;
    ftr_key_info_t *info;
} import_job_t;

static int import_job(void *arg) {
    import_job_t *j = arg;
    return ftr_key_package_import(j->kp, j->kp_len, j->info);
}

typedef struct {
    const uint8_t *legacy;
    size_t legacy_len;
    uint8_t *kp;
    size_t *kp_len;
    uint16_t *participants;
} legacy_job_t;

static int legacy_job(void *arg) {
    legacy_job_t *j = arg;
    return ftr_key_package_from_legacy(j->legacy, j->legacy_len, j->kp, j->kp_len, j->participants);
}

typedef struct {
    const uint8_t *kp;
    size_t kp_len;
    uint8_t *nonces;
    uint8_t *commitments;
} commit_job_t;

static int commit_job(void *arg) {
    commit_job_t *j = arg;
    return ftr_commit(j->kp, j->kp_len, j->nonces, j->commitments);
}

typedef struct {
    const uint8_t *kp;
    size_t kp_len;
    uint8_t *nonces;
    const uint8_t *package;
    size_t package_len;
    const uint8_t *message;
    uint8_t *share;
} sign_job_t;

static int sign_job(void *arg) {
    sign_job_t *j = arg;
    return ftr_sign(j->kp, j->kp_len, j->nonces, j->package, j->package_len, j->message, j->share);
}

#define LOAD_KEY_INVALID -10

/* Loads and validates the stored key package for `group`. On success the caller owns
 * `key` and must wipe it. */
static int load_key_checked(const char *group, share_key_t *key, ftr_key_info_t *info) {
    int ret = share_key_load(group, key);
    if (ret != SHARE_KEY_OK) {
        return ret;
    }
    import_job_t job = {.kp = key->key_package, .kp_len = key->key_package_len, .info = info};
    if (ftr_task_run(import_job, &job) != FTR_OK || info->index > key->participants ||
        info->min_signers > key->participants) {
        secure_memzero(key, sizeof(*key));
        return LOAD_KEY_INVALID;
    }
    return SHARE_KEY_OK;
}

static int load_key(const char *group, share_key_t *key, ftr_key_info_t *info,
                    rpc_response_t *resp) {
    int ret = load_key_checked(group, key, info);
    if (ret == SHARE_KEY_ERR_LEGACY) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SHARE,
                       "Share predates protocol 2 and was not migrated; unlock, or delete and "
                       "import it again");
    } else if (ret == LOAD_KEY_INVALID) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SHARE, "Stored share is invalid");
    } else if (ret != SHARE_KEY_OK) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SHARE, "Share not found");
    }
    return ret == SHARE_KEY_OK ? 0 : -1;
}

int frost_signer_export_meta(const char *group, share_export_meta_t *meta) {
    share_key_t key;
    ftr_key_info_t info;
    if (!group || !meta || load_key_checked(group, &key, &info) != SHARE_KEY_OK) {
        return -1;
    }
    meta->threshold = info.min_signers;
    meta->participants = key.participants;
    meta->share_index = info.index;
    memcpy(meta->group_pubkey, info.group_key, sizeof(meta->group_pubkey));
    secure_memzero(&key, sizeof(key));
    return 0;
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

static bool is_session_id_valid(const uint8_t *session_id) {
    uint8_t all_or = 0;
    uint8_t all_and = 0xFF;
    for (int i = 0; i < SESSION_ID_LEN; i++) {
        all_or |= session_id[i];
        all_and &= session_id[i];
    }
    return all_or != 0 && all_and != 0xFF;
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

void frost_import_share(const char *group, const char *key_package_hex, uint16_t participants,
                        rpc_response_t *resp) {
    KEEP_ASSERT_VOID(group != NULL);
    KEEP_ASSERT_VOID(key_package_hex != NULL);
    KEEP_ASSERT_VOID(resp != NULL);

    if (participants < 2 || participants > FTR_MAX_SIGNERS) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_PARAMS, "participants must be 2 to 16");
        return;
    }

    share_key_t key = {.participants = participants};
    int len = hex_to_bytes(key_package_hex, key.key_package, sizeof(key.key_package));
    if (len <= 0) {
        secure_memzero(&key, sizeof(key));
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_PARAMS, "Invalid key_package hex");
        return;
    }
    key.key_package_len = (size_t)len;

    ftr_key_info_t info;
    import_job_t job = {.kp = key.key_package, .kp_len = key.key_package_len, .info = &info};
    int ret = ftr_task_run(import_job, &job);
    if (ret != FTR_OK) {
        secure_memzero(&key, sizeof(key));
        char msg[64];
        snprintf(msg, sizeof(msg), "Invalid key_package (%d)", ret);
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_PARAMS, msg);
        return;
    }
    if (info.index > participants || info.min_signers > participants) {
        secure_memzero(&key, sizeof(key));
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_PARAMS,
                       "key_package does not fit the participant count");
        return;
    }

    ret = share_key_save(group, &key);
    secure_memzero(&key, sizeof(key));
    switch (ret) {
    case STORAGE_OK:
        break;
    case STORAGE_ERR_CRYPTO_NOT_INIT:
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_STORAGE, "Storage crypto not initialized");
        return;
    case STORAGE_ERR_INVALID_GROUP:
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_PARAMS, "Invalid group name");
        return;
    case STORAGE_ERR_NO_SLOT:
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_STORAGE, "No free storage slot");
        return;
    default:
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_STORAGE, "Storage error");
        return;
    }

    char group_key_hex[67], verifying_share_hex[67];
    bytes_to_hex(info.group_key, sizeof(info.group_key), group_key_hex, sizeof(group_key_hex));
    bytes_to_hex(info.verifying_share, sizeof(info.verifying_share), verifying_share_hex,
                 sizeof(verifying_share_hex));
    char result[256];
    snprintf(result, sizeof(result),
             "{\"ok\":true,\"index\":%u,\"threshold\":%u,\"participants\":%u,\"pubkey\":\"%s\","
             "\"verifying_share\":\"%s\"}",
             info.index, info.min_signers, participants, group_key_hex, verifying_share_hex);
    protocol_success(resp, resp->id, result);
}

int frost_signer_migrate_shares(int *migrated, int *unmigratable) {
    *migrated = 0;
    *unmigratable = 0;
    char groups[STORAGE_MAX_SHARES][STORAGE_GROUP_LEN + 1];
    int count = storage_list_shares(groups, STORAGE_MAX_SHARES);
    if (count < 0) {
        return count;
    }
    int status = 0;
    for (int i = 0; i < count; i++) {
        uint8_t raw[STORAGE_SHARE_LEN];
        size_t raw_len = 0;
        share_key_t probe;
        if (share_raw_load(groups[i], raw, &raw_len) != SHARE_KEY_OK ||
            share_payload_decode(raw, raw_len, &probe) != SHARE_KEY_ERR_LEGACY) {
            secure_memzero(raw, sizeof(raw));
            secure_memzero(&probe, sizeof(probe));
            continue;
        }
        share_key_t key = {0};
        uint8_t kp[FTR_KEY_PACKAGE_MAX];
        legacy_job_t job = {.legacy = raw,
                            .legacy_len = raw_len,
                            .kp = kp,
                            .kp_len = &key.key_package_len,
                            .participants = &key.participants};
        int ret = ftr_task_run(legacy_job, &job);
        secure_memzero(raw, sizeof(raw));
        if (ret == FTR_OK && key.key_package_len <= sizeof(key.key_package)) {
            memcpy(key.key_package, kp, key.key_package_len);
            ret = share_key_save(groups[i], &key);
            if (ret == STORAGE_OK) {
                (*migrated)++;
                FROST_LOGI(TAG, "Migrated share for group %s to protocol 2", groups[i]);
            } else {
                status = ret;
                ESP_LOGE(TAG, "Could not store migrated share for group %s: %d", groups[i], ret);
            }
        } else {
            /* Left as it is: only an explicit delete_share removes a share. */
            (*unmigratable)++;
            FROST_LOGW(TAG, "Share for group %s cannot be rebuilt as a key package (%d)", groups[i],
                       ret);
        }
        secure_memzero(kp, sizeof(kp));
        secure_memzero(&key, sizeof(key));
    }
    return status;
}

static void respond_key_info(const char *group, bool full, rpc_response_t *resp) {
    share_key_t key;
    ftr_key_info_t info;
    if (load_key(group, &key, &info, resp) != 0) {
        return;
    }
    uint16_t participants = key.participants;
    secure_memzero(&key, sizeof(key));

    char group_key_hex[67], verifying_share_hex[67];
    bytes_to_hex(info.group_key, sizeof(info.group_key), group_key_hex, sizeof(group_key_hex));
    bytes_to_hex(info.verifying_share, sizeof(info.verifying_share), verifying_share_hex,
                 sizeof(verifying_share_hex));
    char result[256];
    if (full) {
        snprintf(result, sizeof(result),
                 "{\"pubkey\":\"%s\",\"index\":%u,\"threshold\":%u,\"participants\":%u,"
                 "\"verifying_share\":\"%s\"}",
                 group_key_hex, info.index, info.min_signers, participants, verifying_share_hex);
    } else {
        snprintf(result, sizeof(result), "{\"pubkey\":\"%s\",\"index\":%u}", group_key_hex,
                 info.index);
    }
    protocol_success(resp, resp->id, result);
}

void frost_get_pubkey(const char *group, rpc_response_t *resp) {
    respond_key_info(group, false, resp);
}

void frost_get_share_info(const char *group, rpc_response_t *resp) {
    respond_key_info(group, true, resp);
}

static int frost_commit_validate(const char *session_id_hex, const char *message_hex,
                                 uint8_t *session_id, uint8_t *message, rpc_response_t *resp) {
    secresult_t rng_health = rng_is_healthy_secure();
    rng_health = ag_verify_condition_secure(rng_health);
    if (!SECRESULT_IS_TRUE(rng_health)) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_INTERNAL,
                       "RNG health check failed, device in safe mode");
        return -1;
    }

    if (parse_session_id(session_id_hex, session_id, resp) != 0) {
        return -1;
    }

    if (strlen(message_hex) != FTR_MESSAGE_LEN * 2) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_PARAMS, "message must be 32 bytes");
        return -1;
    }

    if (hex_to_bytes(message_hex, message, FTR_MESSAGE_LEN) != FTR_MESSAGE_LEN) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_PARAMS, "Invalid message hex");
        return -1;
    }

    if (is_session_consumed(session_id)) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Session ID already used");
        return -1;
    }

    if (find_session(session_id) != NULL) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Session ID already active");
        return -1;
    }

    return 0;
}

static void frost_commit_generate(const char *group, const char *session_id_hex,
                                  const uint8_t *session_id, const uint8_t *message,
                                  rpc_response_t *resp) {
    ag_random_delay_us(100, 1000);

    bool has_policy = false;
    uint8_t policy_hash[32];
    secresult_t policy_ret = capture_policy_snapshot_secure(&has_policy, policy_hash);
    policy_ret = ag_verify_condition_secure(policy_ret);
    if (!SECRESULT_IS_TRUE(policy_ret)) {
        secure_memzero(policy_hash, sizeof(policy_hash));
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Policy bundle verification failed");
        return;
    }

    secresult_t raw_ok = ag_verify_condition_secure(policy_allows_raw_secure());

    share_key_t key;
    ftr_key_info_t info;
    if (load_key(group, &key, &info, resp) != 0) {
        secure_memzero(policy_hash, sizeof(policy_hash));
        return;
    }

    signing_session_t *s = alloc_session(session_id);
    if (!s) {
        secure_memzero(&key, sizeof(key));
        secure_memzero(policy_hash, sizeof(policy_hash));
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "No free session slots");
        return;
    }

    s->has_policy = has_policy;
    memcpy(s->policy_hash, policy_hash, 32);
    secure_memzero(policy_hash, sizeof(policy_hash));
    strncpy(s->group, group, STORAGE_GROUP_LEN);
    s->group[STORAGE_GROUP_LEN] = '\0';
    memcpy(s->message, message, FTR_MESSAGE_LEN);
    s->index = info.index;
    memcpy(s->verifying_share, info.verifying_share, sizeof(s->verifying_share));
    s->created_at = get_time_ms();

    /* Consumed only now, so a missing share or a full session table does not use up a
     * valid approval. */
    if (!SECRESULT_IS_TRUE(raw_ok)) {
        secresult_t approved = ag_verify_condition_secure(
            sign_approval_consume_secure(message, sign_approval_now_ms()));
        if (!SECRESULT_IS_TRUE(approved)) {
            secure_memzero(&key, sizeof(key));
            free_session(s);
            PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN,
                           "Message not approved by bitcoin_sign under the installed policy");
            return;
        }
    }

    uint8_t commitments[FTR_COMMITMENTS_LEN];
    commit_job_t job = {.kp = key.key_package,
                        .kp_len = key.key_package_len,
                        .nonces = s->nonces,
                        .commitments = commitments};
    int ret = ftr_task_run(commit_job, &job);
    secure_memzero(&key, sizeof(key));
    if (ret != FTR_OK) {
        free_session(s);
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Failed to create commitment");
        return;
    }

    char commitments_hex[FTR_COMMITMENTS_LEN * 2 + 1];
    bytes_to_hex(commitments, sizeof(commitments), commitments_hex, sizeof(commitments_hex));
    char result[256];
    snprintf(result, sizeof(result), "{\"commitment\":\"%s\",\"index\":%u}", commitments_hex,
             s->index);
    protocol_success(resp, resp->id, result);

    FROST_LOGI(TAG, "Created commitment for session %.16s...", session_id_hex);
}

void frost_commit(const char *group, const char *session_id_hex, const char *message_hex,
                  rpc_response_t *resp) {
    KEEP_ASSERT_VOID(group != NULL);
    KEEP_ASSERT_VOID(session_id_hex != NULL);
    KEEP_ASSERT_VOID(message_hex != NULL);
    KEEP_ASSERT_VOID(resp != NULL);
    KEEP_ASSERT_VOID(group[0] != '\0');

    uint8_t session_id[SESSION_ID_LEN];
    uint8_t message[FTR_MESSAGE_LEN];

    if (frost_commit_validate(session_id_hex, message_hex, session_id, message, resp) != 0) {
        return;
    }

    frost_commit_generate(group, session_id_hex, session_id, message, resp);
}

static void respond_share(const signing_session_t *s, rpc_response_t *resp) {
    char share_hex[FTR_SIGNATURE_SHARE_LEN * 2 + 1];
    bytes_to_hex(s->share, sizeof(s->share), share_hex, sizeof(share_hex));
    char result[128];
    snprintf(result, sizeof(result), "{\"signature_share\":\"%s\",\"index\":%u}", share_hex,
             s->index);
    protocol_success(resp, resp->id, result);
}

static void frost_sign_execute(signing_session_t *s, const char *session_id_hex,
                               const uint8_t *session_id, const uint8_t *package,
                               size_t package_len, const uint8_t package_hash[32],
                               rpc_response_t *resp) {
    ag_random_delay_us(100, 1000);

    secresult_t policy_check = verify_policy_unchanged_secure(s->has_policy, s->policy_hash);
    policy_check = ag_verify_condition_secure(policy_check);
    if (!SECRESULT_IS_TRUE(policy_check)) {
        free_session(s);
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Policy changed during session");
        return;
    }

    share_key_t key;
    ftr_key_info_t info;
    if (load_key(s->group, &key, &info, resp) != 0) {
        free_session(s);
        return;
    }
    if (info.index != s->index ||
        ct_compare(info.verifying_share, s->verifying_share, sizeof(s->verifying_share)) != 0) {
        secure_memzero(&key, sizeof(key));
        free_session(s);
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SHARE, "Share changed during session");
        return;
    }

    ag_random_delay_us(100, 1000);

    uint8_t share[FTR_SIGNATURE_SHARE_LEN];
    sign_job_t job = {.kp = key.key_package,
                      .kp_len = key.key_package_len,
                      .nonces = s->nonces,
                      .package = package,
                      .package_len = package_len,
                      .message = s->message,
                      .share = share};
    int ret = ftr_task_run(sign_job, &job);
    secure_memzero(&key, sizeof(key));
    /* frost_tr zeroes the nonces whatever the outcome; the session is spent either way. */
    secure_memzero(s->nonces, sizeof(s->nonces));
    if (ret != FTR_OK) {
        secure_memzero(share, sizeof(share));
        free_session(s);
        char msg[64];
        snprintf(msg, sizeof(msg), "Signing refused (%d)", ret);
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, msg);
        return;
    }

    ag_random_delay_us(100, 1000);

    secresult_t post_sign_check = verify_policy_unchanged_secure(s->has_policy, s->policy_hash);
    post_sign_check = ag_verify_condition_secure(post_sign_check);
    if (!SECRESULT_IS_TRUE(post_sign_check)) {
        secure_memzero(share, sizeof(share));
        free_session(s);
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Policy changed during signing");
        return;
    }

    record_consumed_session(session_id);
    s->released = true;
    memcpy(s->share, share, sizeof(share));
    memcpy(s->package_hash, package_hash, 32);
    secure_memzero(share, sizeof(share));

    respond_share(s, resp);
    FROST_LOGI(TAG, "Created signature share for session %.16s...", session_id_hex);
}

void frost_sign(const char *group, const char *session_id_hex, const char *signing_package_hex,
                rpc_response_t *resp) {
    KEEP_ASSERT_VOID(group != NULL);
    KEEP_ASSERT_VOID(session_id_hex != NULL);
    KEEP_ASSERT_VOID(signing_package_hex != NULL);
    KEEP_ASSERT_VOID(resp != NULL);
    KEEP_ASSERT_VOID(group[0] != '\0');

    secresult_t rng_health = ag_verify_condition_secure(rng_is_healthy_secure());
    if (!SECRESULT_IS_TRUE(rng_health)) {
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

    static uint8_t package[FTR_SIGNING_PACKAGE_MAX];
    int package_len = hex_to_bytes(signing_package_hex, package, sizeof(package));
    if (package_len <= 0) {
        PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_PARAMS, "Invalid signing_package hex");
        return;
    }
    /* Only identifies a retry of the same package; at worst a failed hash makes a retry
     * return the share already released for this session. */
    uint8_t package_hash[32] = {0};
    mbedtls_sha256(package, (size_t)package_len, package_hash, 0);

    /* A host that lost the response may ask again; it gets the same share for the same
     * package, and nothing for any other. */
    if (s->released) {
        if (ct_compare(s->package_hash, package_hash, sizeof(package_hash)) == 0) {
            respond_share(s, resp);
            FROST_LOGI(TAG, "Returning signature share for session %.16s... (retry)",
                       session_id_hex);
        } else {
            PROTOCOL_ERROR(resp, resp->id, PROTOCOL_ERR_SIGN, "Session already consumed");
        }
        return;
    }

    frost_sign_execute(s, session_id_hex, session_id, package, (size_t)package_len, package_hash,
                       resp);
}

void frost_signer_cleanup_stale(void) {
    uint32_t now = get_time_ms();
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].active && elapsed_ms(sessions[i].created_at, now) > SESSION_TIMEOUT_MS) {
            FROST_LOGW(TAG, "Cleaning up stale session");
            free_session(&sessions[i]);
        }
    }
}

void frost_signer_discard_sessions(void) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].active) {
            free_session(&sessions[i]);
        }
    }
}
