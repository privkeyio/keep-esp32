// SPDX-FileCopyrightText: © 2026 Privkey Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "frost_signer_core.h"
#include "hex_utils.h"
#include "crypto_asm.h"
#include <string.h>

static const uint8_t SESSION_ID_ALL_ONES[SESSION_ID_LEN] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

int frost_get_pubkey_pure(const uint8_t *share_bytes, size_t share_len,
                          frost_pubkey_result_t *result) {
    if (!share_bytes || !result) {
        return FROST_CORE_ERR_INVALID_SHARE;
    }

    frost_state_t state;
    int ret = frost_init(&state, share_bytes, share_len);
    if (ret != 0) {
        return FROST_CORE_ERR_INVALID_SHARE;
    }

    memcpy(result->pubkey, state.group_pubkey, sizeof(result->pubkey));
    result->index = state.share_index;
    result->threshold = state.threshold;
    result->participants = state.participants;

    frost_free(&state);
    return FROST_CORE_OK;
}

int frost_create_commitment_pure(frost_state_t *state, session_t *session,
                                 frost_commitment_result_t *result) {
    if (!state || !session || !result) {
        return FROST_CORE_ERR_INVALID_SESSION;
    }

    size_t commitment_len = 0;
    int ret = frost_create_commitment(state, session, result->commitment, &commitment_len);
    if (ret != 0) {
        return FROST_CORE_ERR_COMMITMENT_FAILED;
    }

    result->commitment_len = commitment_len;
    result->index = state->share_index;
    return FROST_CORE_OK;
}

int frost_sign_share_pure(frost_state_t *state, session_t *session, const uint8_t *message,
                          size_t message_len, frost_sign_result_t *result) {
    if (!state || !session || !message || !result) {
        return FROST_CORE_ERR_INVALID_SESSION;
    }

    size_t sig_share_len = 0;
    int ret =
        frost_sign_share(state, session, message, message_len, result->sig_share, &sig_share_len);
    if (ret != 0) {
        return FROST_CORE_ERR_SIGN_FAILED;
    }

    result->sig_share_len = sig_share_len;
    result->index = state->share_index;
    return FROST_CORE_OK;
}

int frost_aggregate_pure(frost_state_t *state, session_t *session, const uint8_t *message,
                         size_t message_len, frost_aggregate_result_t *result) {
    if (!state || !session || !message || !result) {
        return FROST_CORE_ERR_INVALID_SESSION;
    }

    if (session->sig_share_count < session->threshold) {
        return FROST_CORE_ERR_THRESHOLD;
    }

    int ret = frost_aggregate(state, session, message, message_len, result->signature);
    if (ret != 0) {
        return FROST_CORE_ERR_AGGREGATE_FAILED;
    }

    return FROST_CORE_OK;
}

int frost_parse_commitment(const char *hex_str, uint8_t *out, uint16_t *out_index) {
    if (!hex_str || !out) {
        return FROST_CORE_ERR_PARSE;
    }

    if (strlen(hex_str) != COMMITMENT_HEX_LEN) {
        return FROST_CORE_ERR_PARSE;
    }

    if (hex_to_bytes(hex_str, out, COMMITMENT_LEN) != COMMITMENT_LEN) {
        return FROST_CORE_ERR_PARSE;
    }

    if (out_index) {
        *out_index = (uint16_t)out[0] | ((uint16_t)out[1] << 8);
    }

    return FROST_CORE_OK;
}

int frost_parse_commitments(const char *hex_str, session_t *session) {
    if (!hex_str || !session) {
        return FROST_CORE_ERR_PARSE;
    }

    size_t hex_len = strlen(hex_str);
    if (hex_len == 0) {
        return 0;
    }

    size_t max_hex = (size_t)(MAX_PARTICIPANTS - 1) * COMMITMENT_HEX_LEN;
    if (hex_len > max_hex || hex_len % COMMITMENT_HEX_LEN != 0) {
        return FROST_CORE_ERR_PARSE;
    }

    size_t num_commits = hex_len / COMMITMENT_HEX_LEN;
    int parsed = 0;

    for (size_t i = 0; i < num_commits; i++) {
        if (session->commitment_count >= MAX_PARTICIPANTS) {
            return FROST_CORE_ERR_OVERFLOW;
        }

        uint8_t commit_bytes[COMMITMENT_LEN];
        char commit_chunk[COMMITMENT_HEX_LEN + 1];
        memcpy(commit_chunk, hex_str + i * COMMITMENT_HEX_LEN, COMMITMENT_HEX_LEN);
        commit_chunk[COMMITMENT_HEX_LEN] = '\0';

        if (hex_to_bytes(commit_chunk, commit_bytes, COMMITMENT_LEN) != COMMITMENT_LEN) {
            return FROST_CORE_ERR_PARSE;
        }

        int idx = session->commitment_count;
        uint16_t commit_index = (uint16_t)commit_bytes[0] | ((uint16_t)commit_bytes[1] << 8);

        memcpy(session->commitments[idx], commit_bytes, COMMITMENT_LEN);
        session->commitment_lens[idx] = COMMITMENT_LEN;
        session->commitment_indices[idx] = commit_index;
        session->commitment_count++;
        parsed++;
    }

    return parsed;
}

int frost_parse_sig_share(const char *hex_str, uint8_t *out, size_t *share_len) {
    if (!hex_str || !out || !share_len) {
        return FROST_CORE_ERR_PARSE;
    }

    size_t hex_len = strlen(hex_str);
    if (hex_len == 0 || hex_len > 72) {
        return FROST_CORE_ERR_PARSE;
    }

    int len = hex_to_bytes(hex_str, out, SIG_SHARE_LEN);
    if (len < 0) {
        return FROST_CORE_ERR_PARSE;
    }

    *share_len = (size_t)len;
    return FROST_CORE_OK;
}

bool frost_is_session_id_valid(const uint8_t *session_id) {
    if (!session_id) {
        return false;
    }

    bool is_all_zero = ct_is_zero(session_id, SESSION_ID_LEN);
    bool is_all_ones = ct_compare(session_id, SESSION_ID_ALL_ONES, SESSION_ID_LEN) == 0;

    return !is_all_zero && !is_all_ones;
}

int frost_init_signing_session(session_t *session, const uint8_t *session_id,
                               const uint8_t *message, uint16_t share_index, uint16_t threshold) {
    if (!session || !session_id || !message) {
        return FROST_CORE_ERR_INVALID_SESSION;
    }

    sign_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.session_id, session_id, SESSION_ID_LEN);
    memcpy(req.message, message, SESSION_ID_LEN);
    req.message_len = SESSION_ID_LEN;
    req.participants[0] = share_index;
    req.participant_count = 1;

    if (session_init(session, &req, threshold) != 0) {
        return FROST_CORE_ERR_INVALID_SESSION;
    }
    return FROST_CORE_OK;
}
