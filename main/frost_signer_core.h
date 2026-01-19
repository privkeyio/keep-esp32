// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef FROST_SIGNER_CORE_H
#define FROST_SIGNER_CORE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "frost.h"
#include "session.h"

#define FROST_CORE_OK                    0
#define FROST_CORE_ERR_INVALID_SHARE     -1
#define FROST_CORE_ERR_INVALID_SESSION   -2
#define FROST_CORE_ERR_COMMITMENT_FAILED -3
#define FROST_CORE_ERR_SIGN_FAILED       -4
#define FROST_CORE_ERR_AGGREGATE_FAILED  -5
#define FROST_CORE_ERR_THRESHOLD         -6
#define FROST_CORE_ERR_PARSE             -7
#define FROST_CORE_ERR_OVERFLOW          -8

/**
 * @brief Result of a pure pubkey operation.
 */
typedef struct {
    uint8_t pubkey[33];
    uint16_t index;
    uint16_t threshold;
    uint16_t participants;
} frost_pubkey_result_t;

/**
 * @brief Result of a pure commitment operation.
 */
typedef struct {
    uint8_t commitment[COMMITMENT_LEN];
    size_t commitment_len;
    uint16_t index;
} frost_commitment_result_t;

/**
 * @brief Result of a pure sign operation.
 */
typedef struct {
    uint8_t sig_share[SIG_SHARE_LEN];
    size_t sig_share_len;
    uint16_t index;
} frost_sign_result_t;

/**
 * @brief Result of a pure aggregate operation.
 */
typedef struct {
    uint8_t signature[SIGNATURE_LEN];
} frost_aggregate_result_t;

/**
 * @brief Get pubkey from share bytes (pure function).
 * @param share_bytes Serialized share
 * @param share_len Share length
 * @param result Output result
 * @return 0 on success, negative on error
 */
int frost_get_pubkey_pure(const uint8_t *share_bytes, size_t share_len,
                          frost_pubkey_result_t *result);

/**
 * @brief Create commitment (uses platform RNG internally).
 * @param state Initialized FROST state
 * @param session Session to store nonce
 * @param result Output commitment result
 * @return 0 on success, negative on error
 */
int frost_create_commitment_pure(frost_state_t *state, session_t *session,
                                 frost_commitment_result_t *result);

/**
 * @brief Create signature share (pure function).
 * @param state FROST state
 * @param session Session with all commitments
 * @param message 32-byte message hash
 * @param message_len Must be 32
 * @param result Output signature share result
 * @return 0 on success, negative on error
 */
int frost_sign_share_pure(frost_state_t *state, session_t *session, const uint8_t *message,
                          size_t message_len, frost_sign_result_t *result);

/**
 * @brief Aggregate signature shares (pure function).
 * @param state FROST state
 * @param session Session with threshold shares
 * @param message 32-byte message hash
 * @param message_len Must be 32
 * @param result Output aggregate result
 * @return 0 on success, negative on error
 */
int frost_aggregate_pure(frost_state_t *state, session_t *session, const uint8_t *message,
                         size_t message_len, frost_aggregate_result_t *result);

/**
 * @brief Parse commitment from hex string into binary.
 * @param hex_str Commitment hex string (COMMITMENT_HEX_LEN chars)
 * @param out Output buffer (COMMITMENT_LEN bytes)
 * @param out_index Output: signer index from commitment
 * @return 0 on success, negative on error
 */
int frost_parse_commitment(const char *hex_str, uint8_t *out, uint16_t *out_index);

/**
 * @brief Parse multiple concatenated commitments.
 * @param hex_str Concatenated commitment hex strings
 * @param session Session to add commitments to
 * @return Number of commitments parsed, negative on error
 */
int frost_parse_commitments(const char *hex_str, session_t *session);

/**
 * @brief Parse signature share from hex string.
 * @param hex_str Signature share hex string
 * @param out Output buffer (SIG_SHARE_LEN bytes)
 * @param share_len Output: actual share length
 * @return 0 on success, negative on error
 */
int frost_parse_sig_share(const char *hex_str, uint8_t *out, size_t *share_len);

/**
 * @brief Validate session ID (not zero, not all ones).
 * @param session_id 32-byte session ID
 * @return true if valid
 */
bool frost_is_session_id_valid(const uint8_t *session_id);

/**
 * @brief Initialize a signing session.
 * @param session Output session
 * @param session_id 32-byte session ID
 * @param message 32-byte message hash
 * @param share_index Our signer index
 * @param threshold Signing threshold
 * @return 0 on success, FROST_CORE_ERR_INVALID_SESSION if any param is NULL
 */
int frost_init_signing_session(session_t *session, const uint8_t *session_id,
                               const uint8_t *message, uint16_t share_index, uint16_t threshold);

#endif
