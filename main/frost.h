/**
 * @file frost.h
 * @brief FROST threshold signature operations.
 *
 * @warning Nonces must never be reused. Each session requires fresh commitments.
 * @warning Share bytes contain secret material. Zeroize after use.
 */

#ifndef FROST_H
#define FROST_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "session.h"

/** @brief FROST signer state. */
typedef struct {
    void *ctx;                  /**< secp256k1 context */
    void *keypair;              /**< FROST keypair (secret) */
    uint16_t share_index;       /**< Signer index (1-based) */
    uint16_t threshold;         /**< Minimum signers */
    uint16_t participants;      /**< Total participants */
    uint8_t group_pubkey[33];   /**< Compressed group pubkey */
} frost_state_t;

/**
 * @brief Initialize FROST state from serialized share.
 * @param state Output state
 * @param share_bytes Serialized share (secret)
 * @param share_len Share length
 * @return 0 on success, negative on error
 * @note Call frost_free() when done.
 */
int frost_init(frost_state_t *state, const uint8_t *share_bytes, size_t share_len);

/**
 * @brief Free FROST state, zeroize secrets.
 * @param state State to free
 */
void frost_free(frost_state_t *state);

/**
 * @brief Generate signing commitment.
 * @param state FROST state
 * @param session Signing session (stores nonce)
 * @param commitment_out Output buffer
 * @param commitment_len In: buffer size, Out: length
 * @return 0 on success, negative on error
 * @warning Never reuse session for multiple signatures.
 */
int frost_create_commitment(frost_state_t *state, session_t *session,
                            uint8_t *commitment_out, size_t *commitment_len);

/**
 * @brief Produce signature share.
 * @param state FROST state
 * @param session Session with commitments
 * @param msg_hash 32-byte message hash
 * @param hash_len Must be 32
 * @param sig_share_out Output buffer
 * @param sig_share_len In: buffer size, Out: length
 * @return 0 on success, negative on error
 * @pre Session has all required commitments.
 */
int frost_sign_share(frost_state_t *state, session_t *session,
                     const uint8_t *msg_hash, size_t hash_len,
                     uint8_t *sig_share_out, size_t *sig_share_len);

/**
 * @brief Aggregate shares into Schnorr signature.
 * @param state FROST state
 * @param session Session with signature shares
 * @param msg_hash 32-byte message hash
 * @param hash_len Must be 32
 * @param signature_out Output buffer (64 bytes)
 * @return 0 on success, negative on error
 * @pre Session has threshold shares.
 */
int frost_aggregate(frost_state_t *state, session_t *session,
                    const uint8_t *msg_hash, size_t hash_len,
                    uint8_t *signature_out);

/**
 * @brief Verify Schnorr signature against group pubkey.
 * @param state FROST state
 * @param signature 64-byte signature
 * @param msg_hash 32-byte message hash
 * @param hash_len Must be 32
 * @return 0 if valid, negative on error
 */
int frost_verify(frost_state_t *state, const uint8_t *signature,
                 const uint8_t *msg_hash, size_t hash_len);

#endif
