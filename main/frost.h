#ifndef FROST_H
#define FROST_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "session.h"

typedef struct {
    void *ctx;
    void *keypair;
    uint16_t share_index;
    uint16_t threshold;
    uint8_t group_pubkey[33];
} frost_state_t;

int frost_init(frost_state_t *state, const uint8_t *share_bytes, size_t share_len);
void frost_free(frost_state_t *state);

int frost_create_commitment(frost_state_t *state, session_t *session,
                            uint8_t *commitment_out, size_t *commitment_len);

int frost_sign_share(frost_state_t *state, session_t *session,
                     const uint8_t *msg_hash, size_t hash_len,
                     uint8_t *sig_share_out, size_t *sig_share_len);

int frost_aggregate(frost_state_t *state, session_t *session,
                    const uint8_t *msg_hash, size_t hash_len,
                    uint8_t *signature_out);

int frost_verify(frost_state_t *state, const uint8_t *signature,
                 const uint8_t *msg_hash, size_t hash_len);

#endif
