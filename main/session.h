#ifndef SESSION_H
#define SESSION_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define SESSION_TIMEOUT_MS 30000
#define MAX_ACTIVE_SESSIONS 4
#define MAX_PARTICIPANTS 16
#define MAX_MESSAGE_LEN 1024

#define SESSION_ID_LEN 32
#define SESSION_ID_HEX_LEN 64
#define COMMITMENT_LEN 132
#define COMMITMENT_HEX_LEN 264
#define SIGNATURE_LEN 64
#define SCALAR_LEN 32

typedef struct {
    uint8_t session_id[SESSION_ID_LEN];
    uint8_t group_pubkey[33];
    uint8_t message[MAX_MESSAGE_LEN];
    size_t message_len;
    char message_type[32];
    uint16_t participants[MAX_PARTICIPANTS];
    uint8_t participant_count;
    uint64_t timestamp;
} sign_request_t;

typedef enum {
    SESSION_IDLE,
    SESSION_AWAITING_COMMITMENTS,
    SESSION_AWAITING_SHARES,
    SESSION_COMPLETE,
    SESSION_FAILED,
    SESSION_EXPIRED
} session_state_t;

typedef struct {
    uint8_t session_id[SESSION_ID_LEN];
    uint8_t message[MAX_MESSAGE_LEN];
    size_t message_len;
    uint16_t threshold;
    uint16_t participants[MAX_PARTICIPANTS];
    uint8_t participant_count;
    session_state_t state;
    uint32_t created_at;

    uint8_t commitments[MAX_PARTICIPANTS][128];
    size_t commitment_lens[MAX_PARTICIPANTS];
    uint16_t commitment_indices[MAX_PARTICIPANTS];
    uint8_t commitment_count;

    uint8_t sig_shares[MAX_PARTICIPANTS][64];
    size_t sig_share_lens[MAX_PARTICIPANTS];
    uint16_t sig_share_indices[MAX_PARTICIPANTS];
    uint8_t sig_share_count;

    uint8_t our_nonce[64];
    uint8_t our_commitment[128];
    size_t our_commitment_len;

    uint8_t final_signature[64];
    bool has_signature;
} session_t;

void session_init(session_t *s, const sign_request_t *req, uint16_t threshold);
void session_destroy(session_t *s);
session_state_t session_state(session_t *s);
bool session_is_participant(session_t *s, uint16_t share_index);
int session_add_commitment(session_t *s, uint16_t share_index, const uint8_t *commitment, size_t len);
int session_add_signature_share(session_t *s, uint16_t share_index, const uint8_t *share, size_t len);
bool session_has_all_commitments(session_t *s);
bool session_has_all_shares(session_t *s);

#endif
