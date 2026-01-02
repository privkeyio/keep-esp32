#ifndef NOSTR_FROST_H
#define NOSTR_FROST_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define FROST_KIND_GROUP          21101
#define FROST_KIND_DKG_ROUND1     21102
#define FROST_KIND_DKG_ROUND2     21103
#define FROST_KIND_SIGN_REQUEST   21104
#define FROST_KIND_SIGN_RESPONSE  21105
#define FROST_KIND_NONCE_COMMIT   21106
#define FROST_KIND_PAYMENT_NOTIFY 21110

#define NIP46_KIND_NOSTR_CONNECT  24133
#define NOSTR_P2P_KIND_EPHEMERAL  29001

#define MAX_GROUP_PARTICIPANTS 16
#define MAX_THRESHOLD MAX_GROUP_PARTICIPANTS
#define GROUP_ID_LEN 32
#define MAX_RELAYS 4
#define RELAY_URL_LEN 128
#define DKG_CONTEXT_TAG "frost-keygen"

typedef struct {
    uint8_t npub[32];
    uint8_t index;
    char relay_hint[RELAY_URL_LEN];
} frost_participant_t;

typedef struct {
    uint8_t group_id[GROUP_ID_LEN];
    uint8_t threshold;
    uint8_t participant_count;
    frost_participant_t participants[MAX_GROUP_PARTICIPANTS];
    uint8_t group_pubkey[32];
    uint8_t coordinator_npub[32];
    uint8_t notification_pubkey[32];
    bool has_notification_key;
    char relays[MAX_RELAYS][RELAY_URL_LEN];
    uint8_t relay_count;
} frost_group_t;

typedef struct {
    uint8_t group_id[GROUP_ID_LEN];
    uint8_t participant_index;
    uint8_t num_coefficients;
    uint8_t coefficient_commitments[MAX_THRESHOLD][64];
    uint8_t zkp_r[64];
    uint8_t zkp_z[32];
} frost_dkg_round1_t;

typedef struct {
    uint8_t generator_index;
    uint8_t receiver_index;
    uint8_t value[32];
} frost_dkg_share_t;

typedef struct {
    uint8_t group_id[GROUP_ID_LEN];
    uint8_t sender_index;
    uint8_t recipient_index;
    uint8_t encrypted_share[48];
} frost_dkg_round2_t;

typedef enum {
    FROST_MSG_TYPE_PSBT,
    FROST_MSG_TYPE_NOSTR_EVENT,
    FROST_MSG_TYPE_RAW,
} frost_message_type_t;

typedef struct {
    uint8_t group_id[GROUP_ID_LEN];
    uint8_t request_id[32];
    frost_message_type_t message_type;
    uint8_t *payload;
    size_t payload_len;
    uint32_t nonce_index;
    uint8_t policy_hash[32];
    bool has_policy;
} frost_sign_request_t;

typedef enum {
    FROST_SIGN_STATUS_SIGNED,
    FROST_SIGN_STATUS_REJECTED,
    FROST_SIGN_STATUS_PENDING,
    FROST_SIGN_STATUS_TIMEOUT,
} frost_sign_status_t;

typedef struct {
    uint8_t request_id[32];
    uint8_t participant_index;
    frost_sign_status_t status;
    uint8_t partial_signature[32];
    uint8_t nonce_commitment[33];
    char rejection_reason[128];
} frost_sign_response_t;

int frost_parse_group_event(const char *event_json, frost_group_t *group);
int frost_create_group_event(const frost_group_t *group,
                              const uint8_t *privkey,
                              char *event_json, size_t max_len);
int frost_get_our_index(const frost_group_t *group, const uint8_t our_npub[32]);

int frost_dkg_round1_generate(const frost_group_t *group,
                               uint8_t our_index,
                               frost_dkg_round1_t *round1,
                               uint8_t *secret_shares_out,
                               size_t *share_count);
int frost_dkg_round1_validate(const frost_dkg_round1_t *peer_round1);
int frost_create_dkg_round1_event(const frost_group_t *group,
                                   const frost_dkg_round1_t *round1,
                                   const uint8_t *privkey,
                                   char *event_json, size_t max_len);
int frost_parse_dkg_round1_event(const char *event_json,
                                  const frost_group_t *group,
                                  const uint8_t *our_privkey,
                                  frost_dkg_round1_t *round1);

int frost_create_dkg_round2_event(const frost_group_t *group,
                                   const frost_dkg_round2_t *round2,
                                   const uint8_t *our_privkey,
                                   const uint8_t *recipient_pubkey,
                                   char *event_json, size_t max_len);
int frost_dkg_finalize(const frost_group_t *group,
                        const frost_dkg_round1_t *all_round1,
                        size_t round1_count,
                        const frost_dkg_share_t *received_shares,
                        size_t share_count,
                        uint8_t our_index,
                        uint8_t our_share[32],
                        uint8_t group_pubkey[33]);

int frost_create_sign_request(const frost_group_t *group,
                               const frost_sign_request_t *request,
                               const uint8_t *privkey,
                               char *event_json, size_t max_len);
int frost_parse_sign_request(const char *event_json,
                              const frost_group_t *group,
                              const uint8_t *our_privkey,
                              frost_sign_request_t *request);

int frost_sign_partial(const frost_group_t *group,
                        const frost_sign_request_t *request,
                        const uint8_t our_share[32],
                        uint8_t our_index,
                        frost_sign_response_t *response);
int frost_create_sign_response(const frost_group_t *group,
                                const frost_sign_response_t *response,
                                const uint8_t *privkey,
                                char *event_json, size_t max_len);
int frost_parse_sign_response(const char *event_json,
                               const frost_group_t *group,
                               const uint8_t *our_privkey,
                               frost_sign_response_t *response);

void frost_sign_request_free(frost_sign_request_t *request);

#endif
