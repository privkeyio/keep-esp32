#ifndef KFP_H
#define KFP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define KFP_VERSION 1
#define KFP_EVENT_KIND 24242
#define KFP_MAX_PARTICIPANTS 16
#define KFP_MAX_MESSAGE_LEN 1024

typedef enum {
    KFP_MSG_ANNOUNCE,
    KFP_MSG_SIGN_REQUEST,
    KFP_MSG_COMMITMENT,
    KFP_MSG_SIGNATURE_SHARE,
    KFP_MSG_SIGNATURE_COMPLETE,
    KFP_MSG_PING,
    KFP_MSG_PONG,
    KFP_MSG_ERROR,
    KFP_MSG_UNKNOWN
} kfp_msg_type_t;

typedef struct {
    uint8_t version;
    uint8_t group_pubkey[32];
    uint16_t share_index;
    char name[64];
} kfp_announce_t;

typedef struct {
    uint8_t session_id[32];
    uint8_t group_pubkey[32];
    uint8_t message[KFP_MAX_MESSAGE_LEN];
    size_t message_len;
    char message_type[32];
    uint16_t participants[KFP_MAX_PARTICIPANTS];
    uint8_t participant_count;
    uint64_t timestamp;
} kfp_sign_request_t;

typedef struct {
    uint8_t session_id[32];
    uint16_t share_index;
    uint8_t commitment[128];
    size_t commitment_len;
} kfp_commitment_t;

typedef struct {
    uint8_t session_id[32];
    uint16_t share_index;
    uint8_t signature_share[64];
    size_t share_len;
} kfp_signature_share_t;

typedef struct {
    uint8_t session_id[32];
    uint8_t signature[64];
    uint8_t message_hash[32];
} kfp_signature_complete_t;

typedef struct {
    uint8_t challenge[32];
    uint64_t timestamp;
} kfp_ping_t;

typedef struct {
    uint8_t challenge[32];
    uint64_t timestamp;
} kfp_pong_t;

typedef struct {
    uint8_t session_id[32];
    bool has_session_id;
    char code[32];
    char message[256];
} kfp_error_t;

typedef struct {
    kfp_msg_type_t type;
    union {
        kfp_announce_t announce;
        kfp_sign_request_t sign_request;
        kfp_commitment_t commitment;
        kfp_signature_share_t signature_share;
        kfp_signature_complete_t signature_complete;
        kfp_ping_t ping;
        kfp_pong_t pong;
        kfp_error_t error;
    };
} kfp_msg_t;

kfp_msg_type_t kfp_parse(const char *json, kfp_msg_t *out);
char *kfp_serialize_announce(const kfp_announce_t *msg);
char *kfp_serialize_commitment(const kfp_commitment_t *msg);
char *kfp_serialize_signature_share(const kfp_signature_share_t *msg);
char *kfp_serialize_pong(const kfp_pong_t *msg);
char *kfp_serialize_error(const kfp_error_t *msg);

#endif
