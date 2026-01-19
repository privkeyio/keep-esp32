// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "error_context.h"
#include "error_codes.h"

#define PROTOCOL_MAX_MESSAGE_LEN    16384
#define PROTOCOL_MAX_GROUP_LEN      64
#define PROTOCOL_MAX_HEX_LEN        512
#define PROTOCOL_MAX_PSBT_LEN       8192
#define PROTOCOL_VERSION            "0.1.2"
#define PROTOCOL_API_VERSION        1
#define PROTOCOL_MAX_PARTICIPANTS   16
#define PROTOCOL_COMMITMENT_HEX_LEN 264
#define MAX_COMMITMENTS_SIZE        ((PROTOCOL_MAX_PARTICIPANTS - 1) * PROTOCOL_COMMITMENT_HEX_LEN + 1)

typedef enum {
    RPC_METHOD_PING = 0,
    RPC_METHOD_GET_SHARE_PUBKEY,
    RPC_METHOD_GET_SHARE_INFO,
    RPC_METHOD_FROST_COMMIT,
    RPC_METHOD_FROST_SIGN,
    RPC_METHOD_IMPORT_SHARE,
    RPC_METHOD_DELETE_SHARE,
    RPC_METHOD_LIST_SHARES,
    RPC_METHOD_DKG_INIT,
    RPC_METHOD_DKG_ROUND1,
    RPC_METHOD_DKG_ROUND1_PEER,
    RPC_METHOD_DKG_ROUND2,
    RPC_METHOD_DKG_RECEIVE_SHARE,
    RPC_METHOD_DKG_FINALIZE,
    RPC_METHOD_BITCOIN_PARSE,
    RPC_METHOD_BITCOIN_SIGN,
    RPC_METHOD_POLICY_UPDATE,
    RPC_METHOD_POLICY_GET,
    RPC_METHOD_GET_STATUS,
    RPC_METHOD_RESTART,
    RPC_METHOD_EXPORT_SHARE,
    RPC_METHOD_SESSION_RESUME,
    RPC_METHOD_SESSION_LIST,
    RPC_METHOD_UNKNOWN
} rpc_method_t;

typedef struct {
    int id;
    rpc_method_t method;
    char group[PROTOCOL_MAX_GROUP_LEN + 1];
    char message[PROTOCOL_MAX_HEX_LEN + 1];
    char share[PROTOCOL_MAX_HEX_LEN + 1];
    char session_id[65];
    char commitments[MAX_COMMITMENTS_SIZE];
    uint8_t threshold;
    uint8_t participant_count;
    uint8_t our_index;
    uint8_t peer_index;
    char dkg_data[2048];
    char *psbt;
    size_t input_idx;
    char policy_bundle[5120];
} rpc_request_t;

typedef struct {
    int id;
    bool success;
    int error_code;
    char error_msg[128];
    char result[PROTOCOL_MAX_PSBT_LEN + 256];
    error_context_t error_ctx;
} rpc_response_t;

int protocol_parse_request(const char *json, rpc_request_t *req);
void protocol_free_request(rpc_request_t *req);
int protocol_format_response(const rpc_response_t *resp, char *buf, size_t len);
void protocol_success(rpc_response_t *resp, int id, const char *result);
void protocol_error(rpc_response_t *resp, int id, int code, const char *message);
void protocol_error_ctx(rpc_response_t *resp, int id, int code, const char *message,
                        const char *file, uint16_t line, const char *func);

#define PROTOCOL_ERROR(resp, id, code, msg) \
    protocol_error_ctx((resp), (id), (code), (msg), __FILE__, __LINE__, __func__)

#endif
