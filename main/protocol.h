#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define PROTOCOL_MAX_MESSAGE_LEN 1024
#define PROTOCOL_MAX_GROUP_LEN 64
#define PROTOCOL_MAX_HEX_LEN 512
#define PROTOCOL_VERSION "0.1.0"
#define PROTOCOL_MAX_PARTICIPANTS 16
#define PROTOCOL_COMMITMENT_HEX_LEN 264
#define MAX_COMMITMENTS_SIZE ((PROTOCOL_MAX_PARTICIPANTS - 1) * PROTOCOL_COMMITMENT_HEX_LEN + 1)

#define PROTOCOL_ERR_PARSE       -32700
#define PROTOCOL_ERR_INTERNAL    -32603
#define PROTOCOL_ERR_METHOD      -32601
#define PROTOCOL_ERR_PARAMS      -32602
#define PROTOCOL_ERR_SHARE       -1
#define PROTOCOL_ERR_SIGN        -2
#define PROTOCOL_ERR_STORAGE     -3

typedef enum {
    RPC_METHOD_PING = 0,
    RPC_METHOD_GET_SHARE_PUBKEY,
    RPC_METHOD_FROST_COMMIT,
    RPC_METHOD_FROST_SIGN,
    RPC_METHOD_IMPORT_SHARE,
    RPC_METHOD_DELETE_SHARE,
    RPC_METHOD_LIST_SHARES,
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
} rpc_request_t;

typedef struct {
    int id;
    bool success;
    int error_code;
    char error_msg[128];
    char result[512];
} rpc_response_t;

int protocol_parse_request(const char *json, rpc_request_t *req);
int protocol_format_response(const rpc_response_t *resp, char *buf, size_t len);
void protocol_success(rpc_response_t *resp, int id, const char *result);
void protocol_error(rpc_response_t *resp, int id, int code, const char *message);

#endif
