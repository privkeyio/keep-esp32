// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "error_context.h"
#include "error_codes.h"
#include "frost_tr.h"

#define PROTOCOL_MAX_MESSAGE_LEN     16384
#define PROTOCOL_MAX_GROUP_LEN       64
#define PROTOCOL_MAX_HEX_LEN         512
#define PROTOCOL_MAX_PSBT_LEN        8192
#define PROTOCOL_VERSION             "0.2.0"
#define PROTOCOL_API_VERSION         2
#define PROTOCOL_MAX_PARTICIPANTS    16
#define PROTOCOL_MAX_PIN_LEN         64
#define PROTOCOL_KEY_PACKAGE_HEX     (FTR_KEY_PACKAGE_MAX * 2)
#define PROTOCOL_SIGNING_PACKAGE_HEX (FTR_SIGNING_PACKAGE_MAX * 2)

typedef enum {
    RPC_METHOD_PING = 0,
    RPC_METHOD_GET_SHARE_PUBKEY,
    RPC_METHOD_GET_SHARE_INFO,
    RPC_METHOD_FROST_COMMIT,
    RPC_METHOD_FROST_SIGN,
    RPC_METHOD_IMPORT_SHARE,
    RPC_METHOD_DELETE_SHARE,
    RPC_METHOD_LIST_SHARES,
    RPC_METHOD_BITCOIN_PARSE,
    RPC_METHOD_BITCOIN_SIGN,
    RPC_METHOD_POLICY_UPDATE,
    RPC_METHOD_POLICY_GET,
    RPC_METHOD_GET_STATUS,
    RPC_METHOD_RESTART,
    RPC_METHOD_EXPORT_SHARE,
    RPC_METHOD_UNLOCK,
    /* DKG and session resume, removed in protocol 2. */
    RPC_METHOD_RETIRED,
    RPC_METHOD_UNKNOWN
} rpc_method_t;

typedef struct {
    int id;
    rpc_method_t method;
    char group[PROTOCOL_MAX_GROUP_LEN + 1];
    char message[PROTOCOL_MAX_HEX_LEN + 1];
    char key_package[PROTOCOL_KEY_PACKAGE_HEX + 1];
    /* Set when a request carries the pre-protocol-2 `share` field. */
    bool legacy_share;
    uint16_t participants;
    char session_id[65];
    /* BIP-32 unhardened path for frost_commit; empty signs under the group key. */
    uint32_t derivation_path[FTR_MAX_PATH_DEPTH];
    size_t derivation_path_len;
    /* BIP-341 key-path spend for frost_commit: sign under the output key of the
     * path's key, committing to merkle_root when has_merkle_root (no script tree
     * otherwise). */
    bool taproot_tweak;
    bool has_merkle_root;
    uint8_t merkle_root[32];
    char signing_package[PROTOCOL_SIGNING_PACKAGE_HEX + 1];
    char psbt[PROTOCOL_MAX_PSBT_LEN];
    size_t input_idx;
    char policy_bundle[5120];
    char passphrase[256];
    char pin[PROTOCOL_MAX_PIN_LEN + 1];
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
