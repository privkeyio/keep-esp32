// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include "protocol.h"
#include "error_context.h"
#include "crypto_asm.h"
#include "cJSON.h"
#include "hex_utils.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <math.h>

static bool is_valid_base64(const char *str, size_t len) {
    if (len == 0)
        return false;
    size_t padding = 0;
    for (size_t i = 0; i < len; i++) {
        char c = str[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '+' || c == '/') {
            if (padding > 0)
                return false;
            continue;
        }
        if (c == '=') {
            padding++;
            if (padding > 2)
                return false;
            continue;
        }
        return false;
    }
    return (len % 4) != 1;
}

static rpc_method_t parse_method(const char *method) {
    if (strcmp(method, "ping") == 0)
        return RPC_METHOD_PING;
    if (strcmp(method, "get_share_pubkey") == 0)
        return RPC_METHOD_GET_SHARE_PUBKEY;
    if (strcmp(method, "get_share_info") == 0)
        return RPC_METHOD_GET_SHARE_INFO;
    if (strcmp(method, "frost_commit") == 0)
        return RPC_METHOD_FROST_COMMIT;
    if (strcmp(method, "frost_sign") == 0)
        return RPC_METHOD_FROST_SIGN;
    if (strcmp(method, "import_share") == 0)
        return RPC_METHOD_IMPORT_SHARE;
    if (strcmp(method, "delete_share") == 0)
        return RPC_METHOD_DELETE_SHARE;
    if (strcmp(method, "list_shares") == 0)
        return RPC_METHOD_LIST_SHARES;
    if (strcmp(method, "bitcoin_parse") == 0)
        return RPC_METHOD_BITCOIN_PARSE;
    if (strcmp(method, "bitcoin_sign") == 0)
        return RPC_METHOD_BITCOIN_SIGN;
    if (strcmp(method, "policy_update") == 0)
        return RPC_METHOD_POLICY_UPDATE;
    if (strcmp(method, "policy_get") == 0)
        return RPC_METHOD_POLICY_GET;
    if (strcmp(method, "get_status") == 0)
        return RPC_METHOD_GET_STATUS;
    if (strcmp(method, "restart") == 0)
        return RPC_METHOD_RESTART;
    if (strcmp(method, "export_share") == 0)
        return RPC_METHOD_EXPORT_SHARE;
    if (strcmp(method, "unlock") == 0)
        return RPC_METHOD_UNLOCK;
    if (strncmp(method, "dkg_", 4) == 0 || strcmp(method, "frost_session_resume") == 0 ||
        strcmp(method, "frost_session_list") == 0)
        return RPC_METHOD_RETIRED;
    return RPC_METHOD_UNKNOWN;
}

int protocol_parse_request(const char *json, rpc_request_t *req) {
    if (!json || !req)
        return ERR_PROTOCOL_PARSE;

    memset(req, 0, sizeof(*req));
    req->method = RPC_METHOD_UNKNOWN;

    cJSON *root = cJSON_Parse(json);
    if (!root)
        return ERR_PROTOCOL_PARSE;

    cJSON *id_item = cJSON_GetObjectItem(root, "id");
    if (!id_item || !cJSON_IsNumber(id_item)) {
        cJSON_Delete(root);
        return ERR_PROTOCOL_PARSE;
    }
    req->id = id_item->valueint;

    cJSON *method_item = cJSON_GetObjectItem(root, "method");
    if (!method_item || !cJSON_IsString(method_item)) {
        cJSON_Delete(root);
        return ERR_PROTOCOL_PARSE;
    }
    req->method = parse_method(method_item->valuestring);

    cJSON *params = cJSON_GetObjectItem(root, "params");
    if (params && cJSON_IsObject(params)) {
        cJSON *group = cJSON_GetObjectItem(params, "group");
        if (group && cJSON_IsString(group)) {
            snprintf(req->group, sizeof(req->group), "%s", group->valuestring);
        }
        cJSON *message = cJSON_GetObjectItem(params, "message");
        if (message && cJSON_IsString(message)) {
            snprintf(req->message, sizeof(req->message), "%s", message->valuestring);
        }
        req->legacy_share = cJSON_GetObjectItem(params, "share") != NULL;
        cJSON *key_package = cJSON_GetObjectItem(params, "key_package");
        if (key_package && cJSON_IsString(key_package)) {
            size_t len = strlen(key_package->valuestring);
            if (len > PROTOCOL_KEY_PACKAGE_HEX) {
                cJSON_Delete(root);
                return ERR_PROTOCOL_PARAMS;
            }
            memcpy(req->key_package, key_package->valuestring, len + 1);
        }
        cJSON *participants = cJSON_GetObjectItem(params, "participants");
        if (participants && cJSON_IsNumber(participants)) {
            if (participants->valueint < 0 || participants->valueint > PROTOCOL_MAX_PARTICIPANTS) {
                cJSON_Delete(root);
                return ERR_PROTOCOL_PARAMS;
            }
            req->participants = (uint16_t)participants->valueint;
        }
        cJSON *session_id = cJSON_GetObjectItem(params, "session_id");
        if (session_id && cJSON_IsString(session_id)) {
            size_t len = strlen(session_id->valuestring);
            if (len >= sizeof(req->session_id)) {
                cJSON_Delete(root);
                return ERR_PROTOCOL_PARAMS;
            }
            memcpy(req->session_id, session_id->valuestring, len + 1);
        }
        cJSON *path = cJSON_GetObjectItemCaseSensitive(params, "derivation_path");
        if (path) {
            /* The path is fixed at commit; anywhere else it would be silently ignored. */
            int n = cJSON_IsArray(path) && req->method == RPC_METHOD_FROST_COMMIT
                        ? cJSON_GetArraySize(path)
                        : -1;
            if (n < 0 || n > FTR_MAX_PATH_DEPTH) {
                cJSON_Delete(root);
                return ERR_PROTOCOL_PARAMS;
            }
            for (int i = 0; i < n; i++) {
                cJSON *index = cJSON_GetArrayItem(path, i);
                double v = cJSON_IsNumber(index) ? index->valuedouble : -1.0;
                /* Unhardened only: hardened derivation needs a secret no signer holds. The
                 * range test comes first so NaN never reaches the cast. */
                if (!(v >= 0.0 && v < 2147483648.0) || signbit(v) || v != (double)(uint32_t)v) {
                    cJSON_Delete(root);
                    return ERR_PROTOCOL_PARAMS;
                }
                req->derivation_path[i] = (uint32_t)v;
            }
            req->derivation_path_len = (size_t)n;
        }
        cJSON *taproot = cJSON_GetObjectItemCaseSensitive(params, "taproot_tweak");
        if (taproot) {
            /* Fixed at commit like the path. Its one member, merkle_root, is optional;
             * any other member is refused rather than ignored. */
            int members = cJSON_IsObject(taproot) && req->method == RPC_METHOD_FROST_COMMIT
                              ? cJSON_GetArraySize(taproot)
                              : -1;
            cJSON *merkle_root =
                members == 1 ? cJSON_GetObjectItemCaseSensitive(taproot, "merkle_root") : NULL;
            bool ok = members == 0 ||
                      (cJSON_IsString(merkle_root) && strlen(merkle_root->valuestring) == 64 &&
                       hex_to_bytes(merkle_root->valuestring, req->merkle_root,
                                    sizeof(req->merkle_root)) == (int)sizeof(req->merkle_root));
            if (!ok) {
                cJSON_Delete(root);
                return ERR_PROTOCOL_PARAMS;
            }
            req->taproot_tweak = true;
            req->has_merkle_root = members == 1;
        }
        cJSON *signing_package = cJSON_GetObjectItem(params, "signing_package");
        if (signing_package && cJSON_IsString(signing_package)) {
            size_t len = strlen(signing_package->valuestring);
            if (len > PROTOCOL_SIGNING_PACKAGE_HEX) {
                cJSON_Delete(root);
                return ERR_PROTOCOL_PARAMS;
            }
            memcpy(req->signing_package, signing_package->valuestring, len + 1);
        }
        cJSON *psbt = cJSON_GetObjectItem(params, "psbt");
        if (psbt && cJSON_IsString(psbt)) {
            size_t len = strlen(psbt->valuestring);
            if (len >= PROTOCOL_MAX_PSBT_LEN) {
                cJSON_Delete(root);
                return ERR_PROTOCOL_PARAMS;
            }
            if (!is_valid_base64(psbt->valuestring, len)) {
                cJSON_Delete(root);
                return ERR_PROTOCOL_PARAMS;
            }
            memcpy(req->psbt, psbt->valuestring, len + 1);
        }
        cJSON *input_idx = cJSON_GetObjectItem(params, "input_idx");
        if (input_idx && cJSON_IsNumber(input_idx)) {
            if (input_idx->valueint < 0 || input_idx->valueint > INT_MAX - 1) {
                cJSON_Delete(root);
                return ERR_PROTOCOL_PARAMS;
            }
            req->input_idx = (size_t)input_idx->valueint;
        }
        cJSON *policy_bundle = cJSON_GetObjectItem(params, "bundle");
        if (policy_bundle && cJSON_IsString(policy_bundle)) {
            snprintf(req->policy_bundle, sizeof(req->policy_bundle), "%s",
                     policy_bundle->valuestring);
        }
        cJSON *passphrase = cJSON_GetObjectItem(params, "passphrase");
        if (passphrase && cJSON_IsString(passphrase)) {
            snprintf(req->passphrase, sizeof(req->passphrase), "%s", passphrase->valuestring);
        }
        cJSON *pin = cJSON_GetObjectItem(params, "pin");
        if (pin && cJSON_IsString(pin)) {
            snprintf(req->pin, sizeof(req->pin), "%s", pin->valuestring);
        }
    }

    cJSON_Delete(root);
    return 0;
}

void protocol_free_request(rpc_request_t *req) {
    if (req) {
        secure_memzero(req->passphrase, sizeof(req->passphrase));
        secure_memzero(req->pin, sizeof(req->pin));
        secure_memzero(req->psbt, sizeof(req->psbt));
        secure_memzero(req->key_package, sizeof(req->key_package));
    }
}

int protocol_format_response(const rpc_response_t *resp, char *buf, size_t len) {
    if (!resp || !buf || len == 0)
        return -1;
    if (len > (size_t)INT_MAX)
        len = (size_t)INT_MAX;

    cJSON *root = cJSON_CreateObject();
    if (!root)
        return -1;

    cJSON_AddNumberToObject(root, "id", resp->id);

    if (resp->success) {
        cJSON *result = cJSON_Parse(resp->result);
        if (result) {
            cJSON_AddItemToObject(root, "result", result);
        } else {
            cJSON *str_result = cJSON_CreateString(resp->result);
            if (!str_result) {
                cJSON_Delete(root);
                return -1;
            }
            cJSON_AddItemToObject(root, "result", str_result);
        }
    } else {
        cJSON *error = cJSON_AddObjectToObject(root, "error");
        if (!error) {
            cJSON_Delete(root);
            return -1;
        }
        cJSON_AddNumberToObject(error, "code", error_to_jsonrpc_code(resp->error_code));
        cJSON_AddStringToObject(error, "name", error_name(resp->error_code));
        cJSON_AddStringToObject(error, "message", resp->error_msg);
        cJSON_AddStringToObject(error, "category", error_category_name(resp->error_code));
#ifndef NDEBUG
        if (resp->error_ctx.file[0] != '\0') {
            cJSON *ctx = cJSON_AddObjectToObject(error, "context");
            if (ctx) {
                cJSON_AddStringToObject(ctx, "file", resp->error_ctx.file);
                cJSON_AddNumberToObject(ctx, "line", resp->error_ctx.line);
                cJSON_AddStringToObject(ctx, "func", resp->error_ctx.func);
            }
        }
#endif
    }

    cJSON_bool ok = cJSON_PrintPreallocated(root, buf, (int)len, 0);
    cJSON_Delete(root);

    return ok ? (int)strlen(buf) : -1;
}

void protocol_success(rpc_response_t *resp, int id, const char *result) {
    resp->id = id;
    resp->success = true;
    resp->error_code = 0;
    resp->error_msg[0] = '\0';
    strncpy(resp->result, result, sizeof(resp->result) - 1);
    resp->result[sizeof(resp->result) - 1] = '\0';
    memset(&resp->error_ctx, 0, sizeof(resp->error_ctx));
}

void protocol_error(rpc_response_t *resp, int id, int code, const char *message) {
    resp->id = id;
    resp->success = false;
    resp->error_code = code;
    strncpy(resp->error_msg, message, sizeof(resp->error_msg) - 1);
    resp->error_msg[sizeof(resp->error_msg) - 1] = '\0';
    resp->result[0] = '\0';
    memset(&resp->error_ctx, 0, sizeof(resp->error_ctx));
}

void protocol_error_ctx(rpc_response_t *resp, int id, int code, const char *message,
                        const char *file, uint16_t line, const char *func) {
    protocol_error(resp, id, code, message);
    error_context_set(&resp->error_ctx, code, file, line, func);
}
