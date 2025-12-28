#include "protocol.h"
#include "cJSON.h"
#include <string.h>
#include <stdio.h>

static rpc_method_t parse_method(const char *method) {
    if (strcmp(method, "ping") == 0) return RPC_METHOD_PING;
    if (strcmp(method, "get_share_pubkey") == 0) return RPC_METHOD_GET_SHARE_PUBKEY;
    if (strcmp(method, "frost_commit") == 0) return RPC_METHOD_FROST_COMMIT;
    if (strcmp(method, "frost_sign") == 0) return RPC_METHOD_FROST_SIGN;
    if (strcmp(method, "import_share") == 0) return RPC_METHOD_IMPORT_SHARE;
    if (strcmp(method, "delete_share") == 0) return RPC_METHOD_DELETE_SHARE;
    if (strcmp(method, "list_shares") == 0) return RPC_METHOD_LIST_SHARES;
    return RPC_METHOD_UNKNOWN;
}

int protocol_parse_request(const char *json, rpc_request_t *req) {
    memset(req, 0, sizeof(*req));
    req->method = RPC_METHOD_UNKNOWN;

    cJSON *root = cJSON_Parse(json);
    if (!root) return PROTOCOL_ERR_PARSE;

    cJSON *id_item = cJSON_GetObjectItem(root, "id");
    if (!id_item || !cJSON_IsNumber(id_item)) {
        cJSON_Delete(root);
        return PROTOCOL_ERR_PARSE;
    }
    req->id = id_item->valueint;

    cJSON *method_item = cJSON_GetObjectItem(root, "method");
    if (!method_item || !cJSON_IsString(method_item)) {
        cJSON_Delete(root);
        return PROTOCOL_ERR_PARSE;
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
        cJSON *share = cJSON_GetObjectItem(params, "share");
        if (share && cJSON_IsString(share)) {
            snprintf(req->share, sizeof(req->share), "%s", share->valuestring);
        }
        cJSON *session_id = cJSON_GetObjectItem(params, "session_id");
        if (session_id && cJSON_IsString(session_id)) {
            snprintf(req->session_id, sizeof(req->session_id), "%s", session_id->valuestring);
        }
        cJSON *commitments = cJSON_GetObjectItem(params, "commitments");
        if (commitments && cJSON_IsString(commitments)) {
            snprintf(req->commitments, sizeof(req->commitments), "%s", commitments->valuestring);
        }
    }

    cJSON_Delete(root);
    return 0;
}

int protocol_format_response(const rpc_response_t *resp, char *buf, size_t len) {
    cJSON *root = cJSON_CreateObject();
    if (!root) return -1;

    cJSON_AddNumberToObject(root, "id", resp->id);

    if (resp->success) {
        cJSON *result = cJSON_Parse(resp->result);
        if (result) {
            cJSON_AddItemToObject(root, "result", result);
        } else {
            cJSON_AddRawToObject(root, "result", resp->result);
        }
    } else {
        cJSON *error = cJSON_AddObjectToObject(root, "error");
        if (!error) {
            cJSON_Delete(root);
            return -1;
        }
        cJSON_AddNumberToObject(error, "code", resp->error_code);
        cJSON_AddStringToObject(error, "message", resp->error_msg);
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
}

void protocol_error(rpc_response_t *resp, int id, int code, const char *message) {
    resp->id = id;
    resp->success = false;
    resp->error_code = code;
    strncpy(resp->error_msg, message, sizeof(resp->error_msg) - 1);
    resp->error_msg[sizeof(resp->error_msg) - 1] = '\0';
    resp->result[0] = '\0';
}
