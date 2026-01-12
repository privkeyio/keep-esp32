#include "nostr_frost.h"
#include "nostr_frost_internal.h"
#include "hex_utils.h"
#include "cJSON.h"
#include <string.h>
#include <stdlib.h>

int frost_parse_nip46_event(const char *event_json,
                             const uint8_t *our_privkey,
                             nip46_request_t *request) {
    memset(request, 0, sizeof(*request));

    cJSON *root = cJSON_Parse(event_json);
    if (!root) return -1;

    cJSON *kind = cJSON_GetObjectItem(root, "kind");
    if (!kind || !cJSON_IsNumber(kind) || kind->valueint != NIP46_KIND_NOSTR_CONNECT) {
        cJSON_Delete(root);
        return -2;
    }

    cJSON *pubkey_obj = cJSON_GetObjectItem(root, "pubkey");
    if (pubkey_obj && cJSON_IsString(pubkey_obj)) {
        if (hex_to_bytes(pubkey_obj->valuestring, request->sender_pubkey, 32) != 32) {
            memset(request->sender_pubkey, 0, 32);
            cJSON_Delete(root);
            return -5;
        }
    }

    cJSON *content = cJSON_GetObjectItem(root, "content");
    if (content && cJSON_IsString(content)) {
        char *decrypted = nip44_decrypt_content(content->valuestring, our_privkey, request->sender_pubkey);
        if (!decrypted) {
            cJSON_Delete(root);
            return -3;
        }

        cJSON *inner = cJSON_Parse(decrypted);
        free(decrypted);
        if (!inner) {
            cJSON_Delete(root);
            return -4;
        }

        cJSON *id = cJSON_GetObjectItem(inner, "id");
        if (id && cJSON_IsString(id)) {
            strncpy(request->id, id->valuestring, sizeof(request->id) - 1);
        }
        cJSON *method = cJSON_GetObjectItem(inner, "method");
        if (method && cJSON_IsString(method)) {
            strncpy(request->method, method->valuestring, sizeof(request->method) - 1);
        }
        cJSON *params = cJSON_GetObjectItem(inner, "params");
        if (params) {
            char *params_str = cJSON_PrintUnformatted(params);
            if (params_str) {
                request->params = params_str;
                request->params_len = strlen(params_str);
            }
        }
        cJSON_Delete(inner);
    }

    cJSON_Delete(root);
    return 0;
}

int frost_create_nip46_response(const nip46_response_t *response,
                                 const uint8_t *our_privkey,
                                 const uint8_t *recipient_pubkey,
                                 char *event_json, size_t max_len) {
    cJSON *root = cJSON_CreateObject();
    if (!root) return -1;

    cJSON_AddNumberToObject(root, "kind", NIP46_KIND_NOSTR_CONNECT);

    cJSON *tags = cJSON_AddArrayToObject(root, "tags");
    cJSON *p_tag = cJSON_CreateArray();
    cJSON_AddItemToArray(p_tag, cJSON_CreateString("p"));
    char recip_hex[65];
    bytes_to_hex(recipient_pubkey, 32, recip_hex, sizeof(recip_hex));
    cJSON_AddItemToArray(p_tag, cJSON_CreateString(recip_hex));
    cJSON_AddItemToArray(tags, p_tag);

    cJSON *content_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(content_obj, "id", response->id);
    if (response->error) {
        cJSON_AddStringToObject(content_obj, "error", response->error);
    } else if (response->result) {
        cJSON *result_json = cJSON_Parse(response->result);
        if (result_json) {
            cJSON_AddItemToObject(content_obj, "result", result_json);
        } else {
            cJSON_AddStringToObject(content_obj, "result", response->result);
        }
    } else {
        cJSON_AddStringToObject(content_obj, "error", "internal error: empty response");
    }

    char *content_str = cJSON_PrintUnformatted(content_obj);
    cJSON_Delete(content_obj);
    if (!content_str) {
        cJSON_Delete(root);
        return -2;
    }

    char *encrypted = nip44_encrypt_content(content_str, our_privkey, recipient_pubkey);
    free(content_str);
    if (!encrypted) {
        cJSON_Delete(root);
        return -3;
    }
    cJSON_AddStringToObject(root, "content", encrypted);
    free(encrypted);

    if (sign_event_json(root, our_privkey) != 0) {
        cJSON_Delete(root);
        return -4;
    }

    cJSON_bool ok = cJSON_PrintPreallocated(root, event_json, (int)max_len, 0);
    cJSON_Delete(root);
    return ok ? 0 : -1;
}

void frost_nip46_request_free(nip46_request_t *request) {
    if (request && request->params) {
        free(request->params);
        request->params = NULL;
        request->params_len = 0;
    }
}
