// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "nostr_frost.h"
#include "nostr_frost_internal.h"
#include "hex_utils.h"
#include "crypto_asm.h"
#include "cJSON.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <limits.h>

int frost_parse_sign_request(const char *event_json, const frost_group_t *group,
                             const uint8_t *our_privkey, frost_sign_request_t *request) {
    memset(request, 0, sizeof(*request));

    cJSON *root = cJSON_Parse(event_json);
    if (!root)
        return -1;

    cJSON *kind = cJSON_GetObjectItem(root, "kind");
    if (!kind || !cJSON_IsNumber(kind) || kind->valueint != FROST_KIND_SIGN_REQUEST) {
        cJSON_Delete(root);
        return -2;
    }

    cJSON *tags = cJSON_GetObjectItem(root, "tags");
    if (cJSON_IsArray(tags)) {
        int size = cJSON_GetArraySize(tags);
        for (int i = 0; i < size; i++) {
            cJSON *tag = cJSON_GetArrayItem(tags, i);
            if (!cJSON_IsArray(tag) || cJSON_GetArraySize(tag) < 2)
                continue;

            cJSON *tag_name = cJSON_GetArrayItem(tag, 0);
            cJSON *tag_val = cJSON_GetArrayItem(tag, 1);
            if (!cJSON_IsString(tag_name) || !cJSON_IsString(tag_val))
                continue;

            const char *name = tag_name->valuestring;
            const char *val = tag_val->valuestring;

            if (strcmp(name, "e") == 0) {
                int tag_size = cJSON_GetArraySize(tag);
                if (tag_size >= 4) {
                    cJSON *marker = cJSON_GetArrayItem(tag, 3);
                    if (cJSON_IsString(marker) && strcmp(marker->valuestring, "root") == 0) {
                        hex_to_bytes(val, request->group_id, GROUP_ID_LEN);
                    }
                }
            } else if (strcmp(name, "request_id") == 0) {
                hex_to_bytes(val, request->request_id, 32);
            } else if (strcmp(name, "message_type") == 0) {
                if (strcmp(val, "psbt") == 0)
                    request->message_type = FROST_MSG_TYPE_PSBT;
                else if (strcmp(val, "nostr_event") == 0)
                    request->message_type = FROST_MSG_TYPE_NOSTR_EVENT;
                else
                    request->message_type = FROST_MSG_TYPE_RAW;
            } else if (strcmp(name, "policy_hash") == 0) {
                hex_to_bytes(val, request->policy_hash, 32);
                request->has_policy = true;
            }
        }
    }

    uint8_t sender_pubkey[32] = {0};
    cJSON *pubkey = cJSON_GetObjectItem(root, "pubkey");
    if (pubkey && cJSON_IsString(pubkey)) {
        if (hex_to_bytes(pubkey->valuestring, sender_pubkey, 32) != 32) {
            cJSON_Delete(root);
            return -6;
        }
    }

    cJSON *content = cJSON_GetObjectItem(root, "content");
    if (content && cJSON_IsString(content)) {
        const char *enc = content->valuestring;
        size_t enc_len = strlen(enc);
        if (enc_len > 0) {
            char *decrypted = nip44_decrypt_content(enc, our_privkey, sender_pubkey);
            const char *to_parse = decrypted ? decrypted : enc;

            cJSON *inner = cJSON_Parse(to_parse);
            if (inner) {
                cJSON *payload_hex = cJSON_GetObjectItem(inner, "payload");
                if (payload_hex && cJSON_IsString(payload_hex)) {
                    size_t hex_len = strlen(payload_hex->valuestring);
                    if (hex_len / 2 + 1 > MAX_SIGN_PAYLOAD_SIZE) {
                        cJSON_Delete(inner);
                        free(decrypted);
                        cJSON_Delete(root);
                        return -7;
                    }
                    int decoded = hex_to_bytes(payload_hex->valuestring, request->payload,
                                               hex_len / 2 + 1);
                    if (decoded > 0) {
                        request->payload_len = (size_t)decoded;
                    }
                }
                cJSON *nonce_idx = cJSON_GetObjectItem(inner, "nonce_index");
                if (nonce_idx && cJSON_IsNumber(nonce_idx)) {
                    request->nonce_index = (uint32_t)nonce_idx->valueint;
                }
                cJSON_Delete(inner);
            }
            free(decrypted);
        }
    }

    (void)group;
    cJSON_Delete(root);
    return 0;
}

int frost_create_sign_request(const frost_group_t *group, const frost_sign_request_t *request,
                              const uint8_t *privkey, char *event_json, size_t max_len) {
    cJSON *root = cJSON_CreateObject();
    if (!root)
        return -1;

    cJSON_AddNumberToObject(root, "kind", FROST_KIND_SIGN_REQUEST);

    cJSON *tags = cJSON_AddArrayToObject(root, "tags");

    char gid_hex[65];
    bytes_to_hex(request->group_id, 32, gid_hex, sizeof(gid_hex));
    cJSON *e_tag = cJSON_CreateArray();
    cJSON_AddItemToArray(e_tag, cJSON_CreateString("e"));
    cJSON_AddItemToArray(e_tag, cJSON_CreateString(gid_hex));
    cJSON_AddItemToArray(e_tag, cJSON_CreateString(""));
    cJSON_AddItemToArray(e_tag, cJSON_CreateString("root"));
    cJSON_AddItemToArray(tags, e_tag);

    for (int i = 0; i < group->participant_count; i++) {
        cJSON *p_tag = cJSON_CreateArray();
        cJSON_AddItemToArray(p_tag, cJSON_CreateString("p"));
        char npub_hex[65];
        bytes_to_hex(group->participants[i].npub, 32, npub_hex, sizeof(npub_hex));
        cJSON_AddItemToArray(p_tag, cJSON_CreateString(npub_hex));
        cJSON_AddItemToArray(tags, p_tag);
    }

    char rid_hex[65];
    bytes_to_hex(request->request_id, 32, rid_hex, sizeof(rid_hex));
    cJSON *rid_tag = cJSON_CreateArray();
    cJSON_AddItemToArray(rid_tag, cJSON_CreateString("request_id"));
    cJSON_AddItemToArray(rid_tag, cJSON_CreateString(rid_hex));
    cJSON_AddItemToArray(tags, rid_tag);

    const char *msg_type_str;
    switch (request->message_type) {
    case FROST_MSG_TYPE_PSBT:
        msg_type_str = "psbt";
        break;
    case FROST_MSG_TYPE_NOSTR_EVENT:
        msg_type_str = "nostr_event";
        break;
    default:
        msg_type_str = "raw";
        break;
    }
    cJSON *mt_tag = cJSON_CreateArray();
    cJSON_AddItemToArray(mt_tag, cJSON_CreateString("message_type"));
    cJSON_AddItemToArray(mt_tag, cJSON_CreateString(msg_type_str));
    cJSON_AddItemToArray(tags, mt_tag);

    if (request->has_policy) {
        char ph_hex[65];
        bytes_to_hex(request->policy_hash, 32, ph_hex, sizeof(ph_hex));
        cJSON *ph_tag = cJSON_CreateArray();
        cJSON_AddItemToArray(ph_tag, cJSON_CreateString("policy_hash"));
        cJSON_AddItemToArray(ph_tag, cJSON_CreateString(ph_hex));
        cJSON_AddItemToArray(tags, ph_tag);
    }

    cJSON *content_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(content_obj, "message_type", msg_type_str);
    cJSON_AddStringToObject(content_obj, "request_id", rid_hex);
    if (request->payload_len > 0 && request->payload_len <= MAX_SIGN_PAYLOAD_SIZE) {
        char payload_hex[MAX_SIGN_PAYLOAD_SIZE * 2 + 1];
        bytes_to_hex(request->payload, request->payload_len, payload_hex, sizeof(payload_hex));
        cJSON_AddStringToObject(content_obj, "payload", payload_hex);
    }
    cJSON_AddNumberToObject(content_obj, "nonce_index", request->nonce_index);

    char *content_str = cJSON_PrintUnformatted(content_obj);
    cJSON_Delete(content_obj);

    if (!content_str) {
        cJSON_Delete(root);
        return -3;
    }

    if (group->participant_count > 0) {
        char *encrypted = nip44_encrypt_content(content_str, privkey, group->coordinator_npub);
        free(content_str);
        if (!encrypted) {
            cJSON_Delete(root);
            return -4;
        }
        cJSON_AddStringToObject(root, "content", encrypted);
        free(encrypted);
    } else {
        cJSON_AddStringToObject(root, "content", content_str);
        free(content_str);
    }

    if (sign_event_json(root, privkey) != 0) {
        cJSON_Delete(root);
        return -5;
    }

    if (max_len > (size_t)INT_MAX)
        max_len = (size_t)INT_MAX;
    cJSON_bool ok = cJSON_PrintPreallocated(root, event_json, (int)max_len, 0);
    cJSON_Delete(root);
    return ok ? 0 : -1;
}

int frost_create_sign_response(const frost_group_t *group, const frost_sign_response_t *response,
                               const uint8_t *privkey, char *event_json, size_t max_len) {
    if (!group || !response || !privkey || !event_json || max_len == 0)
        return -1;

    cJSON *root = cJSON_CreateObject();
    if (!root)
        return -1;

    cJSON_AddNumberToObject(root, "kind", FROST_KIND_SIGN_RESPONSE);

    cJSON *tags = cJSON_AddArrayToObject(root, "tags");

    char gid_hex[65];
    bytes_to_hex(group->group_id, 32, gid_hex, sizeof(gid_hex));
    cJSON *e_tag = cJSON_CreateArray();
    cJSON_AddItemToArray(e_tag, cJSON_CreateString("e"));
    cJSON_AddItemToArray(e_tag, cJSON_CreateString(gid_hex));
    cJSON_AddItemToArray(e_tag, cJSON_CreateString(""));
    cJSON_AddItemToArray(e_tag, cJSON_CreateString("root"));
    cJSON_AddItemToArray(tags, e_tag);

    char rid_hex[65];
    bytes_to_hex(response->request_id, 32, rid_hex, sizeof(rid_hex));
    cJSON *rid_tag = cJSON_CreateArray();
    cJSON_AddItemToArray(rid_tag, cJSON_CreateString("request_id"));
    cJSON_AddItemToArray(rid_tag, cJSON_CreateString(rid_hex));
    cJSON_AddItemToArray(tags, rid_tag);

    char idx_str[8];
    snprintf(idx_str, sizeof(idx_str), "%d", response->participant_index);
    cJSON *idx_tag = cJSON_CreateArray();
    cJSON_AddItemToArray(idx_tag, cJSON_CreateString("participant_index"));
    cJSON_AddItemToArray(idx_tag, cJSON_CreateString(idx_str));
    cJSON_AddItemToArray(tags, idx_tag);

    const char *status_str;
    switch (response->status) {
    case FROST_SIGN_STATUS_REJECTED:
        status_str = "rejected";
        break;
    case FROST_SIGN_STATUS_PENDING:
        status_str = "pending";
        break;
    case FROST_SIGN_STATUS_TIMEOUT:
        status_str = "timeout";
        break;
    default:
        status_str = "signed";
        break;
    }
    cJSON *st_tag = cJSON_CreateArray();
    cJSON_AddItemToArray(st_tag, cJSON_CreateString("status"));
    cJSON_AddItemToArray(st_tag, cJSON_CreateString(status_str));
    cJSON_AddItemToArray(tags, st_tag);

    cJSON *content_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(content_obj, "request_id", rid_hex);
    cJSON_AddNumberToObject(content_obj, "participant_index", response->participant_index);

    if (response->status == FROST_SIGN_STATUS_SIGNED) {
        char sig_hex[65];
        bytes_to_hex(response->partial_signature, 32, sig_hex, sizeof(sig_hex));
        cJSON_AddStringToObject(content_obj, "partial_signature", sig_hex);
        char nc_hex[67];
        bytes_to_hex(response->nonce_commitment, 33, nc_hex, sizeof(nc_hex));
        cJSON_AddStringToObject(content_obj, "nonce_commitment", nc_hex);
    } else if (response->status == FROST_SIGN_STATUS_REJECTED) {
        cJSON_AddStringToObject(content_obj, "status", "rejected");
        cJSON_AddStringToObject(content_obj, "reason", response->rejection_reason);
    }

    char *content_str = cJSON_PrintUnformatted(content_obj);
    cJSON_Delete(content_obj);
    if (!content_str) {
        cJSON_Delete(root);
        return -3;
    }

    char *encrypted = nip44_encrypt_content(content_str, privkey, group->coordinator_npub);
    free(content_str);
    if (!encrypted) {
        cJSON_Delete(root);
        return -4;
    }
    cJSON_AddStringToObject(root, "content", encrypted);
    free(encrypted);

    if (sign_event_json(root, privkey) != 0) {
        cJSON_Delete(root);
        return -5;
    }

    if (max_len > (size_t)INT_MAX)
        max_len = (size_t)INT_MAX;
    cJSON_bool ok = cJSON_PrintPreallocated(root, event_json, (int)max_len, 0);
    cJSON_Delete(root);
    return ok ? 0 : -1;
}

int frost_parse_sign_response(const char *event_json, const frost_group_t *group,
                              const uint8_t *our_privkey, frost_sign_response_t *response) {
    memset(response, 0, sizeof(*response));

    cJSON *root = cJSON_Parse(event_json);
    if (!root)
        return -1;

    cJSON *kind = cJSON_GetObjectItem(root, "kind");
    if (!kind || !cJSON_IsNumber(kind) || kind->valueint != FROST_KIND_SIGN_RESPONSE) {
        cJSON_Delete(root);
        return -2;
    }

    cJSON *tags = cJSON_GetObjectItem(root, "tags");
    if (cJSON_IsArray(tags)) {
        int size = cJSON_GetArraySize(tags);
        for (int i = 0; i < size; i++) {
            cJSON *tag = cJSON_GetArrayItem(tags, i);
            if (!cJSON_IsArray(tag) || cJSON_GetArraySize(tag) < 2)
                continue;

            cJSON *tag_name = cJSON_GetArrayItem(tag, 0);
            cJSON *tag_val = cJSON_GetArrayItem(tag, 1);
            if (!cJSON_IsString(tag_name) || !cJSON_IsString(tag_val))
                continue;

            const char *name = tag_name->valuestring;
            const char *val = tag_val->valuestring;

            if (strcmp(name, "request_id") == 0) {
                hex_to_bytes(val, response->request_id, 32);
            } else if (strcmp(name, "participant_index") == 0) {
                char *endptr;
                long tmp = strtol(val, &endptr, 10);
                if (endptr != val && *endptr == '\0' && tmp > 0 && tmp <= UINT8_MAX) {
                    response->participant_index = (uint8_t)tmp;
                }
            } else if (strcmp(name, "status") == 0) {
                if (strcmp(val, "rejected") == 0)
                    response->status = FROST_SIGN_STATUS_REJECTED;
                else if (strcmp(val, "pending") == 0)
                    response->status = FROST_SIGN_STATUS_PENDING;
                else if (strcmp(val, "timeout") == 0)
                    response->status = FROST_SIGN_STATUS_TIMEOUT;
                else
                    response->status = FROST_SIGN_STATUS_SIGNED;
            }
        }
    }

    uint8_t sender_pubkey[32] = {0};
    cJSON *pubkey_obj = cJSON_GetObjectItem(root, "pubkey");
    if (pubkey_obj && cJSON_IsString(pubkey_obj)) {
        if (hex_to_bytes(pubkey_obj->valuestring, sender_pubkey, 32) != 32) {
            cJSON_Delete(root);
            return -6;
        }
    }

    cJSON *content = cJSON_GetObjectItem(root, "content");
    if (content && cJSON_IsString(content)) {
        const char *content_str = content->valuestring;
        char *decrypted = nip44_decrypt_content(content_str, our_privkey, sender_pubkey);
        const char *to_parse = decrypted ? decrypted : content_str;

        cJSON *inner = cJSON_Parse(to_parse);
        if (inner) {
            cJSON *psig = cJSON_GetObjectItem(inner, "partial_signature");
            if (psig && cJSON_IsString(psig)) {
                if (hex_to_bytes(psig->valuestring, response->partial_signature, 32) != 32) {
                    memset(response->partial_signature, 0, 32);
                }
            }
            cJSON *nc = cJSON_GetObjectItem(inner, "nonce_commitment");
            if (nc && cJSON_IsString(nc)) {
                if (hex_to_bytes(nc->valuestring, response->nonce_commitment, 33) != 33) {
                    memset(response->nonce_commitment, 0, 33);
                }
            }
            cJSON *reason = cJSON_GetObjectItem(inner, "reason");
            if (reason && cJSON_IsString(reason)) {
                strncpy(response->rejection_reason, reason->valuestring,
                        sizeof(response->rejection_reason) - 1);
            }
            cJSON_Delete(inner);
        }
        free(decrypted);
    }

    (void)group;
    cJSON_Delete(root);
    return 0;
}

void frost_sign_request_free(frost_sign_request_t *request) {
    if (request) {
        secure_memzero(request->payload, sizeof(request->payload));
        request->payload_len = 0;
    }
}
