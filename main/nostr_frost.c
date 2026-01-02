#include "nostr_frost.h"
#include "nostr.h"
#include "cJSON.h"
#include "crypto_asm.h"
#include <secp256k1.h>
#include <secp256k1_frost.h>
#include <mbedtls/sha256.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifdef ESP_PLATFORM
#include "esp_random.h"
#else
static int secure_random_fill(uint8_t *buf, size_t len) {
    FILE *fp = fopen("/dev/urandom", "r");
    if (!fp) return -1;
    size_t total = 0;
    while (total < len) {
        size_t n = fread(buf + total, 1, len - total, fp);
        if (n == 0) { fclose(fp); return -1; }
        total += n;
    }
    fclose(fp);
    return 0;
}
#endif

static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > out_len) return -1;
    for (size_t i = 0; i < hex_len / 2; i++) {
        int hi = hex_digit(hex[2*i]);
        int lo = hex_digit(hex[2*i+1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(hex_len / 2);
}

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(out + 2*i, "%02x", bytes[i]);
    }
    out[len*2] = '\0';
}

static int compute_event_id(cJSON *event, uint8_t id_out[32]) {
    cJSON *pubkey = cJSON_GetObjectItem(event, "pubkey");
    cJSON *created_at = cJSON_GetObjectItem(event, "created_at");
    cJSON *kind = cJSON_GetObjectItem(event, "kind");
    cJSON *tags = cJSON_GetObjectItem(event, "tags");
    cJSON *content = cJSON_GetObjectItem(event, "content");
    if (!pubkey || !created_at || !kind || !tags || !content) return -1;

    cJSON *arr = cJSON_CreateArray();
    cJSON_AddItemToArray(arr, cJSON_CreateNumber(0));
    cJSON_AddItemToArray(arr, cJSON_CreateString(pubkey->valuestring));
    cJSON_AddItemToArray(arr, cJSON_CreateNumber(created_at->valuedouble));
    cJSON_AddItemToArray(arr, cJSON_CreateNumber(kind->valueint));
    cJSON_AddItemToArray(arr, cJSON_Duplicate(tags, 1));
    cJSON_AddItemToArray(arr, cJSON_CreateString(content->valuestring));

    char *serialized = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    if (!serialized) return -1;

    mbedtls_sha256((uint8_t *)serialized, strlen(serialized), id_out, 0);
    free(serialized);
    return 0;
}

static int sign_event_json(cJSON *event, const uint8_t privkey[32]) {
    nostr_privkey priv;
    nostr_key pub;
    memcpy(priv.data, privkey, 32);

    if (nostr_key_generate(&priv, &pub) != NOSTR_OK) {
        nostr_keypair kp;
        if (nostr_keypair_from_private_key(&kp, &priv) != NOSTR_OK) {
            secure_wipe(&priv, sizeof(priv));
            return -1;
        }
        memcpy(pub.data, kp.pubkey.data, 32);
        nostr_keypair_destroy(&kp);
    }

    char pubkey_hex[65];
    bytes_to_hex(pub.data, 32, pubkey_hex);
    cJSON_DeleteItemFromObject(event, "pubkey");
    cJSON_AddStringToObject(event, "pubkey", pubkey_hex);

    if (!cJSON_GetObjectItem(event, "created_at")) {
        cJSON_AddNumberToObject(event, "created_at", (double)time(NULL));
    }

    uint8_t id[32];
    if (compute_event_id(event, id) != 0) {
        secure_wipe(&priv, sizeof(priv));
        return -2;
    }

    char id_hex[65];
    bytes_to_hex(id, 32, id_hex);
    cJSON_DeleteItemFromObject(event, "id");
    cJSON_AddStringToObject(event, "id", id_hex);

    nostr_event *ev = NULL;
    char *json_str = cJSON_PrintUnformatted(event);
    if (!json_str || nostr_event_from_json(json_str, &ev) != NOSTR_OK) {
        free(json_str);
        secure_wipe(&priv, sizeof(priv));
        return -3;
    }
    free(json_str);

    if (nostr_event_sign(ev, &priv) != NOSTR_OK) {
        nostr_event_destroy(ev);
        secure_wipe(&priv, sizeof(priv));
        return -4;
    }
    secure_wipe(&priv, sizeof(priv));

    char sig_hex[129];
    bytes_to_hex(ev->sig, 64, sig_hex);
    cJSON_DeleteItemFromObject(event, "sig");
    cJSON_AddStringToObject(event, "sig", sig_hex);

    char new_id_hex[65];
    bytes_to_hex(ev->id, 32, new_id_hex);
    cJSON_DeleteItemFromObject(event, "id");
    cJSON_AddStringToObject(event, "id", new_id_hex);

    nostr_event_destroy(ev);
    return 0;
}

static char *nip44_encrypt_content(const char *plaintext, const uint8_t sender_priv[32],
                                    const uint8_t recipient_pub[32]) {
    nostr_privkey priv;
    nostr_key pub;
    memcpy(priv.data, sender_priv, 32);
    memcpy(pub.data, recipient_pub, 32);

    char *ciphertext = NULL;
    if (nostr_nip44_encrypt(&priv, &pub, plaintext, strlen(plaintext), &ciphertext) != NOSTR_OK) {
        secure_wipe(&priv, sizeof(priv));
        return NULL;
    }
    secure_wipe(&priv, sizeof(priv));
    return ciphertext;
}

static char *nip44_decrypt_content(const char *ciphertext, const uint8_t recipient_priv[32],
                                    const uint8_t sender_pub[32]) {
    nostr_privkey priv;
    nostr_key pub;
    memcpy(priv.data, recipient_priv, 32);
    memcpy(pub.data, sender_pub, 32);

    char *plaintext = NULL;
    size_t plaintext_len = 0;
    if (nostr_nip44_decrypt(&priv, &pub, ciphertext, &plaintext, &plaintext_len) != NOSTR_OK) {
        secure_wipe(&priv, sizeof(priv));
        return NULL;
    }
    secure_wipe(&priv, sizeof(priv));
    return plaintext;
}

static int parse_tags(cJSON *tags, frost_group_t *group) {
    if (!cJSON_IsArray(tags)) return -1;

    int size = cJSON_GetArraySize(tags);
    for (int i = 0; i < size; i++) {
        cJSON *tag = cJSON_GetArrayItem(tags, i);
        if (!cJSON_IsArray(tag) || cJSON_GetArraySize(tag) < 2) continue;

        cJSON *tag_name = cJSON_GetArrayItem(tag, 0);
        cJSON *tag_val = cJSON_GetArrayItem(tag, 1);
        if (!cJSON_IsString(tag_name) || !cJSON_IsString(tag_val)) continue;

        const char *name = tag_name->valuestring;
        const char *val = tag_val->valuestring;

        if (strcmp(name, "d") == 0) {
            hex_to_bytes(val, group->group_id, GROUP_ID_LEN);
        } else if (strcmp(name, "threshold") == 0) {
            group->threshold = (uint8_t)atoi(val);
        } else if (strcmp(name, "participants") == 0) {
            group->participant_count = (uint8_t)atoi(val);
        } else if (strcmp(name, "relay") == 0) {
            if (group->relay_count < MAX_RELAYS) {
                strncpy(group->relays[group->relay_count], val, RELAY_URL_LEN - 1);
                group->relays[group->relay_count][RELAY_URL_LEN - 1] = '\0';
                group->relay_count++;
            }
        } else if (strcmp(name, "p") == 0) {
            int tag_size = cJSON_GetArraySize(tag);
            if (tag_size >= 2) {
                frost_participant_t *p = NULL;
                for (int j = 0; j < MAX_GROUP_PARTICIPANTS; j++) {
                    if (group->participants[j].index == 0) {
                        p = &group->participants[j];
                        break;
                    }
                }
                if (!p) continue;

                memset(p, 0, sizeof(*p));
                hex_to_bytes(val, p->npub, 32);
                if (tag_size >= 3) {
                    cJSON *relay = cJSON_GetArrayItem(tag, 2);
                    if (cJSON_IsString(relay)) {
                        strncpy(p->relay_hint, relay->valuestring, RELAY_URL_LEN - 1);
                        p->relay_hint[RELAY_URL_LEN - 1] = '\0';
                    }
                }
                if (tag_size >= 4) {
                    cJSON *idx = cJSON_GetArrayItem(tag, 3);
                    if (cJSON_IsString(idx)) {
                        p->index = (uint8_t)atoi(idx->valuestring);
                    }
                }
                if (p->index == 0) {
                    p->index = group->participant_count + 1;
                }
                group->participant_count++;
            }
        } else if (strcmp(name, "notification_pubkey") == 0) {
            hex_to_bytes(val, group->notification_pubkey, 32);
            group->has_notification_key = true;
        }
    }
    return 0;
}

int frost_parse_group_event(const char *event_json, frost_group_t *group) {
    memset(group, 0, sizeof(*group));

    cJSON *root = cJSON_Parse(event_json);
    if (!root) return -1;

    cJSON *kind = cJSON_GetObjectItem(root, "kind");
    if (!kind || !cJSON_IsNumber(kind) || kind->valueint != FROST_KIND_GROUP) {
        cJSON_Delete(root);
        return -2;
    }

    cJSON *pubkey = cJSON_GetObjectItem(root, "pubkey");
    if (pubkey && cJSON_IsString(pubkey)) {
        hex_to_bytes(pubkey->valuestring, group->coordinator_npub, 32);
    }

    cJSON *tags = cJSON_GetObjectItem(root, "tags");
    if (tags) {
        parse_tags(tags, group);
    }

    cJSON_Delete(root);
    return 0;
}

int frost_create_group_event(const frost_group_t *group,
                              const uint8_t *privkey,
                              char *event_json, size_t max_len) {
    cJSON *root = cJSON_CreateObject();
    if (!root) return -1;

    cJSON_AddNumberToObject(root, "kind", FROST_KIND_GROUP);

    char pubkey_hex[65];
    bytes_to_hex(group->coordinator_npub, 32, pubkey_hex);
    cJSON_AddStringToObject(root, "pubkey", pubkey_hex);

    cJSON *tags = cJSON_AddArrayToObject(root, "tags");

    char id_hex[65];
    bytes_to_hex(group->group_id, 32, id_hex);
    cJSON *d_tag = cJSON_CreateArray();
    cJSON_AddItemToArray(d_tag, cJSON_CreateString("d"));
    cJSON_AddItemToArray(d_tag, cJSON_CreateString(id_hex));
    cJSON_AddItemToArray(tags, d_tag);

    char threshold_str[8];
    snprintf(threshold_str, sizeof(threshold_str), "%d", group->threshold);
    cJSON *t_tag = cJSON_CreateArray();
    cJSON_AddItemToArray(t_tag, cJSON_CreateString("threshold"));
    cJSON_AddItemToArray(t_tag, cJSON_CreateString(threshold_str));
    cJSON_AddItemToArray(tags, t_tag);

    char pcount_str[8];
    snprintf(pcount_str, sizeof(pcount_str), "%d", group->participant_count);
    cJSON *p_tag = cJSON_CreateArray();
    cJSON_AddItemToArray(p_tag, cJSON_CreateString("participants"));
    cJSON_AddItemToArray(p_tag, cJSON_CreateString(pcount_str));
    cJSON_AddItemToArray(tags, p_tag);

    for (int i = 0; i < group->participant_count; i++) {
        const frost_participant_t *part = &group->participants[i];
        cJSON *ptag = cJSON_CreateArray();
        cJSON_AddItemToArray(ptag, cJSON_CreateString("p"));
        char npub_hex[65];
        bytes_to_hex(part->npub, 32, npub_hex);
        cJSON_AddItemToArray(ptag, cJSON_CreateString(npub_hex));
        cJSON_AddItemToArray(ptag, cJSON_CreateString(part->relay_hint));
        char idx_str[8];
        snprintf(idx_str, sizeof(idx_str), "%d", part->index);
        cJSON_AddItemToArray(ptag, cJSON_CreateString(idx_str));
        cJSON_AddItemToArray(tags, ptag);
    }

    for (int i = 0; i < group->relay_count; i++) {
        cJSON *rtag = cJSON_CreateArray();
        cJSON_AddItemToArray(rtag, cJSON_CreateString("relay"));
        cJSON_AddItemToArray(rtag, cJSON_CreateString(group->relays[i]));
        cJSON_AddItemToArray(tags, rtag);
    }

    if (group->has_notification_key) {
        cJSON *ntag = cJSON_CreateArray();
        cJSON_AddItemToArray(ntag, cJSON_CreateString("notification_pubkey"));
        char npk_hex[65];
        bytes_to_hex(group->notification_pubkey, 32, npk_hex);
        cJSON_AddItemToArray(ntag, cJSON_CreateString(npk_hex));
        cJSON_AddItemToArray(tags, ntag);
    }

    cJSON_AddStringToObject(root, "content", "");

    if (sign_event_json(root, privkey) != 0) {
        cJSON_Delete(root);
        return -2;
    }

    cJSON_bool ok = cJSON_PrintPreallocated(root, event_json, (int)max_len, 0);
    cJSON_Delete(root);
    return ok ? 0 : -1;
}

int frost_get_our_index(const frost_group_t *group, const uint8_t our_npub[32]) {
    for (int i = 0; i < group->participant_count; i++) {
        if (ct_compare(group->participants[i].npub, our_npub, 32) == 0) {
            return group->participants[i].index;
        }
    }
    return -1;
}

int frost_parse_sign_request(const char *event_json,
                              const frost_group_t *group,
                              const uint8_t *our_privkey,
                              frost_sign_request_t *request) {
    memset(request, 0, sizeof(*request));

    cJSON *root = cJSON_Parse(event_json);
    if (!root) return -1;

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
            if (!cJSON_IsArray(tag) || cJSON_GetArraySize(tag) < 2) continue;

            cJSON *tag_name = cJSON_GetArrayItem(tag, 0);
            cJSON *tag_val = cJSON_GetArrayItem(tag, 1);
            if (!cJSON_IsString(tag_name) || !cJSON_IsString(tag_val)) continue;

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
                if (strcmp(val, "psbt") == 0) {
                    request->message_type = FROST_MSG_TYPE_PSBT;
                } else if (strcmp(val, "nostr_event") == 0) {
                    request->message_type = FROST_MSG_TYPE_NOSTR_EVENT;
                } else {
                    request->message_type = FROST_MSG_TYPE_RAW;
                }
            } else if (strcmp(name, "policy_hash") == 0) {
                hex_to_bytes(val, request->policy_hash, 32);
                request->has_policy = true;
            }
        }
    }

    uint8_t sender_pubkey[32] = {0};
    cJSON *pubkey = cJSON_GetObjectItem(root, "pubkey");
    if (pubkey && cJSON_IsString(pubkey)) {
        hex_to_bytes(pubkey->valuestring, sender_pubkey, 32);
    }

    cJSON *content = cJSON_GetObjectItem(root, "content");
    if (content && cJSON_IsString(content)) {
        const char *enc = content->valuestring;
        size_t enc_len = strlen(enc);
        if (enc_len > 0) {
            char *decrypted = nip44_decrypt_content(enc, our_privkey, sender_pubkey);
            if (decrypted) {
                cJSON *inner = cJSON_Parse(decrypted);
                if (inner) {
                    cJSON *payload_hex = cJSON_GetObjectItem(inner, "payload");
                    if (payload_hex && cJSON_IsString(payload_hex)) {
                        size_t hex_len = strlen(payload_hex->valuestring);
                        request->payload = malloc(hex_len / 2 + 1);
                        if (request->payload) {
                            int decoded = hex_to_bytes(payload_hex->valuestring, request->payload, hex_len / 2 + 1);
                            if (decoded > 0) {
                                request->payload_len = (size_t)decoded;
                            } else {
                                free(request->payload);
                                request->payload = NULL;
                            }
                        }
                    }
                    cJSON *nonce_idx = cJSON_GetObjectItem(inner, "nonce_index");
                    if (nonce_idx && cJSON_IsNumber(nonce_idx)) {
                        request->nonce_index = (uint32_t)nonce_idx->valueint;
                    }
                    cJSON_Delete(inner);
                }
                free(decrypted);
            } else {
                cJSON *inner = cJSON_Parse(enc);
                if (inner) {
                    cJSON *payload_hex = cJSON_GetObjectItem(inner, "payload");
                    if (payload_hex && cJSON_IsString(payload_hex)) {
                        size_t hex_len = strlen(payload_hex->valuestring);
                        request->payload = malloc(hex_len / 2 + 1);
                        if (request->payload) {
                            int decoded = hex_to_bytes(payload_hex->valuestring, request->payload, hex_len / 2 + 1);
                            if (decoded > 0) {
                                request->payload_len = (size_t)decoded;
                            } else {
                                free(request->payload);
                                request->payload = NULL;
                            }
                        }
                    }
                    cJSON_Delete(inner);
                }
            }
        }
    }

    (void)group;

    cJSON_Delete(root);
    return 0;
}

int frost_create_sign_request(const frost_group_t *group,
                               const frost_sign_request_t *request,
                               const uint8_t *privkey,
                               char *event_json, size_t max_len) {
    cJSON *root = cJSON_CreateObject();
    if (!root) return -1;

    cJSON_AddNumberToObject(root, "kind", FROST_KIND_SIGN_REQUEST);

    cJSON *tags = cJSON_AddArrayToObject(root, "tags");

    char gid_hex[65];
    bytes_to_hex(request->group_id, 32, gid_hex);
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
        bytes_to_hex(group->participants[i].npub, 32, npub_hex);
        cJSON_AddItemToArray(p_tag, cJSON_CreateString(npub_hex));
        cJSON_AddItemToArray(tags, p_tag);
    }

    char rid_hex[65];
    bytes_to_hex(request->request_id, 32, rid_hex);
    cJSON *rid_tag = cJSON_CreateArray();
    cJSON_AddItemToArray(rid_tag, cJSON_CreateString("request_id"));
    cJSON_AddItemToArray(rid_tag, cJSON_CreateString(rid_hex));
    cJSON_AddItemToArray(tags, rid_tag);

    const char *msg_type_str = "raw";
    if (request->message_type == FROST_MSG_TYPE_PSBT) {
        msg_type_str = "psbt";
    } else if (request->message_type == FROST_MSG_TYPE_NOSTR_EVENT) {
        msg_type_str = "nostr_event";
    }
    cJSON *mt_tag = cJSON_CreateArray();
    cJSON_AddItemToArray(mt_tag, cJSON_CreateString("message_type"));
    cJSON_AddItemToArray(mt_tag, cJSON_CreateString(msg_type_str));
    cJSON_AddItemToArray(tags, mt_tag);

    if (request->has_policy) {
        char ph_hex[65];
        bytes_to_hex(request->policy_hash, 32, ph_hex);
        cJSON *ph_tag = cJSON_CreateArray();
        cJSON_AddItemToArray(ph_tag, cJSON_CreateString("policy_hash"));
        cJSON_AddItemToArray(ph_tag, cJSON_CreateString(ph_hex));
        cJSON_AddItemToArray(tags, ph_tag);
    }

    cJSON *content_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(content_obj, "message_type", msg_type_str);
    cJSON_AddStringToObject(content_obj, "request_id", rid_hex);
    if (request->payload && request->payload_len > 0) {
        char *payload_hex = malloc(request->payload_len * 2 + 1);
        if (payload_hex) {
            bytes_to_hex(request->payload, request->payload_len, payload_hex);
            cJSON_AddStringToObject(content_obj, "payload", payload_hex);
            free(payload_hex);
        }
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

    cJSON_bool ok = cJSON_PrintPreallocated(root, event_json, (int)max_len, 0);
    cJSON_Delete(root);
    return ok ? 0 : -1;
}

int frost_create_sign_response(const frost_group_t *group,
                                const frost_sign_response_t *response,
                                const uint8_t *privkey,
                                char *event_json, size_t max_len) {
    cJSON *root = cJSON_CreateObject();
    if (!root) return -1;

    cJSON_AddNumberToObject(root, "kind", FROST_KIND_SIGN_RESPONSE);

    cJSON *tags = cJSON_AddArrayToObject(root, "tags");

    char gid_hex[65];
    bytes_to_hex(group->group_id, 32, gid_hex);
    cJSON *e_tag = cJSON_CreateArray();
    cJSON_AddItemToArray(e_tag, cJSON_CreateString("e"));
    cJSON_AddItemToArray(e_tag, cJSON_CreateString(gid_hex));
    cJSON_AddItemToArray(e_tag, cJSON_CreateString(""));
    cJSON_AddItemToArray(e_tag, cJSON_CreateString("root"));
    cJSON_AddItemToArray(tags, e_tag);

    char rid_hex[65];
    bytes_to_hex(response->request_id, 32, rid_hex);
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

    const char *status_str = "signed";
    if (response->status == FROST_SIGN_STATUS_REJECTED) {
        status_str = "rejected";
    } else if (response->status == FROST_SIGN_STATUS_PENDING) {
        status_str = "pending";
    } else if (response->status == FROST_SIGN_STATUS_TIMEOUT) {
        status_str = "timeout";
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
        bytes_to_hex(response->partial_signature, 32, sig_hex);
        cJSON_AddStringToObject(content_obj, "partial_signature", sig_hex);
        char nc_hex[67];
        bytes_to_hex(response->nonce_commitment, 33, nc_hex);
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

    cJSON_bool ok = cJSON_PrintPreallocated(root, event_json, (int)max_len, 0);
    cJSON_Delete(root);
    return ok ? 0 : -1;
}

int frost_parse_sign_response(const char *event_json,
                               const frost_group_t *group,
                               const uint8_t *our_privkey,
                               frost_sign_response_t *response) {
    memset(response, 0, sizeof(*response));

    cJSON *root = cJSON_Parse(event_json);
    if (!root) return -1;

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
            if (!cJSON_IsArray(tag) || cJSON_GetArraySize(tag) < 2) continue;

            cJSON *tag_name = cJSON_GetArrayItem(tag, 0);
            cJSON *tag_val = cJSON_GetArrayItem(tag, 1);
            if (!cJSON_IsString(tag_name) || !cJSON_IsString(tag_val)) continue;

            const char *name = tag_name->valuestring;
            const char *val = tag_val->valuestring;

            if (strcmp(name, "request_id") == 0) {
                hex_to_bytes(val, response->request_id, 32);
            } else if (strcmp(name, "participant_index") == 0) {
                response->participant_index = (uint8_t)atoi(val);
            } else if (strcmp(name, "status") == 0) {
                if (strcmp(val, "signed") == 0) {
                    response->status = FROST_SIGN_STATUS_SIGNED;
                } else if (strcmp(val, "rejected") == 0) {
                    response->status = FROST_SIGN_STATUS_REJECTED;
                } else if (strcmp(val, "pending") == 0) {
                    response->status = FROST_SIGN_STATUS_PENDING;
                } else if (strcmp(val, "timeout") == 0) {
                    response->status = FROST_SIGN_STATUS_TIMEOUT;
                }
            }
        }
    }

    uint8_t sender_pubkey[32] = {0};
    cJSON *pubkey_obj = cJSON_GetObjectItem(root, "pubkey");
    if (pubkey_obj && cJSON_IsString(pubkey_obj)) {
        hex_to_bytes(pubkey_obj->valuestring, sender_pubkey, 32);
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
                hex_to_bytes(psig->valuestring, response->partial_signature, 32);
            }
            cJSON *nc = cJSON_GetObjectItem(inner, "nonce_commitment");
            if (nc && cJSON_IsString(nc)) {
                hex_to_bytes(nc->valuestring, response->nonce_commitment, 33);
            }
            cJSON *reason = cJSON_GetObjectItem(inner, "reason");
            if (reason && cJSON_IsString(reason)) {
                strncpy(response->rejection_reason, reason->valuestring, sizeof(response->rejection_reason) - 1);
            }
            cJSON_Delete(inner);
        }
        free(decrypted);
    }

    (void)group;

    cJSON_Delete(root);
    return 0;
}

int frost_create_dkg_round1_event(const frost_group_t *group,
                                   const frost_dkg_round1_t *round1,
                                   const uint8_t *privkey,
                                   char *event_json, size_t max_len) {
    cJSON *root = cJSON_CreateObject();
    if (!root) return -1;

    cJSON_AddNumberToObject(root, "kind", FROST_KIND_DKG_ROUND1);

    cJSON *tags = cJSON_AddArrayToObject(root, "tags");

    char gid_hex[65];
    bytes_to_hex(round1->group_id, 32, gid_hex);
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
        bytes_to_hex(group->participants[i].npub, 32, npub_hex);
        cJSON_AddItemToArray(p_tag, cJSON_CreateString(npub_hex));
        cJSON_AddItemToArray(tags, p_tag);
    }

    char idx_str[8];
    snprintf(idx_str, sizeof(idx_str), "%d", round1->participant_index);
    cJSON *idx_tag = cJSON_CreateArray();
    cJSON_AddItemToArray(idx_tag, cJSON_CreateString("participant_index"));
    cJSON_AddItemToArray(idx_tag, cJSON_CreateString(idx_str));
    cJSON_AddItemToArray(tags, idx_tag);

    cJSON *content_obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(content_obj, "num_coefficients", round1->num_coefficients);
    cJSON *coeffs = cJSON_AddArrayToObject(content_obj, "coefficient_commitments");
    for (uint8_t i = 0; i < round1->num_coefficients; i++) {
        char coeff_hex[129];
        bytes_to_hex(round1->coefficient_commitments[i], 64, coeff_hex);
        cJSON_AddItemToArray(coeffs, cJSON_CreateString(coeff_hex));
    }
    char zkp_r_hex[129];
    bytes_to_hex(round1->zkp_r, 64, zkp_r_hex);
    cJSON_AddStringToObject(content_obj, "zkp_r", zkp_r_hex);
    char zkp_z_hex[65];
    bytes_to_hex(round1->zkp_z, 32, zkp_z_hex);
    cJSON_AddStringToObject(content_obj, "zkp_z", zkp_z_hex);

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

    cJSON_bool ok = cJSON_PrintPreallocated(root, event_json, (int)max_len, 0);
    cJSON_Delete(root);
    return ok ? 0 : -1;
}

int frost_parse_dkg_round1_event(const char *event_json,
                                  const frost_group_t *group,
                                  const uint8_t *our_privkey,
                                  frost_dkg_round1_t *round1) {
    memset(round1, 0, sizeof(*round1));

    cJSON *root = cJSON_Parse(event_json);
    if (!root) return -1;

    cJSON *kind = cJSON_GetObjectItem(root, "kind");
    if (!kind || !cJSON_IsNumber(kind) || kind->valueint != FROST_KIND_DKG_ROUND1) {
        cJSON_Delete(root);
        return -2;
    }

    cJSON *tags = cJSON_GetObjectItem(root, "tags");
    if (cJSON_IsArray(tags)) {
        int size = cJSON_GetArraySize(tags);
        for (int i = 0; i < size; i++) {
            cJSON *tag = cJSON_GetArrayItem(tags, i);
            if (!cJSON_IsArray(tag) || cJSON_GetArraySize(tag) < 2) continue;

            cJSON *tag_name = cJSON_GetArrayItem(tag, 0);
            cJSON *tag_val = cJSON_GetArrayItem(tag, 1);
            if (!cJSON_IsString(tag_name) || !cJSON_IsString(tag_val)) continue;

            const char *name = tag_name->valuestring;
            const char *val = tag_val->valuestring;

            if (strcmp(name, "e") == 0) {
                int tag_size = cJSON_GetArraySize(tag);
                if (tag_size >= 4) {
                    cJSON *marker = cJSON_GetArrayItem(tag, 3);
                    if (cJSON_IsString(marker) && strcmp(marker->valuestring, "root") == 0) {
                        hex_to_bytes(val, round1->group_id, GROUP_ID_LEN);
                    }
                }
            } else if (strcmp(name, "participant_index") == 0) {
                round1->participant_index = (uint8_t)atoi(val);
            }
        }
    }

    uint8_t sender_pubkey[32] = {0};
    cJSON *pubkey_obj = cJSON_GetObjectItem(root, "pubkey");
    if (pubkey_obj && cJSON_IsString(pubkey_obj)) {
        hex_to_bytes(pubkey_obj->valuestring, sender_pubkey, 32);
    }

    cJSON *content = cJSON_GetObjectItem(root, "content");
    if (content && cJSON_IsString(content)) {
        const char *content_str = content->valuestring;
        char *decrypted = nip44_decrypt_content(content_str, our_privkey, sender_pubkey);
        const char *to_parse = decrypted ? decrypted : content_str;

        cJSON *inner = cJSON_Parse(to_parse);
        if (inner) {
            cJSON *num_coeff = cJSON_GetObjectItem(inner, "num_coefficients");
            if (num_coeff && cJSON_IsNumber(num_coeff)) {
                round1->num_coefficients = (uint8_t)num_coeff->valueint;
            }
            cJSON *coeffs = cJSON_GetObjectItem(inner, "coefficient_commitments");
            if (coeffs && cJSON_IsArray(coeffs)) {
                int arr_size = cJSON_GetArraySize(coeffs);
                for (int i = 0; i < arr_size && i < MAX_THRESHOLD; i++) {
                    cJSON *c = cJSON_GetArrayItem(coeffs, i);
                    if (c && cJSON_IsString(c)) {
                        hex_to_bytes(c->valuestring, round1->coefficient_commitments[i], 64);
                    }
                }
            }
            cJSON *zkp_r = cJSON_GetObjectItem(inner, "zkp_r");
            if (zkp_r && cJSON_IsString(zkp_r)) {
                hex_to_bytes(zkp_r->valuestring, round1->zkp_r, 64);
            }
            cJSON *zkp_z = cJSON_GetObjectItem(inner, "zkp_z");
            if (zkp_z && cJSON_IsString(zkp_z)) {
                hex_to_bytes(zkp_z->valuestring, round1->zkp_z, 32);
            }
            cJSON_Delete(inner);
        }
        free(decrypted);
    }

    (void)group;

    cJSON_Delete(root);
    return 0;
}

int frost_create_dkg_round2_event(const frost_group_t *group,
                                   const frost_dkg_round2_t *round2,
                                   const uint8_t *our_privkey,
                                   const uint8_t *recipient_pubkey,
                                   char *event_json, size_t max_len) {
    cJSON *root = cJSON_CreateObject();
    if (!root) return -1;

    cJSON_AddNumberToObject(root, "kind", FROST_KIND_DKG_ROUND2);

    cJSON *tags = cJSON_AddArrayToObject(root, "tags");

    char gid_hex[65];
    bytes_to_hex(round2->group_id, 32, gid_hex);
    cJSON *e_tag = cJSON_CreateArray();
    cJSON_AddItemToArray(e_tag, cJSON_CreateString("e"));
    cJSON_AddItemToArray(e_tag, cJSON_CreateString(gid_hex));
    cJSON_AddItemToArray(e_tag, cJSON_CreateString(""));
    cJSON_AddItemToArray(e_tag, cJSON_CreateString("root"));
    cJSON_AddItemToArray(tags, e_tag);

    cJSON *p_tag = cJSON_CreateArray();
    cJSON_AddItemToArray(p_tag, cJSON_CreateString("p"));
    char recip_hex[65];
    bytes_to_hex(recipient_pubkey, 32, recip_hex);
    cJSON_AddItemToArray(p_tag, cJSON_CreateString(recip_hex));
    cJSON_AddItemToArray(tags, p_tag);

    char si_str[8], ri_str[8];
    snprintf(si_str, sizeof(si_str), "%d", round2->sender_index);
    snprintf(ri_str, sizeof(ri_str), "%d", round2->recipient_index);

    cJSON *si_tag = cJSON_CreateArray();
    cJSON_AddItemToArray(si_tag, cJSON_CreateString("participant_index"));
    cJSON_AddItemToArray(si_tag, cJSON_CreateString(si_str));
    cJSON_AddItemToArray(tags, si_tag);

    cJSON *ri_tag = cJSON_CreateArray();
    cJSON_AddItemToArray(ri_tag, cJSON_CreateString("recipient_index"));
    cJSON_AddItemToArray(ri_tag, cJSON_CreateString(ri_str));
    cJSON_AddItemToArray(tags, ri_tag);

    cJSON *content_obj = cJSON_CreateObject();
    char share_hex[97];
    bytes_to_hex(round2->encrypted_share, 48, share_hex);
    cJSON_AddStringToObject(content_obj, "share", share_hex);
    cJSON_AddNumberToObject(content_obj, "sender_index", round2->sender_index);
    cJSON_AddNumberToObject(content_obj, "recipient_index", round2->recipient_index);

    char *content_str = cJSON_PrintUnformatted(content_obj);
    cJSON_Delete(content_obj);

    char *encrypted = nip44_encrypt_content(content_str ? content_str : "{}", our_privkey, recipient_pubkey);
    free(content_str);
    if (encrypted) {
        cJSON_AddStringToObject(root, "content", encrypted);
        free(encrypted);
    } else {
        cJSON_AddStringToObject(root, "content", "{}");
    }

    (void)group;

    if (sign_event_json(root, our_privkey) != 0) {
        cJSON_Delete(root);
        return -2;
    }

    cJSON_bool ok = cJSON_PrintPreallocated(root, event_json, (int)max_len, 0);
    cJSON_Delete(root);
    return ok ? 0 : -1;
}

static secp256k1_context *get_secp_ctx(void) {
    static secp256k1_context *ctx = NULL;
    if (!ctx) {
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }
    return ctx;
}

int frost_dkg_round1_generate(const frost_group_t *group,
                               uint8_t our_index,
                               frost_dkg_round1_t *round1,
                               uint8_t *secret_shares_out,
                               size_t *share_count) {
    secp256k1_context *ctx = get_secp_ctx();
    if (!ctx || !group || !round1 || !secret_shares_out || !share_count) return -1;
    if (group->threshold > MAX_THRESHOLD || group->participant_count > MAX_GROUP_PARTICIPANTS) return -2;

    secp256k1_frost_vss_commitments *vss = secp256k1_frost_vss_commitments_create(group->threshold);
    if (!vss) return -3;

    secp256k1_frost_keygen_secret_share *shares = malloc(
        sizeof(secp256k1_frost_keygen_secret_share) * group->participant_count);
    if (!shares) {
        secp256k1_frost_vss_commitments_destroy(vss);
        return -4;
    }

    int ret = secp256k1_frost_keygen_dkg_begin(ctx, vss, shares,
        group->participant_count, group->threshold, our_index,
        (const unsigned char *)DKG_CONTEXT_TAG, strlen(DKG_CONTEXT_TAG));

    if (ret != 1) {
        free(shares);
        secp256k1_frost_vss_commitments_destroy(vss);
        return -5;
    }

    memset(round1, 0, sizeof(*round1));
    memcpy(round1->group_id, group->group_id, GROUP_ID_LEN);
    round1->participant_index = our_index;
    round1->num_coefficients = group->threshold;

    for (uint8_t i = 0; i < group->threshold; i++) {
        memcpy(round1->coefficient_commitments[i], vss->coefficient_commitments[i].data, 64);
    }
    memcpy(round1->zkp_r, vss->zkp_r, 64);
    memcpy(round1->zkp_z, vss->zkp_z, 32);

    frost_dkg_share_t *out = (frost_dkg_share_t *)secret_shares_out;
    for (uint8_t i = 0; i < group->participant_count; i++) {
        out[i].generator_index = (uint8_t)shares[i].generator_index;
        out[i].receiver_index = (uint8_t)shares[i].receiver_index;
        memcpy(out[i].value, shares[i].value, 32);
    }
    *share_count = group->participant_count;

    free(shares);
    secp256k1_frost_vss_commitments_destroy(vss);
    return 0;
}

int frost_dkg_round1_validate(const frost_dkg_round1_t *peer_round1) {
    secp256k1_context *ctx = get_secp_ctx();
    if (!ctx || !peer_round1) return -1;

    secp256k1_frost_vss_commitments *vss = secp256k1_frost_vss_commitments_create(peer_round1->num_coefficients);
    if (!vss) return -2;

    vss->index = peer_round1->participant_index;
    vss->num_coefficients = peer_round1->num_coefficients;
    for (uint8_t i = 0; i < peer_round1->num_coefficients; i++) {
        memcpy(vss->coefficient_commitments[i].data, peer_round1->coefficient_commitments[i], 64);
    }
    memcpy(vss->zkp_r, peer_round1->zkp_r, 64);
    memcpy(vss->zkp_z, peer_round1->zkp_z, 32);

    int ret = secp256k1_frost_keygen_dkg_commitment_validate(ctx, vss,
        (const unsigned char *)DKG_CONTEXT_TAG, strlen(DKG_CONTEXT_TAG));

    secp256k1_frost_vss_commitments_destroy(vss);
    return ret == 1 ? 0 : -3;
}

int frost_dkg_finalize(const frost_group_t *group,
                        const frost_dkg_round1_t *all_round1,
                        size_t round1_count,
                        const frost_dkg_share_t *received_shares,
                        size_t share_count,
                        uint8_t our_index,
                        uint8_t our_share[32],
                        uint8_t group_pubkey[33]) {
    secp256k1_context *ctx = get_secp_ctx();
    if (!ctx || !group || !all_round1 || !received_shares || !our_share || !group_pubkey) return -1;
    if (round1_count != group->participant_count || share_count != group->participant_count) return -2;

    secp256k1_frost_vss_commitments **commitments = malloc(
        sizeof(secp256k1_frost_vss_commitments *) * round1_count);
    if (!commitments) return -3;

    for (size_t i = 0; i < round1_count; i++) {
        commitments[i] = secp256k1_frost_vss_commitments_create(all_round1[i].num_coefficients);
        if (!commitments[i]) {
            for (size_t j = 0; j < i; j++) secp256k1_frost_vss_commitments_destroy(commitments[j]);
            free(commitments);
            return -4;
        }
        commitments[i]->index = all_round1[i].participant_index;
        commitments[i]->num_coefficients = all_round1[i].num_coefficients;
        for (uint8_t k = 0; k < all_round1[i].num_coefficients; k++) {
            memcpy(commitments[i]->coefficient_commitments[k].data, all_round1[i].coefficient_commitments[k], 64);
        }
        memcpy(commitments[i]->zkp_r, all_round1[i].zkp_r, 64);
        memcpy(commitments[i]->zkp_z, all_round1[i].zkp_z, 32);
    }

    secp256k1_frost_keygen_secret_share *shares = malloc(
        sizeof(secp256k1_frost_keygen_secret_share) * share_count);
    if (!shares) {
        for (size_t i = 0; i < round1_count; i++) secp256k1_frost_vss_commitments_destroy(commitments[i]);
        free(commitments);
        return -5;
    }

    for (size_t i = 0; i < share_count; i++) {
        shares[i].generator_index = received_shares[i].generator_index;
        shares[i].receiver_index = received_shares[i].receiver_index;
        memcpy(shares[i].value, received_shares[i].value, 32);
    }

    secp256k1_frost_keypair *keypair = secp256k1_frost_keypair_create(our_index);
    if (!keypair) {
        free(shares);
        for (size_t i = 0; i < round1_count; i++) secp256k1_frost_vss_commitments_destroy(commitments[i]);
        free(commitments);
        return -6;
    }

    int ret = secp256k1_frost_keygen_dkg_finalize(ctx, keypair, our_index,
        (uint32_t)round1_count, shares, commitments);

    if (ret == 1) {
        memcpy(our_share, keypair->secret, 32);
        secure_memzero(keypair->secret, 32);
        uint8_t pubkey33[33], group33[33];
        secp256k1_frost_pubkey_save(pubkey33, group33, &keypair->public_keys);
        memcpy(group_pubkey, group33, 33);
    }

    secp256k1_frost_keypair_destroy(keypair);
    free(shares);
    for (size_t i = 0; i < round1_count; i++) secp256k1_frost_vss_commitments_destroy(commitments[i]);
    free(commitments);

    return ret == 1 ? 0 : -7;
}

int frost_sign_partial(const frost_group_t *group,
                        const frost_sign_request_t *request,
                        const uint8_t our_share[32],
                        uint8_t our_index,
                        frost_sign_response_t *response) {
    if (!group || !request || !our_share || !response) {
        return -1;
    }

    memset(response, 0, sizeof(*response));
    memcpy(response->request_id, request->request_id, 32);
    response->participant_index = our_index;
    response->status = FROST_SIGN_STATUS_SIGNED;

    secp256k1_context *ctx = get_secp_ctx();
    if (!ctx) {
        response->status = FROST_SIGN_STATUS_REJECTED;
        strncpy(response->rejection_reason, "Crypto context unavailable", sizeof(response->rejection_reason) - 1);
        return -2;
    }

    uint8_t msg_hash[32];
    if (request->message_type == FROST_MSG_TYPE_RAW && request->payload_len == 32) {
        memcpy(msg_hash, request->payload, 32);
    } else {
        mbedtls_sha256(request->payload, request->payload_len, msg_hash, 0);
    }

    secp256k1_frost_keypair *kp = secp256k1_frost_keypair_create(our_index);
    if (!kp) {
        response->status = FROST_SIGN_STATUS_REJECTED;
        strncpy(response->rejection_reason, "Keypair creation failed", sizeof(response->rejection_reason) - 1);
        return -3;
    }

    memcpy(kp->secret, our_share, 32);

    uint8_t binding_seed[32], hiding_seed[32];
#ifdef ESP_PLATFORM
    esp_fill_random(binding_seed, 32);
    esp_fill_random(hiding_seed, 32);
#else
    if (secure_random_fill(binding_seed, 32) != 0 || secure_random_fill(hiding_seed, 32) != 0) {
        secp256k1_frost_keypair_destroy(kp);
        response->status = FROST_SIGN_STATUS_REJECTED;
        strncpy(response->rejection_reason, "Failed to get secure random", sizeof(response->rejection_reason) - 1);
        return -4;
    }
#endif

    secp256k1_frost_nonce *nonce = secp256k1_frost_nonce_create(ctx, kp, binding_seed, hiding_seed);
    secure_memzero(binding_seed, 32);
    secure_memzero(hiding_seed, 32);

    if (!nonce) {
        secp256k1_frost_keypair_destroy(kp);
        response->status = FROST_SIGN_STATUS_REJECTED;
        strncpy(response->rejection_reason, "Nonce creation failed", sizeof(response->rejection_reason) - 1);
        return -4;
    }

    response->nonce_commitment[0] = 0x02 | (nonce->commitments.hiding[63] & 0x01);
    memcpy(response->nonce_commitment + 1, nonce->commitments.hiding, 32);

    secp256k1_frost_signature_share sig_share;
    secp256k1_frost_nonce_commitment commits[1];
    commits[0] = nonce->commitments;

    int ret = secp256k1_frost_sign(ctx, &sig_share, msg_hash, 32, 1, kp, nonce, commits);

    secp256k1_frost_nonce_destroy(nonce);
    secp256k1_frost_keypair_destroy(kp);

    if (ret != 1) {
        response->status = FROST_SIGN_STATUS_REJECTED;
        strncpy(response->rejection_reason, "Signing failed", sizeof(response->rejection_reason) - 1);
        return -5;
    }

    memcpy(response->partial_signature, sig_share.response, 32);
    return 0;
}

void frost_sign_request_free(frost_sign_request_t *request) {
    if (request && request->payload) {
        secure_memzero(request->payload, request->payload_len);
        free(request->payload);
        request->payload = NULL;
        request->payload_len = 0;
    }
}
