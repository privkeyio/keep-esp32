#include "nostr_frost.h"
#include "nostr_frost_internal.h"
#include "nostr.h"
#include "hex_utils.h"
#include "crypto_asm.h"
#include "cJSON.h"
#include <mbedtls/sha256.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int compute_event_id(cJSON *event, uint8_t id_out[32]) {
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

int sign_event_json(cJSON *event, const uint8_t privkey[32]) {
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
    bytes_to_hex(pub.data, 32, pubkey_hex, sizeof(pubkey_hex));
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
    bytes_to_hex(id, 32, id_hex, sizeof(id_hex));
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
    bytes_to_hex(ev->sig, 64, sig_hex, sizeof(sig_hex));
    cJSON_DeleteItemFromObject(event, "sig");
    cJSON_AddStringToObject(event, "sig", sig_hex);

    char new_id_hex[65];
    bytes_to_hex(ev->id, 32, new_id_hex, sizeof(new_id_hex));
    cJSON_DeleteItemFromObject(event, "id");
    cJSON_AddStringToObject(event, "id", new_id_hex);

    nostr_event_destroy(ev);
    return 0;
}

char *nip44_encrypt_content(const char *plaintext, const uint8_t sender_priv[32],
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

char *nip44_decrypt_content(const char *ciphertext, const uint8_t recipient_priv[32],
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
    bytes_to_hex(group->coordinator_npub, 32, pubkey_hex, sizeof(pubkey_hex));
    cJSON_AddStringToObject(root, "pubkey", pubkey_hex);

    cJSON *tags = cJSON_AddArrayToObject(root, "tags");

    char id_hex[65];
    bytes_to_hex(group->group_id, 32, id_hex, sizeof(id_hex));
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
        bytes_to_hex(part->npub, 32, npub_hex, sizeof(npub_hex));
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
        bytes_to_hex(group->notification_pubkey, 32, npk_hex, sizeof(npk_hex));
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
