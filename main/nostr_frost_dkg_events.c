// SPDX-FileCopyrightText: © 2026 Privkey Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "nostr_frost.h"
#include "nostr_frost_internal.h"
#include "hex_utils.h"
#include "cJSON.h"
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int frost_create_dkg_round1_event(const frost_group_t *group, const frost_dkg_round1_t *round1,
                                  const uint8_t *privkey, char *event_json, size_t max_len) {
    cJSON *root = cJSON_CreateObject();
    if (!root)
        return -1;

    cJSON_AddNumberToObject(root, "kind", FROST_KIND_DKG_ROUND1);

    cJSON *tags = cJSON_AddArrayToObject(root, "tags");

    char gid_hex[65];
    bytes_to_hex(round1->group_id, 32, gid_hex, sizeof(gid_hex));
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
        bytes_to_hex(round1->coefficient_commitments[i], 64, coeff_hex, sizeof(coeff_hex));
        cJSON_AddItemToArray(coeffs, cJSON_CreateString(coeff_hex));
    }
    char zkp_r_hex[129];
    bytes_to_hex(round1->zkp_r, 64, zkp_r_hex, sizeof(zkp_r_hex));
    cJSON_AddStringToObject(content_obj, "zkp_r", zkp_r_hex);
    char zkp_z_hex[65];
    bytes_to_hex(round1->zkp_z, 32, zkp_z_hex, sizeof(zkp_z_hex));
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

    if (max_len > (size_t)INT_MAX)
        max_len = (size_t)INT_MAX;
    cJSON_bool ok = cJSON_PrintPreallocated(root, event_json, (int)max_len, 0);
    cJSON_Delete(root);
    return ok ? 0 : -1;
}

int frost_parse_dkg_round1_event(const char *event_json, const frost_group_t *group,
                                 const uint8_t *our_privkey, frost_dkg_round1_t *round1) {
    memset(round1, 0, sizeof(*round1));

    cJSON *root = cJSON_Parse(event_json);
    if (!root)
        return -1;

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
                        hex_to_bytes(val, round1->group_id, GROUP_ID_LEN);
                    }
                }
            } else if (strcmp(name, "participant_index") == 0) {
                char *endptr;
                long tmp = strtol(val, &endptr, 10);
                if (endptr != val && *endptr == '\0' && tmp > 0 && tmp <= UINT8_MAX) {
                    round1->participant_index = (uint8_t)tmp;
                }
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
                        if (hex_to_bytes(c->valuestring, round1->coefficient_commitments[i], 64) !=
                            64) {
                            memset(round1->coefficient_commitments[i], 0, 64);
                        }
                    }
                }
            }
            cJSON *zkp_r = cJSON_GetObjectItem(inner, "zkp_r");
            if (zkp_r && cJSON_IsString(zkp_r)) {
                if (hex_to_bytes(zkp_r->valuestring, round1->zkp_r, 64) != 64) {
                    memset(round1->zkp_r, 0, 64);
                }
            }
            cJSON *zkp_z = cJSON_GetObjectItem(inner, "zkp_z");
            if (zkp_z && cJSON_IsString(zkp_z)) {
                if (hex_to_bytes(zkp_z->valuestring, round1->zkp_z, 32) != 32) {
                    memset(round1->zkp_z, 0, 32);
                }
            }
            cJSON_Delete(inner);
        }
        free(decrypted);
    }

    (void)group;
    cJSON_Delete(root);
    return 0;
}

int frost_create_dkg_round2_event(const frost_group_t *group, const frost_dkg_round2_t *round2,
                                  const uint8_t *our_privkey, const uint8_t *recipient_pubkey,
                                  char *event_json, size_t max_len) {
    cJSON *root = cJSON_CreateObject();
    if (!root)
        return -1;

    cJSON_AddNumberToObject(root, "kind", FROST_KIND_DKG_ROUND2);

    cJSON *tags = cJSON_AddArrayToObject(root, "tags");

    char gid_hex[65];
    bytes_to_hex(round2->group_id, 32, gid_hex, sizeof(gid_hex));
    cJSON *e_tag = cJSON_CreateArray();
    cJSON_AddItemToArray(e_tag, cJSON_CreateString("e"));
    cJSON_AddItemToArray(e_tag, cJSON_CreateString(gid_hex));
    cJSON_AddItemToArray(e_tag, cJSON_CreateString(""));
    cJSON_AddItemToArray(e_tag, cJSON_CreateString("root"));
    cJSON_AddItemToArray(tags, e_tag);

    cJSON *p_tag = cJSON_CreateArray();
    cJSON_AddItemToArray(p_tag, cJSON_CreateString("p"));
    char recip_hex[65];
    bytes_to_hex(recipient_pubkey, 32, recip_hex, sizeof(recip_hex));
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
    bytes_to_hex(round2->encrypted_share, 48, share_hex, sizeof(share_hex));
    cJSON_AddStringToObject(content_obj, "share", share_hex);
    cJSON_AddNumberToObject(content_obj, "sender_index", round2->sender_index);
    cJSON_AddNumberToObject(content_obj, "recipient_index", round2->recipient_index);

    char *content_str = cJSON_PrintUnformatted(content_obj);
    cJSON_Delete(content_obj);

    if (!content_str) {
        cJSON_Delete(root);
        return -3;
    }

    char *encrypted = nip44_encrypt_content(content_str, our_privkey, recipient_pubkey);
    free(content_str);
    if (!encrypted) {
        cJSON_Delete(root);
        return -3;
    }
    cJSON_AddStringToObject(root, "content", encrypted);
    free(encrypted);

    (void)group;

    if (sign_event_json(root, our_privkey) != 0) {
        cJSON_Delete(root);
        return -2;
    }

    if (max_len > (size_t)INT_MAX)
        max_len = (size_t)INT_MAX;
    cJSON_bool ok = cJSON_PrintPreallocated(root, event_json, (int)max_len, 0);
    cJSON_Delete(root);
    return ok ? 0 : -1;
}

int frost_parse_dkg_round2_event(const char *event_json, const frost_group_t *group,
                                 const uint8_t *our_privkey, frost_dkg_round2_t *round2) {
    memset(round2, 0, sizeof(*round2));

    cJSON *root = cJSON_Parse(event_json);
    if (!root)
        return -1;

    cJSON *kind = cJSON_GetObjectItem(root, "kind");
    if (!kind || !cJSON_IsNumber(kind) || kind->valueint != FROST_KIND_DKG_ROUND2) {
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
                        hex_to_bytes(val, round2->group_id, GROUP_ID_LEN);
                    }
                }
            } else if (strcmp(name, "participant_index") == 0) {
                char *endptr;
                long tmp = strtol(val, &endptr, 10);
                if (endptr != val && *endptr == '\0' && tmp > 0 && tmp <= UINT8_MAX) {
                    round2->sender_index = (uint8_t)tmp;
                }
            } else if (strcmp(name, "recipient_index") == 0) {
                char *endptr;
                long tmp = strtol(val, &endptr, 10);
                if (endptr != val && *endptr == '\0' && tmp > 0 && tmp <= UINT8_MAX) {
                    round2->recipient_index = (uint8_t)tmp;
                }
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

        cJSON *share = cJSON_GetObjectItem(inner, "share");
        if (share && cJSON_IsString(share)) {
            if (hex_to_bytes(share->valuestring, round2->encrypted_share, 48) != 48) {
                memset(round2->encrypted_share, 0, 48);
            }
        }
        cJSON *si = cJSON_GetObjectItem(inner, "sender_index");
        if (si && cJSON_IsNumber(si)) {
            round2->sender_index = (uint8_t)si->valueint;
        }
        cJSON *ri = cJSON_GetObjectItem(inner, "recipient_index");
        if (ri && cJSON_IsNumber(ri)) {
            round2->recipient_index = (uint8_t)ri->valueint;
        }
        cJSON_Delete(inner);
    }

    (void)group;
    cJSON_Delete(root);
    return 0;
}
