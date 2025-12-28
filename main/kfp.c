#include "kfp.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "cJSON.h"

static int hex_decode(const char *hex, uint8_t *out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return 0;
}

static void hex_encode(const uint8_t *data, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(out + i * 2, "%02x", data[i]);
    }
    out[len * 2] = '\0';
}

static int parse_hex_field(cJSON *obj, const char *key, uint8_t *out, size_t len) {
    cJSON *item = cJSON_GetObjectItem(obj, key);
    if (!item || !cJSON_IsString(item)) return -1;
    return hex_decode(item->valuestring, out, len);
}

static int parse_hex_vec(cJSON *obj, const char *key, uint8_t *out, size_t max_len, size_t *actual_len) {
    cJSON *item = cJSON_GetObjectItem(obj, key);
    if (!item || !cJSON_IsString(item)) return -1;
    size_t hex_len = strlen(item->valuestring);
    *actual_len = hex_len / 2;
    if (*actual_len > max_len) return -1;
    return hex_decode(item->valuestring, out, *actual_len);
}

kfp_msg_type_t kfp_parse(const char *json, kfp_msg_t *out) {
    memset(out, 0, sizeof(*out));
    out->type = KFP_MSG_UNKNOWN;

    cJSON *root = cJSON_Parse(json);
    if (!root) return KFP_MSG_UNKNOWN;

    cJSON *type_item = cJSON_GetObjectItem(root, "type");
    if (!type_item || !cJSON_IsString(type_item)) {
        cJSON_Delete(root);
        return KFP_MSG_UNKNOWN;
    }

    const char *type_str = type_item->valuestring;

    if (strcmp(type_str, "announce") == 0) {
        out->type = KFP_MSG_ANNOUNCE;
        kfp_announce_t *a = &out->announce;
        cJSON *v = cJSON_GetObjectItem(root, "version");
        a->version = v && cJSON_IsNumber(v) ? (uint8_t)v->valueint : KFP_VERSION;
        parse_hex_field(root, "group_pubkey", a->group_pubkey, 32);
        cJSON *idx = cJSON_GetObjectItem(root, "share_index");
        a->share_index = idx && cJSON_IsNumber(idx) ? (uint16_t)idx->valueint : 0;
        cJSON *name = cJSON_GetObjectItem(root, "name");
        if (name && cJSON_IsString(name)) {
            strncpy(a->name, name->valuestring, sizeof(a->name) - 1);
        }
    }
    else if (strcmp(type_str, "sign_request") == 0) {
        out->type = KFP_MSG_SIGN_REQUEST;
        kfp_sign_request_t *s = &out->sign_request;
        parse_hex_field(root, "session_id", s->session_id, 32);
        parse_hex_field(root, "group_pubkey", s->group_pubkey, 32);
        parse_hex_vec(root, "message", s->message, KFP_MAX_MESSAGE_LEN, &s->message_len);
        cJSON *mt = cJSON_GetObjectItem(root, "message_type");
        if (mt && cJSON_IsString(mt)) {
            strncpy(s->message_type, mt->valuestring, sizeof(s->message_type) - 1);
        }
        cJSON *parts = cJSON_GetObjectItem(root, "participants");
        if (parts && cJSON_IsArray(parts)) {
            int n = cJSON_GetArraySize(parts);
            s->participant_count = n > KFP_MAX_PARTICIPANTS ? KFP_MAX_PARTICIPANTS : n;
            for (int i = 0; i < s->participant_count; i++) {
                cJSON *p = cJSON_GetArrayItem(parts, i);
                s->participants[i] = p && cJSON_IsNumber(p) ? (uint16_t)p->valueint : 0;
            }
        }
        cJSON *ts = cJSON_GetObjectItem(root, "timestamp");
        s->timestamp = ts && cJSON_IsNumber(ts) ? (uint64_t)ts->valuedouble : 0;
    }
    else if (strcmp(type_str, "commitment") == 0) {
        out->type = KFP_MSG_COMMITMENT;
        kfp_commitment_t *c = &out->commitment;
        parse_hex_field(root, "session_id", c->session_id, 32);
        cJSON *idx = cJSON_GetObjectItem(root, "share_index");
        c->share_index = idx && cJSON_IsNumber(idx) ? (uint16_t)idx->valueint : 0;
        parse_hex_vec(root, "commitment", c->commitment, sizeof(c->commitment), &c->commitment_len);
    }
    else if (strcmp(type_str, "signature_share") == 0) {
        out->type = KFP_MSG_SIGNATURE_SHARE;
        kfp_signature_share_t *ss = &out->signature_share;
        parse_hex_field(root, "session_id", ss->session_id, 32);
        cJSON *idx = cJSON_GetObjectItem(root, "share_index");
        ss->share_index = idx && cJSON_IsNumber(idx) ? (uint16_t)idx->valueint : 0;
        parse_hex_vec(root, "signature_share", ss->signature_share, sizeof(ss->signature_share), &ss->share_len);
    }
    else if (strcmp(type_str, "signature_complete") == 0) {
        out->type = KFP_MSG_SIGNATURE_COMPLETE;
        kfp_signature_complete_t *sc = &out->signature_complete;
        parse_hex_field(root, "session_id", sc->session_id, 32);
        parse_hex_field(root, "signature", sc->signature, 64);
        parse_hex_field(root, "message_hash", sc->message_hash, 32);
    }
    else if (strcmp(type_str, "ping") == 0) {
        out->type = KFP_MSG_PING;
        parse_hex_field(root, "challenge", out->ping.challenge, 32);
        cJSON *ts = cJSON_GetObjectItem(root, "timestamp");
        out->ping.timestamp = ts && cJSON_IsNumber(ts) ? (uint64_t)ts->valuedouble : 0;
    }
    else if (strcmp(type_str, "pong") == 0) {
        out->type = KFP_MSG_PONG;
        parse_hex_field(root, "challenge", out->pong.challenge, 32);
        cJSON *ts = cJSON_GetObjectItem(root, "timestamp");
        out->pong.timestamp = ts && cJSON_IsNumber(ts) ? (uint64_t)ts->valuedouble : 0;
    }
    else if (strcmp(type_str, "error") == 0) {
        out->type = KFP_MSG_ERROR;
        kfp_error_t *e = &out->error;
        cJSON *sid = cJSON_GetObjectItem(root, "session_id");
        if (sid && cJSON_IsString(sid)) {
            e->has_session_id = (hex_decode(sid->valuestring, e->session_id, 32) == 0);
        }
        cJSON *code = cJSON_GetObjectItem(root, "code");
        if (code && cJSON_IsString(code)) {
            strncpy(e->code, code->valuestring, sizeof(e->code) - 1);
        }
        cJSON *msg = cJSON_GetObjectItem(root, "message");
        if (msg && cJSON_IsString(msg)) {
            strncpy(e->message, msg->valuestring, sizeof(e->message) - 1);
        }
    }

    cJSON_Delete(root);
    return out->type;
}

char *kfp_serialize_announce(const kfp_announce_t *msg) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "announce");
    cJSON_AddNumberToObject(root, "version", msg->version);
    char hex[65];
    hex_encode(msg->group_pubkey, 32, hex);
    cJSON_AddStringToObject(root, "group_pubkey", hex);
    cJSON_AddNumberToObject(root, "share_index", msg->share_index);
    cJSON *caps = cJSON_AddArrayToObject(root, "capabilities");
    cJSON_AddItemToArray(caps, cJSON_CreateString("sign"));
    if (msg->name[0]) {
        cJSON_AddStringToObject(root, "name", msg->name);
    }
    char *out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return out;
}

char *kfp_serialize_commitment(const kfp_commitment_t *msg) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "commitment");
    char hex[257];
    hex_encode(msg->session_id, 32, hex);
    cJSON_AddStringToObject(root, "session_id", hex);
    cJSON_AddNumberToObject(root, "share_index", msg->share_index);
    hex_encode(msg->commitment, msg->commitment_len, hex);
    cJSON_AddStringToObject(root, "commitment", hex);
    char *out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return out;
}

char *kfp_serialize_signature_share(const kfp_signature_share_t *msg) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "signature_share");
    char hex[129];
    hex_encode(msg->session_id, 32, hex);
    cJSON_AddStringToObject(root, "session_id", hex);
    cJSON_AddNumberToObject(root, "share_index", msg->share_index);
    hex_encode(msg->signature_share, msg->share_len, hex);
    cJSON_AddStringToObject(root, "signature_share", hex);
    char *out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return out;
}

char *kfp_serialize_pong(const kfp_pong_t *msg) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "pong");
    char hex[65];
    hex_encode(msg->challenge, 32, hex);
    cJSON_AddStringToObject(root, "challenge", hex);
    cJSON_AddNumberToObject(root, "timestamp", (double)msg->timestamp);
    char *out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return out;
}

char *kfp_serialize_error(const kfp_error_t *msg) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "error");
    if (msg->has_session_id) {
        char hex[65];
        hex_encode(msg->session_id, 32, hex);
        cJSON_AddStringToObject(root, "session_id", hex);
    }
    cJSON_AddStringToObject(root, "code", msg->code);
    cJSON_AddStringToObject(root, "message", msg->message);
    char *out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return out;
}
