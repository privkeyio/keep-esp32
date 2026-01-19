#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "hex_utils.h"

#define MAX_JSON_LEN     16384
#define MAX_PARTICIPANTS 16
#define MAX_RELAYS       4
#define RELAY_URL_LEN    128

typedef struct {
    uint8_t npub[32];
    uint8_t index;
    char relay_hint[RELAY_URL_LEN];
} participant_t;

typedef struct {
    uint8_t group_id[32];
    uint8_t threshold;
    uint8_t participant_count;
    participant_t participants[MAX_PARTICIPANTS];
    uint8_t group_pubkey[32];
    uint8_t coordinator_npub[32];
    char relays[MAX_RELAYS][RELAY_URL_LEN];
    uint8_t relay_count;
} frost_group_t;

static int parse_uint8(const char *str, uint8_t *out) {
    char *endptr;
    long val = strtol(str, &endptr, 10);
    if (endptr == str || *endptr != '\0' || val < 0 || val > 255)
        return -1;
    *out = (uint8_t)val;
    return 0;
}

static void copy_string(char *dst, const char *src, size_t max_len) {
    snprintf(dst, max_len, "%s", src);
}

static void parse_tags(cJSON *tags, frost_group_t *group) {
    if (!cJSON_IsArray(tags))
        return;

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

        if (strcmp(name, "d") == 0) {
            hex_to_bytes(val, group->group_id, 32);
        } else if (strcmp(name, "threshold") == 0) {
            parse_uint8(val, &group->threshold);
        } else if (strcmp(name, "relay") == 0 && group->relay_count < MAX_RELAYS) {
            copy_string(group->relays[group->relay_count++], val, RELAY_URL_LEN);
        } else if (strcmp(name, "p") == 0 && group->participant_count < MAX_PARTICIPANTS) {
            participant_t *p = &group->participants[group->participant_count];
            memset(p, 0, sizeof(*p));
            hex_to_bytes(val, p->npub, 32);

            cJSON *relay = cJSON_GetArrayItem(tag, 2);
            if (relay && cJSON_IsString(relay))
                copy_string(p->relay_hint, relay->valuestring, RELAY_URL_LEN);

            cJSON *idx = cJSON_GetArrayItem(tag, 3);
            if (idx && cJSON_IsString(idx))
                parse_uint8(idx->valuestring, &p->index);

            group->participant_count++;
        }
    }
}

static int parse_frost_group_event(const char *json, frost_group_t *group) {
    memset(group, 0, sizeof(*group));

    cJSON *root = cJSON_Parse(json);
    if (!root)
        return -1;

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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > MAX_JSON_LEN) {
        return 0;
    }

    char *json = malloc(size + 1);
    if (!json) {
        return 0;
    }
    memcpy(json, data, size);
    json[size] = '\0';

    frost_group_t group;
    parse_frost_group_event(json, &group);

    free(json);
    return 0;
}
