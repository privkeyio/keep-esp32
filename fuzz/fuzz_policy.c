#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"

#define MAX_JSON_LEN 2048

static uint64_t double_to_uint64_safe(double v) {
    if (v < 0.0 || isnan(v))
        return 0;
    if (v >= (double)UINT64_MAX)
        return UINT64_MAX;
    return (uint64_t)v;
}

static int policy_evaluate(const char *json, uint64_t amount, uint64_t fee) {
    cJSON *rules = cJSON_Parse(json);
    if (!rules) {
        return -1;
    }

    int result = 0;

    cJSON *max_amount = cJSON_GetObjectItem(rules, "max_amount");
    if (max_amount && cJSON_IsNumber(max_amount)) {
        if (amount > double_to_uint64_safe(max_amount->valuedouble)) {
            result = -2;
        }
    }

    cJSON *max_fee = cJSON_GetObjectItem(rules, "max_fee");
    if (result == 0 && max_fee && cJSON_IsNumber(max_fee)) {
        if (fee > double_to_uint64_safe(max_fee->valuedouble)) {
            result = -3;
        }
    }

    cJSON_Delete(rules);
    return result;
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

    policy_evaluate(json, 100000000, 10000);
    policy_evaluate(json, 0, 0);
    policy_evaluate(json, UINT64_MAX, UINT64_MAX);

    free(json);
    return 0;
}
