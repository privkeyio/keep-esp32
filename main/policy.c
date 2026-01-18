#include "policy.h"
#include "hex_utils.h"
#include "esp_partition.h"
#include "esp_log.h"
#include "crypto_asm.h"
#include "cJSON.h"
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_extrakeys.h>
#include <mbedtls/sha256.h>
#include <string.h>

#define TAG "policy"
#define PARTITION_NAME "policy"
#define SECTOR_SIZE 4096

static const esp_partition_t *policy_partition = NULL;
static bool initialized = false;
static uint8_t sector_buf[SECTOR_SIZE];

_Static_assert(sizeof(policy_bundle_t) <= POLICY_SLOT_SIZE, "policy_bundle_t exceeds slot size");
_Static_assert(sizeof(policy_bundle_t) <= SECTOR_SIZE, "policy_bundle_t exceeds sector size");

int policy_init(void) {
    if (initialized) return 0;

    policy_partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, PARTITION_NAME);
    if (!policy_partition) {
        ESP_LOGE(TAG, "Policy partition '%s' not found", PARTITION_NAME);
        return -1;
    }

    ESP_LOGI(TAG, "Policy storage initialized: %s at 0x%lx (%lu bytes)",
             policy_partition->label, policy_partition->address, policy_partition->size);
    initialized = true;
    return 0;
}

int policy_save_bundle(const policy_bundle_t *bundle) {
    if (!initialized) return POLICY_ERR_STORAGE;
    if (bundle->version != POLICY_VERSION) return POLICY_ERR_VERSION;

    int ret = policy_verify_signature(bundle);
    if (ret != 0) return ret;

    esp_err_t err = esp_partition_read(policy_partition, 0, sector_buf, SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(sector_buf, SECTOR_SIZE);
        return POLICY_ERR_STORAGE;
    }

    memcpy(sector_buf, bundle, sizeof(policy_bundle_t));
    secure_memzero(sector_buf + sizeof(policy_bundle_t), SECTOR_SIZE - sizeof(policy_bundle_t));

    err = esp_partition_erase_range(policy_partition, 0, SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(sector_buf, SECTOR_SIZE);
        return POLICY_ERR_STORAGE;
    }

    err = esp_partition_write(policy_partition, 0, sector_buf, SECTOR_SIZE);
    secure_memzero(sector_buf, SECTOR_SIZE);

    if (err != ESP_OK) return POLICY_ERR_STORAGE;

    ESP_LOGI(TAG, "Policy bundle saved (rules_len=%lu)", (unsigned long)bundle->rules_len);
    return 0;
}

int policy_load_bundle(policy_bundle_t *bundle) {
    if (!initialized) return POLICY_ERR_STORAGE;

    esp_err_t err = esp_partition_read(policy_partition, 0, bundle, sizeof(policy_bundle_t));
    if (err != ESP_OK) {
        secure_memzero(bundle, sizeof(policy_bundle_t));
        return POLICY_ERR_STORAGE;
    }

    if (bundle->version == 0 || bundle->version == 0xFF) {
        secure_memzero(bundle, sizeof(policy_bundle_t));
        return POLICY_ERR_NOT_FOUND;
    }

    if (bundle->version != POLICY_VERSION) {
        secure_memzero(bundle, sizeof(policy_bundle_t));
        return POLICY_ERR_VERSION;
    }

    if (bundle->rules_len > POLICY_MAX_RULES_LEN) {
        secure_memzero(bundle, sizeof(policy_bundle_t));
        return POLICY_ERR_NOT_FOUND;
    }

    return 0;
}

int policy_delete_bundle(void) {
    if (!initialized) return POLICY_ERR_STORAGE;

    esp_err_t err = esp_partition_erase_range(policy_partition, 0, SECTOR_SIZE);
    if (err != ESP_OK) {
        return POLICY_ERR_STORAGE;
    }

    ESP_LOGI(TAG, "Policy bundle deleted");
    return 0;
}

bool policy_has_bundle(void) {
    if (!initialized) return false;

    policy_bundle_t bundle;
    esp_err_t err = esp_partition_read(policy_partition, 0, &bundle, sizeof(bundle));
    if (err != ESP_OK) {
        secure_memzero(&bundle, sizeof(bundle));
        return false;
    }

    bool has = (bundle.version == POLICY_VERSION && bundle.rules_len <= POLICY_MAX_RULES_LEN);
    secure_memzero(&bundle, sizeof(bundle));
    return has;
}

int policy_verify_signature(const policy_bundle_t *bundle) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx) return POLICY_ERR_INVALID_SIG;

    size_t msg_len = offsetof(policy_bundle_t, signature);
    uint8_t msg_hash[32];
    mbedtls_sha256((const uint8_t *)bundle, msg_len, msg_hash, 0);

    secp256k1_xonly_pubkey xonly_pk;
    if (!secp256k1_xonly_pubkey_parse(ctx, &xonly_pk, bundle->warden_pubkey)) {
        secp256k1_context_destroy(ctx);
        return POLICY_ERR_INVALID_SIG;
    }

    int valid = secp256k1_schnorrsig_verify(ctx, bundle->signature, msg_hash, 32, &xonly_pk);
    secp256k1_context_destroy(ctx);

    return valid == 1 ? 0 : POLICY_ERR_INVALID_SIG;
}

int policy_check_hash(const policy_bundle_t *bundle, const uint8_t expected_hash[POLICY_HASH_LEN]) {
    if (ct_compare(bundle->policy_hash, expected_hash, POLICY_HASH_LEN) != 0) {
        return POLICY_ERR_HASH_MISMATCH;
    }
    return 0;
}

void policy_handle_update(const rpc_request_t *req, rpc_response_t *resp) {
    size_t hex_len = strlen(req->policy_bundle);
    if (hex_len == 0) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_PARAMS, "Missing bundle parameter");
        return;
    }

    if (hex_len != sizeof(policy_bundle_t) * 2) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_PARAMS, "Invalid bundle length");
        return;
    }

    policy_bundle_t bundle;
    int byte_len = hex_to_bytes(req->policy_bundle, (uint8_t *)&bundle, sizeof(bundle));
    if (byte_len != (int)sizeof(policy_bundle_t)) {
        secure_memzero(&bundle, sizeof(bundle));
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_PARAMS, "Invalid bundle hex");
        return;
    }

    int ret = policy_save_bundle(&bundle);
    secure_memzero(&bundle, sizeof(bundle));

    if (ret == POLICY_ERR_INVALID_SIG) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_PARAMS, "Invalid signature");
        return;
    }
    if (ret == POLICY_ERR_VERSION) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_PARAMS, "Unsupported version");
        return;
    }
    if (ret != 0) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_STORAGE, "Storage error");
        return;
    }

    protocol_success(resp, req->id, "{\"ok\":true}");
}

void policy_handle_get(const rpc_request_t *req, rpc_response_t *resp) {
    if (!policy_has_bundle()) {
        protocol_success(resp, req->id, "{\"has_policy\":false}");
        return;
    }

    policy_bundle_t bundle;
    int ret = policy_load_bundle(&bundle);
    if (ret != 0) {
        secure_memzero(&bundle, sizeof(bundle));
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_STORAGE, "Load error");
        return;
    }

    char policy_hash_hex[65];
    bytes_to_hex(bundle.policy_hash, POLICY_HASH_LEN, policy_hash_hex, sizeof(policy_hash_hex));

    char warden_pubkey_hex[65];
    bytes_to_hex(bundle.warden_pubkey, POLICY_PUBKEY_LEN, warden_pubkey_hex, sizeof(warden_pubkey_hex));

    char result[512];
    int written = snprintf(result, sizeof(result),
             "{\"has_policy\":true,\"version\":%d,\"policy_hash\":\"%s\",\"warden_pubkey\":\"%s\",\"rules_len\":%lu,\"created_at\":%llu}",
             bundle.version, policy_hash_hex, warden_pubkey_hex,
             (unsigned long)bundle.rules_len, (unsigned long long)bundle.created_at);

    secure_memzero(&bundle, sizeof(bundle));

    if (written < 0 || (size_t)written >= sizeof(result)) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_INTERNAL, "Response buffer overflow");
        return;
    }

    protocol_success(resp, req->id, result);
}

int policy_evaluate(uint64_t total_out_sats, uint64_t fee_sats) {
    if (!policy_has_bundle()) {
        return 0;
    }

    policy_bundle_t bundle;
    int ret = policy_load_bundle(&bundle);
    if (ret != 0) {
        secure_memzero(&bundle, sizeof(bundle));
        return ret;
    }

    ret = policy_verify_signature(&bundle);
    if (ret != 0) {
        secure_memzero(&bundle, sizeof(bundle));
        return ret;
    }

    if (bundle.rules_len == 0 || bundle.rules_len > POLICY_MAX_RULES_LEN) {
        secure_memzero(&bundle, sizeof(bundle));
        return 0;
    }

    char rules_str[POLICY_MAX_RULES_LEN + 1];
    memcpy(rules_str, bundle.rules, bundle.rules_len);
    rules_str[bundle.rules_len] = '\0';
    secure_memzero(&bundle, sizeof(bundle));

    cJSON *rules = cJSON_Parse(rules_str);
    secure_memzero(rules_str, sizeof(rules_str));
    if (!rules) {
        return POLICY_ERR_MALFORMED;
    }

    cJSON *max_amount = cJSON_GetObjectItem(rules, "max_amount");
    if (max_amount && cJSON_IsNumber(max_amount)) {
        uint64_t limit = (uint64_t)max_amount->valuedouble;
        if (total_out_sats > limit) {
            ESP_LOGW(TAG, "Policy denied: amount %llu exceeds max %llu",
                     (unsigned long long)total_out_sats, (unsigned long long)limit);
            cJSON_Delete(rules);
            return POLICY_ERR_DENIED;
        }
    }

    cJSON *max_fee = cJSON_GetObjectItem(rules, "max_fee");
    if (max_fee && cJSON_IsNumber(max_fee)) {
        uint64_t limit = (uint64_t)max_fee->valuedouble;
        if (fee_sats > limit) {
            ESP_LOGW(TAG, "Policy denied: fee %llu exceeds max %llu",
                     (unsigned long long)fee_sats, (unsigned long long)limit);
            cJSON_Delete(rules);
            return POLICY_ERR_DENIED;
        }
    }

    cJSON_Delete(rules);
    return 0;
}
