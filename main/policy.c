// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include "policy.h"
#include "psbt_fraud.h"
#include "hex_utils.h"
#include "esp_partition.h"
#include "esp_log.h"
#include "crypto_asm.h"
#include "secresult.h"
#include "anti_glitch.h"
#include "cJSON.h"
#include "ux_interface.h"
#include "sign_approval.h"
#include "frost_signer.h"
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_extrakeys.h>
#include <mbedtls/sha256.h>
#include <string.h>
#include <inttypes.h>

#define TAG            "policy"
#define PARTITION_NAME "policy"
#define SECTOR_SIZE    4096

#define POLICY_PIN_CONFIRM_TIMEOUT_MS 120000

static const esp_partition_t *policy_partition = NULL;
static bool initialized = false;
static uint8_t sector_buf[SECTOR_SIZE];

_Static_assert(sizeof(policy_bundle_t) <= POLICY_SLOT_SIZE, "policy_bundle_t exceeds slot size");
_Static_assert(sizeof(policy_bundle_t) <= SECTOR_SIZE, "policy_bundle_t exceeds sector size");

static int policy_verify_signature(const policy_bundle_t *bundle);
static int policy_check_hash(const policy_bundle_t *bundle,
                             const uint8_t expected_hash[POLICY_HASH_LEN]);

int policy_init(void) {
    if (initialized)
        return 0;

    policy_partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY,
                                                PARTITION_NAME);
    if (!policy_partition) {
        ESP_LOGE(TAG, "Policy partition '%s' not found", PARTITION_NAME);
        return -1;
    }

    ESP_LOGI(TAG, "Policy storage initialized: %s at 0x%lx (%lu bytes)", policy_partition->label,
             policy_partition->address, policy_partition->size);
    initialized = true;
    return 0;
}

void policy_raise_lagging_pin(void) {
    /* A power cut between writing a bundle and raising the pin leaves the pin behind it,
     * and until then an older bundle from the pinned key would load if it were put back
     * in flash. Catch the pin up to the installed bundle once that bundle verifies. */
    policy_pin_t pin;
    if (!initialized || policy_pin_read(&pin) != 0)
        return;
    policy_bundle_t bundle;
    if (policy_load_bundle(&bundle) == 0 && policy_verify_signature(&bundle) == 0 &&
        bundle.created_at > pin.created_at) {
        pin.created_at = bundle.created_at;
        if (policy_pin_write(&pin) != 0)
            ESP_LOGW(TAG, "Could not raise the Warden pin to the installed bundle");
    }
    secure_memzero(&bundle, sizeof(bundle));
}

int policy_check_update(const policy_pin_t *pin, const policy_bundle_t *installed,
                        const policy_bundle_t *candidate, bool *needs_confirm) {
    KEEP_ASSERT(candidate != NULL);
    KEEP_ASSERT(needs_confirm != NULL);
    *needs_confirm = false;

    if (candidate->version != POLICY_VERSION)
        return POLICY_ERR_VERSION;
    if (candidate->rules_len > POLICY_MAX_RULES_LEN)
        return POLICY_ERR_MALFORMED;

    int ret = policy_verify_signature(candidate);
    if (ret != 0)
        return ret;

    if (pin != NULL) {
        if (ct_compare(candidate->warden_pubkey, pin->warden_pubkey, POLICY_PUBKEY_LEN) != 0)
            return POLICY_ERR_WARDEN;
        uint64_t floor = pin->created_at;
        if (installed &&
            ct_compare(installed->warden_pubkey, pin->warden_pubkey, POLICY_PUBKEY_LEN) == 0 &&
            installed->created_at > floor) {
            floor = installed->created_at;
        }
        return candidate->created_at > floor ? 0 : POLICY_ERR_ROLLBACK;
    }

    /* Unpinned, including a bundle installed before pinning existed: the key must be
     * confirmed on the device, and a bundle from the same key must still be newer. */
    *needs_confirm = true;
    if (installed &&
        ct_compare(candidate->warden_pubkey, installed->warden_pubkey, POLICY_PUBKEY_LEN) == 0 &&
        candidate->created_at <= installed->created_at) {
        return POLICY_ERR_ROLLBACK;
    }
    return 0;
}

static int store_bundle(const policy_bundle_t *bundle, policy_pin_t *pin, bool pinned) {
    /* The pin is written before the bundle and raised after it, so a power cut at any
     * point leaves the device pinned and failing closed until a newer bundle arrives. */
    if (!pinned) {
        memcpy(pin->warden_pubkey, bundle->warden_pubkey, POLICY_PUBKEY_LEN);
        pin->created_at = 0;
        if (policy_pin_write(pin) != 0)
            return POLICY_ERR_STORAGE;
    }

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

    if (err != ESP_OK)
        return POLICY_ERR_STORAGE;

    pin->created_at = bundle->created_at;
    if (policy_pin_write(pin) != 0)
        return POLICY_ERR_STORAGE;

    ESP_LOGI(TAG, "Policy bundle saved (rules_len=%lu)", (unsigned long)bundle->rules_len);
    return 0;
}

int policy_save_bundle(const policy_bundle_t *bundle) {
    KEEP_ASSERT(bundle != NULL);

    if (!initialized)
        return POLICY_ERR_STORAGE;

    policy_pin_t pin;
    int pin_ret = policy_pin_read(&pin);
    if (pin_ret != 0 && pin_ret != POLICY_ERR_NOT_FOUND) {
        return POLICY_ERR_STORAGE;
    }
    bool pinned = pin_ret == 0;

    policy_bundle_t installed;
    bool installed_valid =
        policy_load_bundle(&installed) == 0 && policy_verify_signature(&installed) == 0;

    bool needs_confirm = false;
    int ret = policy_check_update(pinned ? &pin : NULL, installed_valid ? &installed : NULL, bundle,
                                  &needs_confirm);
    secure_memzero(&installed, sizeof(installed));
    if (ret != 0)
        return ret;

    if (needs_confirm &&
        !ux_confirm_warden_pin(bundle->warden_pubkey, POLICY_PIN_CONFIRM_TIMEOUT_MS)) {
        return POLICY_ERR_UNCONFIRMED;
    }

    ret = store_bundle(bundle, &pin, pinned);
    if (needs_confirm) {
        ux_report_warden_pin(ret == 0);
    }
    return ret;
}

int policy_load_bundle(policy_bundle_t *bundle) {
    KEEP_ASSERT(bundle != NULL);

    if (!initialized)
        return POLICY_ERR_STORAGE;

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

    /* The pin is raised to each bundle's created_at once it is stored, so a bundle in
     * flash that is older than the pin, or from another key, was put back or written
     * there some other way: a restored sector must not bring back an older policy. */
    policy_pin_t pin;
    int pin_ret = policy_pin_read(&pin);
    if (pin_ret == 0) {
        int ret = 0;
        if (ct_compare(bundle->warden_pubkey, pin.warden_pubkey, POLICY_PUBKEY_LEN) != 0) {
            ret = POLICY_ERR_WARDEN;
        } else if (bundle->created_at < pin.created_at) {
            ret = POLICY_ERR_ROLLBACK;
        }
        if (ret != 0) {
            secure_memzero(bundle, sizeof(policy_bundle_t));
            return ret;
        }
    } else if (pin_ret != POLICY_ERR_NOT_FOUND) {
        secure_memzero(bundle, sizeof(policy_bundle_t));
        return POLICY_ERR_STORAGE;
    }

    return 0;
}

int policy_delete_bundle(void) {
    if (!initialized)
        return POLICY_ERR_STORAGE;

    esp_err_t err = esp_partition_erase_range(policy_partition, 0, SECTOR_SIZE);
    if (err != ESP_OK) {
        return POLICY_ERR_STORAGE;
    }

    ESP_LOGI(TAG, "Policy bundle deleted");
    return 0;
}

bool policy_has_bundle(void) {
    /* Pinned means a policy is in force even if the bundle is missing or unreadable, so
     * signing fails closed instead of treating the device as unrestricted. */
    policy_pin_t pin;
    if (policy_pin_read(&pin) != POLICY_ERR_NOT_FOUND)
        return true;

    if (!initialized)
        return false;

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

static int policy_verify_signature(const policy_bundle_t *bundle) {
    KEEP_ASSERT(bundle != NULL);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx)
        return POLICY_ERR_INVALID_SIG;

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

secresult_t policy_verify_signature_secure(const policy_bundle_t *bundle) {
    int ret = policy_verify_signature(bundle);
    if (ret == 0)
        return SECRESULT_TRUE;
    return SECRESULT_ERR_INVALID_SIG;
}

static int policy_check_hash(const policy_bundle_t *bundle,
                             const uint8_t expected_hash[POLICY_HASH_LEN]) {
    if (ct_compare(bundle->policy_hash, expected_hash, POLICY_HASH_LEN) != 0) {
        return POLICY_ERR_HASH_MISMATCH;
    }
    return 0;
}

secresult_t policy_check_hash_secure(const policy_bundle_t *bundle,
                                     const uint8_t expected_hash[POLICY_HASH_LEN]) {
    int ret = policy_check_hash(bundle, expected_hash);
    if (ret == 0)
        return SECRESULT_TRUE;
    return SECRESULT_ERR_HASH_MISMATCH;
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
    if (ret == POLICY_ERR_MALFORMED) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_PARAMS, "Malformed policy");
        return;
    }
    if (ret == POLICY_ERR_WARDEN) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_PARAMS,
                       "Policy not signed by the pinned Warden key");
        return;
    }
    if (ret == POLICY_ERR_ROLLBACK) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_PARAMS,
                       "Policy is not newer than the installed one");
        return;
    }
    if (ret == POLICY_ERR_UNCONFIRMED) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_PARAMS,
                       "Warden key not confirmed on the device");
        return;
    }
    if (ret != 0) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_STORAGE, "Storage error");
        return;
    }

    sign_approval_clear();
    frost_signer_discard_sessions();
    protocol_success(resp, req->id, "{\"ok\":true}");
}

void policy_handle_get(const rpc_request_t *req, rpc_response_t *resp) {
    if (!policy_has_bundle()) {
        protocol_success(resp, req->id, "{\"has_policy\":false}");
        return;
    }

    policy_bundle_t bundle;
    int ret = policy_load_bundle(&bundle);
    if (ret == 0 && policy_verify_signature(&bundle) != 0)
        ret = POLICY_ERR_INVALID_SIG;
    if (ret != 0) {
        secure_memzero(&bundle, sizeof(bundle));
        policy_pin_t pin;
        if (policy_pin_read(&pin) != 0) {
            PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_STORAGE, "Load error");
            return;
        }
        char pin_hex[65];
        bytes_to_hex(pin.warden_pubkey, POLICY_PUBKEY_LEN, pin_hex, sizeof(pin_hex));
        char result[192];
        snprintf(result, sizeof(result),
                 "{\"has_policy\":true,\"bundle_valid\":false,\"warden_pubkey\":\"%s\","
                 "\"created_at\":%llu}",
                 pin_hex, (unsigned long long)pin.created_at);
        protocol_success(resp, req->id, result);
        return;
    }

    char policy_hash_hex[65];
    bytes_to_hex(bundle.policy_hash, POLICY_HASH_LEN, policy_hash_hex, sizeof(policy_hash_hex));

    char warden_pubkey_hex[65];
    bytes_to_hex(bundle.warden_pubkey, POLICY_PUBKEY_LEN, warden_pubkey_hex,
                 sizeof(warden_pubkey_hex));

    char result[512];
    int written = snprintf(result, sizeof(result),
                           "{\"has_policy\":true,\"version\":%d,\"policy_hash\":\"%s\",\"warden_"
                           "pubkey\":\"%s\",\"rules_len\":%lu,\"created_at\":%llu}",
                           bundle.version, policy_hash_hex, warden_pubkey_hex,
                           (unsigned long)bundle.rules_len, (unsigned long long)bundle.created_at);

    secure_memzero(&bundle, sizeof(bundle));

    if (written < 0 || (size_t)written >= sizeof(result)) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_INTERNAL, "Response buffer overflow");
        return;
    }

    protocol_success(resp, req->id, result);
}

/* Loads, verifies and parses the installed bundle's rules. TRUE with *rules NULL
 * means a verified bundle that carries no rules. */
static secresult_t load_rules_secure(cJSON **rules) {
    *rules = NULL;
    ag_random_delay_us(100, 1000);

    policy_bundle_t bundle;
    int ret = policy_load_bundle(&bundle);
    if (ret != 0) {
        secure_memzero(&bundle, sizeof(bundle));
        return SECRESULT_ERR_LOAD_FAILED;
    }

    ag_random_delay_us(100, 1000);

    secresult_t sig_result = policy_verify_signature_secure(&bundle);
    secresult_t sig_verified = ag_verify_condition_secure(sig_result);
    if (!SECRESULT_IS_TRUE(sig_verified)) {
        secure_memzero(&bundle, sizeof(bundle));
        return sig_result;
    }

    if (bundle.rules_len == 0 || bundle.rules_len > POLICY_MAX_RULES_LEN) {
        secure_memzero(&bundle, sizeof(bundle));
        return SECRESULT_TRUE;
    }

    char rules_str[POLICY_MAX_RULES_LEN + 1];
    memcpy(rules_str, bundle.rules, bundle.rules_len);
    rules_str[bundle.rules_len] = '\0';
    secure_memzero(&bundle, sizeof(bundle));

    *rules = cJSON_ParseWithOpts(rules_str, NULL, 1);
    secure_memzero(rules_str, sizeof(rules_str));
    return *rules ? SECRESULT_TRUE : SECRESULT_ERR_POLICY_DENIED;
}

secresult_t policy_allows_raw_secure(void) {
    if (!policy_has_bundle()) {
        return SECRESULT_TRUE;
    }

    cJSON *rules = NULL;
    secresult_t loaded = load_rules_secure(&rules);
    if (!SECRESULT_IS_TRUE(loaded)) {
        return loaded;
    }
    bool allowed = rules && cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(rules, "allow_raw"));
    cJSON_Delete(rules);
    return ag_verify_condition_secure(allowed ? SECRESULT_TRUE : SECRESULT_ERR_POLICY_DENIED);
}

secresult_t policy_evaluate_secure(uint64_t total_out_sats, uint64_t fee_sats) {
    if (!policy_has_bundle()) {
        return SECRESULT_TRUE;
    }

    cJSON *rules = NULL;
    secresult_t loaded = load_rules_secure(&rules);
    if (!SECRESULT_IS_TRUE(loaded)) {
        return loaded;
    }
    if (!rules) {
        return SECRESULT_TRUE;
    }

    ag_random_delay_us(100, 1000);

    secresult_t result = SECRESULT_TRUE;

    cJSON *max_amount = cJSON_GetObjectItem(rules, "max_amount");
    if (max_amount && cJSON_IsNumber(max_amount)) {
        uint64_t limit = (uint64_t)max_amount->valuedouble;
        ag_random_delay_us(50, 500);
        if (total_out_sats > limit) {
            ESP_LOGW(TAG, "Policy denied: amount %llu exceeds max %llu",
                     (unsigned long long)total_out_sats, (unsigned long long)limit);
            result = SECRESULT_ERR_POLICY_DENIED;
        }
    }

    if (SECRESULT_IS_TRUE(result)) {
        cJSON *max_fee = cJSON_GetObjectItem(rules, "max_fee");
        if (max_fee && cJSON_IsNumber(max_fee)) {
            uint64_t limit = (uint64_t)max_fee->valuedouble;
            ag_random_delay_us(50, 500);
            if (fee_sats > limit) {
                ESP_LOGW(TAG, "Policy denied: fee %llu exceeds max %llu",
                         (unsigned long long)fee_sats, (unsigned long long)limit);
                result = SECRESULT_ERR_POLICY_DENIED;
            }
        }
    }

    cJSON_Delete(rules);
    return ag_verify_condition_secure(result);
}

secresult_t policy_evaluate_psbt_secure(const char *psbt_base64, uint64_t total_in_sats,
                                        const uint8_t *wallet_fingerprint, bool allow_high_fee,
                                        bool allow_dust, bool allow_unknown_scripts,
                                        bool allow_op_return, bool allow_no_change,
                                        bool allow_all_external) {
    if (!psbt_base64) {
        return SECRESULT_ERR_POLICY_DENIED;
    }

    psbt_fraud_analysis_t fraud;
    int ret = psbt_fraud_analyze(psbt_base64, total_in_sats, wallet_fingerprint, &fraud);
    if (ret != 0) {
        secure_memzero(&fraud, sizeof(fraud));
        ESP_LOGW(TAG, "PSBT fraud analysis failed: %d", ret);
        return SECRESULT_ERR_POLICY_DENIED;
    }

    secresult_t fraud_result =
        psbt_fraud_check_secure(&fraud, allow_high_fee, allow_dust, allow_unknown_scripts,
                                allow_op_return, allow_no_change, allow_all_external);
    if (!SECRESULT_IS_TRUE(fraud_result)) {
        ESP_LOGW(TAG, "PSBT fraud check failed: flags=0x%" PRIx32, fraud.flags);
        secure_memzero(&fraud, sizeof(fraud));
        return fraud_result;
    }

    secresult_t policy_result =
        policy_evaluate_secure(fraud.fee.send_amount_sats, fraud.fee.fee_sats);
    secure_memzero(&fraud, sizeof(fraud));
    if (!SECRESULT_IS_TRUE(policy_result)) {
        return policy_result;
    }

    return SECRESULT_TRUE;
}
