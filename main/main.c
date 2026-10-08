// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "nvs_flash.h"
#include "sdkconfig.h"

#include "protocol.h"
#include "serial.h"
#include "storage.h"
#include "storage_crypto.h"
#include "frost_signer.h"
#include "bitcoin_rpc.h"
#include "policy.h"
#include "secresult.h"
#include "random_utils.h"
#include "anti_glitch.h"
#include "hex_utils.h"
#include "crypto_asm.h"
#include "ux_interface.h"
#include "self_test.h"
#include "frost_tr.h"
#include "frost_tr_task.h"
#include "ui_test.h"

#define TAG                  "main"
#define VERSION              "0.2.2"
#define RATE_LIMIT_THRESHOLD 5
#define RATE_LIMIT_DELAY_MS  1000

static int consecutive_errors = 0;

static void handle_ping(const rpc_request_t *req, rpc_response_t *resp) {
    uint32_t boot_counter = 0;
    ag_get_boot_counter(&boot_counter);
    char result[128];
    snprintf(result, sizeof(result),
             "{\"pong\":true,\"version\":\"%s\",\"protocol_version\":%d,\"boot_counter\":%lu}",
             VERSION, PROTOCOL_API_VERSION, (unsigned long)boot_counter);
    protocol_success(resp, req->id, result);
}

static void handle_get_status(const rpc_request_t *req, rpc_response_t *resp) {
    rng_health_stats_t rng_stats;
    rng_get_health(&rng_stats);
    self_test_stats_t st_stats;
    self_test_get_stats(&st_stats);
    char result[512];
    snprintf(result, sizeof(result),
             "{\"version\":\"%s\",\"rng_healthy\":%s,\"rng_entropy_source\":%s,\"rng_total_calls\":"
             "%lu,\"rng_failed_checks\":%lu,\"rng_retries\":%lu,\"self_test_passed\":%lu,"
             "\"self_test_failed\":%lu,\"self_test_ok\":%s,\"frost_stack_free_min\":%lu,"
             "\"heap_free_min\":%lu}",
             VERSION, rng_stats.healthy ? "true" : "false",
             rng_stats.entropy_source_verified ? "true" : "false",
             (unsigned long)rng_stats.total_calls, (unsigned long)rng_stats.failed_checks,
             (unsigned long)rng_stats.retries, (unsigned long)st_stats.passed,
             (unsigned long)st_stats.failed, st_stats.all_required_passed ? "true" : "false",
             (unsigned long)ftr_task_stack_free_min(),
             (unsigned long)heap_caps_get_minimum_free_size(MALLOC_CAP_DEFAULT));
    protocol_success(resp, req->id, result);
}

static void handle_restart(const rpc_request_t *req, rpc_response_t *resp) {
    protocol_success(resp, req->id, "{\"restarting\":true}");
    vTaskDelay(pdMS_TO_TICKS(100));
    esp_restart();
}

static void handle_unlock(const rpc_request_t *req, rpc_response_t *resp) {
    if (storage_crypto_is_initialized()) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_PARAMS, "Already unlocked");
        return;
    }

    if (strlen(req->pin) == 0) {
        PROTOCOL_ERROR(resp, req->id, ERR_PIN_INVALID, "PIN required");
        return;
    }

    int ret = storage_unlock(req->pin);
    if (ret == ERR_PIN_BRICKED) {
        PROTOCOL_ERROR(resp, req->id, ERR_PIN_BRICKED,
                       "Device bricked after too many PIN attempts");
        return;
    }
    if (ret == ERR_PIN_LOCKED) {
        PROTOCOL_ERROR(resp, req->id, ERR_PIN_LOCKED, "Device locked");
        return;
    }
    if (ret == ERR_PIN_NO_STATE) {
        PROTOCOL_ERROR(resp, req->id, ERR_PIN_NO_STATE,
                       "PIN attempt state cannot be stored on this device");
        return;
    }
    if (ret == ERR_PIN_MUST_WAIT) {
        PROTOCOL_ERROR(resp, req->id, ERR_PIN_MUST_WAIT, "Too many attempts, please wait");
        return;
    }
    if (ret == ERR_PIN_INVALID) {
        PROTOCOL_ERROR(resp, req->id, ERR_PIN_INVALID, "Invalid PIN");
        return;
    }
    if (ret == STORAGE_ERR_IO) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_STORAGE, "Could not record the PIN check");
        return;
    }
    if (ret == STORAGE_ERR_NOT_INIT) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_STORAGE, "Share storage unavailable");
        return;
    }
    if (ret != 0) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_INTERNAL, "Unlock failed");
        return;
    }

    int migrate_ret = storage_migrate_if_needed();
    if (migrate_ret == STORAGE_ERR_IO) {
        storage_crypto_clear();
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_STORAGE, "Migration failed");
        return;
    }
    if (migrate_ret != STORAGE_OK && migrate_ret != STORAGE_ERR_NOT_INIT) {
        ESP_LOGW(TAG, "Storage migration warning: %d", migrate_ret);
    }

    int migrated = 0, unmigratable = 0;
    int shares_ret = frost_signer_migrate_shares(&migrated, &unmigratable);
    if (shares_ret != 0) {
        ESP_LOGW(TAG, "Share migration incomplete: %d", shares_ret);
    }

    char result[128];
    snprintf(result, sizeof(result),
             "{\"unlocked\":true,\"shares_migrated\":%d,\"shares_unmigratable\":%d,"
             "\"migration_complete\":%s}",
             migrated, unmigratable, shares_ret == 0 ? "true" : "false");
    protocol_success(resp, req->id, result);
}

static void handle_list_shares(const rpc_request_t *req, rpc_response_t *resp) {
    char groups[STORAGE_MAX_SHARES][STORAGE_GROUP_LEN + 1];
    int count = storage_list_shares(groups, STORAGE_MAX_SHARES);

    char result[16 + STORAGE_MAX_SHARES * (STORAGE_GROUP_LEN + 4)];
    size_t buf_size = sizeof(result);
    size_t offset = 0;

    int ret = snprintf(result, buf_size, "{\"shares\":[");
    if (ret < 0 || (size_t)ret >= buf_size) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_INTERNAL, "Buffer error");
        return;
    }
    offset = (size_t)ret;

    for (int i = 0; i < count; i++) {
        ret =
            snprintf(result + offset, buf_size - offset, "%s\"%s\"", (i > 0) ? "," : "", groups[i]);
        if (ret < 0 || (size_t)ret >= buf_size - offset) {
            PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_INTERNAL, "Buffer overflow");
            return;
        }
        offset += (size_t)ret;
    }

    ret = snprintf(result + offset, buf_size - offset, "]}");
    if (ret < 0 || (size_t)ret >= buf_size - offset) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_INTERNAL, "Buffer overflow");
        return;
    }

    protocol_success(resp, req->id, result);
}

static void handle_import_share(const rpc_request_t *req, rpc_response_t *resp) {
    if (req->legacy_share) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_PARAMS,
                       "The share field is retired in protocol 2; send key_package and "
                       "participants");
        return;
    }
    frost_import_share(req->group, req->key_package, req->participants, resp);
}

static void handle_delete_share(const rpc_request_t *req, rpc_response_t *resp) {
    int ret = storage_delete_share(req->group);

    switch (ret) {
    case STORAGE_OK:
        protocol_success(resp, req->id, "{\"ok\":true}");
        break;
    case STORAGE_ERR_NOT_FOUND:
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_STORAGE, "Share not found");
        break;
    case STORAGE_ERR_CRYPTO_NOT_INIT:
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_STORAGE, "Unlock required");
        break;
    default:
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_STORAGE, "Storage error");
        break;
    }
}

static void handle_export_share(const rpc_request_t *req, rpc_response_t *resp) {
    if (storage_export_check_rate_limit() != STORAGE_OK) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_STORAGE, "Rate limited");
        return;
    }

    if (strlen(req->group) == 0) {
        storage_export_record_attempt(false);
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_PARAMS, "Missing group");
        return;
    }

    if (strlen(req->passphrase) < 8) {
        storage_export_record_attempt(false);
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_PARAMS,
                       "Passphrase must be at least 8 characters");
        return;
    }

    share_export_meta_t meta;
    if (frost_signer_export_meta(req->group, &meta) != 0) {
        storage_export_record_attempt(false);
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_SHARE, "Share not found");
        return;
    }

    share_export_t export_data;
    int ret = storage_export_share(req->group, req->passphrase, &meta, &export_data);
    if (ret != STORAGE_OK) {
        storage_export_record_attempt(false);
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_STORAGE, "Export failed");
        return;
    }

    storage_export_record_attempt(true);

    char pubkey_hex[67];
    char encrypted_hex[(STORAGE_SHARE_LEN + 16) * 2 + 1];
    char nonce_hex[25];
    char salt_hex[65];
    char checksum_hex[65];
    bytes_to_hex(export_data.group_pubkey, sizeof(export_data.group_pubkey), pubkey_hex,
                 sizeof(pubkey_hex));
    bytes_to_hex(export_data.encrypted_share, export_data.encrypted_len, encrypted_hex,
                 sizeof(encrypted_hex));
    bytes_to_hex(export_data.nonce, sizeof(export_data.nonce), nonce_hex, sizeof(nonce_hex));
    bytes_to_hex(export_data.salt, sizeof(export_data.salt), salt_hex, sizeof(salt_hex));
    bytes_to_hex(export_data.checksum, sizeof(export_data.checksum), checksum_hex,
                 sizeof(checksum_hex));

    char result[2048];
    snprintf(result, sizeof(result),
             "{\"version\":%d,\"group\":\"%s\",\"share_index\":%d,\"threshold\":%d,"
             "\"participants\":%d,\"group_pubkey\":\"%s\",\"encrypted_share\":\"%s\","
             "\"nonce\":\"%s\",\"salt\":\"%s\",\"checksum\":\"%s\"}",
             STORAGE_EXPORT_VERSION, req->group, export_data.share_index, export_data.threshold,
             export_data.participants, pubkey_hex, encrypted_hex, nonce_hex, salt_hex,
             checksum_hex);
    secure_memzero(&export_data, sizeof(export_data));
    secure_memzero(pubkey_hex, sizeof(pubkey_hex));
    secure_memzero(encrypted_hex, sizeof(encrypted_hex));
    secure_memzero(nonce_hex, sizeof(nonce_hex));
    secure_memzero(salt_hex, sizeof(salt_hex));
    secure_memzero(checksum_hex, sizeof(checksum_hex));
    protocol_success(resp, req->id, result);
}

static void handle_request(const rpc_request_t *req, rpc_response_t *resp) {
    resp->id = req->id;
    frost_signer_cleanup_stale();

    switch (req->method) {
    case RPC_METHOD_PING:
        handle_ping(req, resp);
        break;
    case RPC_METHOD_GET_SHARE_PUBKEY:
        frost_get_pubkey(req->group, resp);
        break;
    case RPC_METHOD_GET_SHARE_INFO:
        frost_get_share_info(req->group, resp);
        break;
    case RPC_METHOD_FROST_COMMIT:
        frost_commit(req->group, req->session_id, req->message, req->derivation_path,
                     req->derivation_path_len, req->taproot_tweak,
                     req->has_merkle_root ? req->merkle_root : NULL, resp);
        break;
    case RPC_METHOD_FROST_SIGN:
        frost_sign(req->group, req->session_id, req->signing_package, resp);
        break;
    case RPC_METHOD_IMPORT_SHARE:
        handle_import_share(req, resp);
        break;
    case RPC_METHOD_DELETE_SHARE:
        handle_delete_share(req, resp);
        break;
    case RPC_METHOD_LIST_SHARES:
        handle_list_shares(req, resp);
        break;
    case RPC_METHOD_BITCOIN_PARSE:
        bitcoin_rpc_parse(req, resp);
        break;
    case RPC_METHOD_BITCOIN_SIGN:
        bitcoin_rpc_sign(req, resp);
        break;
    case RPC_METHOD_POLICY_UPDATE:
        policy_handle_update(req, resp);
        break;
    case RPC_METHOD_POLICY_GET:
        policy_handle_get(req, resp);
        break;
    case RPC_METHOD_GET_STATUS:
        handle_get_status(req, resp);
        break;
    case RPC_METHOD_RESTART:
        handle_restart(req, resp);
        break;
    case RPC_METHOD_EXPORT_SHARE:
        handle_export_share(req, resp);
        break;
    case RPC_METHOD_UNLOCK:
        handle_unlock(req, resp);
        break;
    case RPC_METHOD_RETIRED:
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_METHOD, "Method not available in protocol 2");
        break;
    default:
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_METHOD, "Method not found");
    }
}

static void app_init(void) {
    ESP_LOGI(TAG, "=================================");
    ESP_LOGI(TAG, "  Keep Hardware - FROST Signer");
    ESP_LOGI(TAG, "  Version: %s", VERSION);
    ESP_LOGI(TAG, "=================================");

    ag_init();

    if (rng_init() != 0) {
        ESP_LOGE(TAG, "RNG self-test failed, restarting");
        esp_restart();
    }
    if (ftr_init(rng_fill_checked, rng_is_healthy_secure) != 0 || ftr_task_start() != 0) {
        ESP_LOGE(TAG, "FROST init failed, restarting");
        esp_restart();
    }

    ag_random_delay_ms(AG_BOOT_DELAY_MIN_MS, AG_BOOT_DELAY_MAX_MS);

    esp_err_t nvs_ret = nvs_flash_init();
    if (nvs_ret != ESP_OK) {
        ESP_LOGE(TAG, "NVS init failed (%s); PIN unlock needs a secure element",
                 esp_err_to_name(nvs_ret));
    }
    storage_crypto_set_pin_state_persistent(nvs_ret == ESP_OK);

    if (storage_init() != 0) {
        ESP_LOGW(TAG, "Storage init failed, continuing without storage");
    }

    ag_random_delay_ms(AG_BOOT_DELAY_MIN_MS, AG_BOOT_DELAY_MAX_MS);

    ESP_LOGI(TAG, "PIN-protected storage enabled - share operations require PIN");

    ag_random_delay_ms(AG_BOOT_DELAY_MIN_MS, AG_BOOT_DELAY_MAX_MS);

    if (self_test_run_all() != 0) {
        ESP_LOGE(TAG, "Critical self-test failed, restarting");
        esp_restart();
    }

    ag_random_delay_ms(AG_BOOT_DELAY_MIN_MS, AG_BOOT_DELAY_MAX_MS);

    if (policy_init() != 0) {
        ESP_LOGW(TAG, "Policy init failed, continuing without policy");
    }
    policy_raise_lagging_pin();

    ag_random_delay_ms(AG_BOOT_DELAY_MIN_MS, AG_BOOT_DELAY_MAX_MS);

    frost_signer_init();

    int psbt_ret = bitcoin_rpc_init();
    if (psbt_ret != 0) {
        ESP_LOGW(TAG, "PSBT init failed: %d", psbt_ret);
    } else {
        ESP_LOGI(TAG, "PSBT support initialized");
    }

    ag_random_delay_ms(AG_BOOT_DELAY_MIN_MS, AG_BOOT_DELAY_MAX_MS);

    if (serial_init() != 0) {
        ESP_LOGE(TAG, "Serial init failed, restarting");
        esp_restart();
    }

    ag_random_delay_ms(AG_BOOT_DELAY_MIN_MS, AG_BOOT_DELAY_MAX_MS);

    if (ux_init() != 0) {
        ESP_LOGE(TAG, "UX init failed, restarting");
        esp_restart();
    }
    if (strcmp(ux_get_backend()->name, "display") == 0) {
        ui_test_init();
    }

    const ux_backend_t *ux = ux_get_backend();
    if (ux != NULL && ux->show_idle != NULL) {
        ux->show_idle("keep", policy_has_bundle(), POLICY_VERSION);
    } else {
        ESP_LOGW(TAG, "UX backend or show_idle unavailable");
    }
}

void app_main(void) {
    app_init();

    static char line_buf[PROTOCOL_MAX_MESSAGE_LEN];
    static char resp_buf[PROTOCOL_MAX_MESSAGE_LEN];
    static rpc_request_t req;
    static rpc_response_t resp;

    while (1) {
        int len = serial_read_line(line_buf, sizeof(line_buf));
        if (len > 0) {
            if (consecutive_errors >= RATE_LIMIT_THRESHOLD) {
                vTaskDelay(pdMS_TO_TICKS(RATE_LIMIT_DELAY_MS));
            }
            memset(&resp, 0, sizeof(resp));
            if (protocol_parse_request(line_buf, &req) == 0) {
                if (!ui_test_handle(line_buf, &req, &resp)) {
                    handle_request(&req, &resp);
                }
            } else {
                PROTOCOL_ERROR(&resp, 0, PROTOCOL_ERR_PARSE, "Parse error");
            }
            protocol_free_request(&req);
            /* The line may have carried a key package or PIN. */
            secure_memzero(line_buf, sizeof(line_buf));
            if (resp.success) {
                consecutive_errors = 0;
            } else {
                consecutive_errors++;
            }
            int fmt_ret = protocol_format_response(&resp, resp_buf, sizeof(resp_buf));
            if (fmt_ret >= 0) {
                serial_write_line(resp_buf);
            } else {
                ESP_LOGE(TAG, "Response formatting failed");
            }
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}
