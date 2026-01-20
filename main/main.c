// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "sdkconfig.h"

#include "protocol.h"
#include "serial.h"
#include "storage.h"
#include "storage_crypto.h"
#include "frost_signer.h"
#include "frost_dkg.h"
#include "psbt.h"
#include "policy.h"
#include "secresult.h"
#include "random_utils.h"
#include "anti_glitch.h"
#include "hex_utils.h"
#include "ux_interface.h"
#include "self_test.h"

#define TAG                  "main"
#define VERSION              "0.1.2"
#define RATE_LIMIT_THRESHOLD 5
#define RATE_LIMIT_DELAY_MS  1000

static int consecutive_errors = 0;
static bool psbt_initialized = false;

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
    char result[384];
    snprintf(result, sizeof(result),
             "{\"version\":\"%s\",\"rng_healthy\":%s,\"rng_total_calls\":%lu,\"rng_failed_checks\":"
             "%lu,\"rng_retries\":%lu,\"self_test_passed\":%lu,\"self_test_failed\":%lu,"
             "\"self_test_ok\":%s}",
             VERSION, rng_stats.healthy ? "true" : "false", (unsigned long)rng_stats.total_calls,
             (unsigned long)rng_stats.failed_checks, (unsigned long)rng_stats.retries,
             (unsigned long)st_stats.passed, (unsigned long)st_stats.failed,
             st_stats.all_required_passed ? "true" : "false");
    protocol_success(resp, req->id, result);
}

static void handle_restart(const rpc_request_t *req, rpc_response_t *resp) {
    protocol_success(resp, req->id, "{\"restarting\":true}");
    vTaskDelay(pdMS_TO_TICKS(100));
    esp_restart();
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
    int ret = storage_save_share(req->group, req->share);

    switch (ret) {
    case STORAGE_OK:
        protocol_success(resp, req->id, "{\"ok\":true}");
        break;
    case STORAGE_ERR_CRYPTO_NOT_INIT:
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_STORAGE, "Storage crypto not initialized");
        break;
    case STORAGE_ERR_INVALID_GROUP:
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_PARAMS, "Invalid group name");
        break;
    case STORAGE_ERR_INVALID_DATA:
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_PARAMS, "Invalid share data");
        break;
    case STORAGE_ERR_NO_SLOT:
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_STORAGE, "No free storage slot");
        break;
    default:
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_STORAGE, "Storage error");
        break;
    }
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
    default:
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_STORAGE, "Storage error");
        break;
    }
}

static void handle_bitcoin_parse(const rpc_request_t *req, rpc_response_t *resp) {
    if (!psbt_initialized) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_INTERNAL, "PSBT not initialized");
        return;
    }
    if (!req->psbt) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_PARAMS, "Missing psbt");
        return;
    }

    psbt_summary_t summary;
    int ret = psbt_parse(req->psbt, &summary);
    if (ret != 0) {
        char err_msg[64];
        snprintf(err_msg, sizeof(err_msg), "PSBT parse error: %d", ret);
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_PARAMS, err_msg);
        return;
    }

    char result[256];
    snprintf(result, sizeof(result),
             "{\"inputs\":%zu,\"outputs\":%zu,\"total_in_sats\":%llu,\"total_out_sats\":%llu,\"fee_"
             "sats\":%llu}",
             summary.input_count, summary.output_count, (unsigned long long)summary.total_in_sats,
             (unsigned long long)summary.total_out_sats, (unsigned long long)summary.fee_sats);
    protocol_success(resp, req->id, result);
}

static void handle_bitcoin_sign(const rpc_request_t *req, rpc_response_t *resp) {
    if (!psbt_initialized) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_INTERNAL, "PSBT not initialized");
        return;
    }
    if (!req->psbt) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_PARAMS, "Missing psbt");
        return;
    }

    psbt_summary_t summary;
    if (psbt_parse(req->psbt, &summary) != 0) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_PARAMS, "Failed to parse PSBT");
        return;
    }

    secresult_t policy_ret = policy_evaluate_secure(summary.total_out_sats, summary.fee_sats);
    if (!SECRESULT_IS_TRUE(policy_ret)) {
        if (policy_ret == SECRESULT_ERR_POLICY_DENIED) {
            PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_SIGN, "Policy denied");
        } else {
            PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_SIGN, "Policy evaluation failed");
        }
        return;
    }

    uint8_t sighash[32];
    if (psbt_get_sighash(req->psbt, req->input_idx, sighash) != 0) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_SIGN, "Failed to get sighash");
        return;
    }

    char hex[65];
    bytes_to_hex(sighash, 32, hex, sizeof(hex));

    char result[128];
    snprintf(result, sizeof(result), "{\"input_idx\":%zu,\"sighash\":\"%s\"}", req->input_idx, hex);
    protocol_success(resp, req->id, result);
}

static void handle_dkg_checkpoint(const rpc_request_t *req, rpc_response_t *resp) {
    size_t sid_len = strlen(req->session_id);
    if (sid_len == 0) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_PARAMS, "session_id required");
        return;
    }
    if (sid_len > DKG_SESSION_ID_LEN) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_PARAMS, "session_id too long");
        return;
    }

    dkg_state_t state = dkg_get_state();
    if (state != DKG_ROUND1 && state != DKG_ROUND2) {
        PROTOCOL_ERROR(resp, req->id, -1, "No active DKG session to checkpoint");
        return;
    }

    int ret = dkg_checkpoint_save(req->session_id);
    if (ret == STORAGE_ERR_CHECKPOINT_EXISTS) {
        PROTOCOL_ERROR(resp, req->id, -1, "Checkpoint already exists");
        return;
    }
    if (ret != 0) {
        PROTOCOL_ERROR(resp, req->id, -1, "Failed to save checkpoint");
        return;
    }

    protocol_success(resp, req->id, "{\"ok\":true}");
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
        frost_commit(req->group, req->session_id, req->message, resp);
        break;
    case RPC_METHOD_FROST_SIGN:
        frost_sign(req->group, req->session_id, req->commitments, resp);
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
    case RPC_METHOD_DKG_INIT:
        dkg_init(req, resp);
        break;
    case RPC_METHOD_DKG_ROUND1:
        dkg_round1(req, resp);
        break;
    case RPC_METHOD_DKG_ROUND1_PEER:
        dkg_round1_peer(req, resp);
        break;
    case RPC_METHOD_DKG_ROUND2:
        dkg_round2(req, resp);
        break;
    case RPC_METHOD_DKG_RECEIVE_SHARE:
        dkg_receive_share(req, resp);
        break;
    case RPC_METHOD_DKG_FINALIZE:
        dkg_finalize(req, resp);
        break;
    case RPC_METHOD_DKG_RESUME:
        dkg_resume(req, resp);
        break;
    case RPC_METHOD_DKG_CHECKPOINT:
        handle_dkg_checkpoint(req, resp);
        break;
    case RPC_METHOD_BITCOIN_PARSE:
        handle_bitcoin_parse(req, resp);
        break;
    case RPC_METHOD_BITCOIN_SIGN:
        handle_bitcoin_sign(req, resp);
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
        frost_export_share(req->group, resp);
        break;
    case RPC_METHOD_SESSION_RESUME:
        frost_session_resume(req->session_id, resp);
        break;
    case RPC_METHOD_SESSION_LIST:
        frost_session_list(resp);
        break;
    default:
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_METHOD, "Method not found");
    }
}

void app_main(void) {
    ESP_LOGI(TAG, "=================================");
    ESP_LOGI(TAG, "  Keep Hardware - FROST Signer");
    ESP_LOGI(TAG, "  Version: %s", VERSION);
    ESP_LOGI(TAG, "=================================");

    ag_init();

    if (rng_init() != 0) {
        ESP_LOGE(TAG, "RNG self-test failed, restarting");
        esp_restart();
    }

    ag_random_delay_ms(AG_BOOT_DELAY_MIN_MS, AG_BOOT_DELAY_MAX_MS);

    if (storage_init() != 0) {
        ESP_LOGW(TAG, "Storage init failed, continuing without storage");
    }

    ag_random_delay_ms(AG_BOOT_DELAY_MIN_MS, AG_BOOT_DELAY_MAX_MS);

    if (storage_crypto_init(NULL) != 0) {
        ESP_LOGE(TAG, "Storage crypto init failed - share storage operations will be unavailable");
    } else {
        int migrate_ret = storage_migrate_if_needed();
        if (migrate_ret == STORAGE_ERR_IO) {
            ESP_LOGE(TAG, "Storage migration failed with IO error, restarting");
            esp_restart();
        } else if (migrate_ret != STORAGE_OK && migrate_ret != STORAGE_ERR_NOT_INIT) {
            ESP_LOGW(TAG, "Storage migration failed: %d (continuing with existing data)",
                     migrate_ret);
        }
    }

    ag_random_delay_ms(AG_BOOT_DELAY_MIN_MS, AG_BOOT_DELAY_MAX_MS);

    if (self_test_run_all() != 0) {
        ESP_LOGE(TAG, "Critical self-test failed, restarting");
        esp_restart();
    }

    ag_random_delay_ms(AG_BOOT_DELAY_MIN_MS, AG_BOOT_DELAY_MAX_MS);

    if (policy_init() != 0) {
        ESP_LOGW(TAG, "Policy init failed, continuing without policy");
    }

    ag_random_delay_ms(AG_BOOT_DELAY_MIN_MS, AG_BOOT_DELAY_MAX_MS);

    frost_signer_init();

    int psbt_ret = psbt_init();
    if (psbt_ret != 0) {
        ESP_LOGW(TAG, "PSBT init failed: %d", psbt_ret);
    } else {
        psbt_initialized = true;
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

    const ux_backend_t *ux = ux_get_backend();
    if (ux != NULL && ux->show_idle != NULL) {
        ux->show_idle("keep", policy_has_bundle(), POLICY_VERSION);
    } else {
        ESP_LOGW(TAG, "UX backend or show_idle unavailable");
    }

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
                handle_request(&req, &resp);
                protocol_free_request(&req);
            } else {
                PROTOCOL_ERROR(&resp, 0, PROTOCOL_ERR_PARSE, "Parse error");
            }
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
