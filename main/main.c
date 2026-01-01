#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "sdkconfig.h"

#include "protocol.h"
#include "serial.h"
#include "storage.h"
#include "frost_signer.h"

#define TAG "main"
#define VERSION "0.1.0"
#define RATE_LIMIT_THRESHOLD 5
#define RATE_LIMIT_DELAY_MS 1000

static int consecutive_errors = 0;

static void handle_ping(const rpc_request_t *req, rpc_response_t *resp) {
    char result[64];
    snprintf(result, sizeof(result), "{\"version\":\"%s\"}", VERSION);
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
        protocol_error(resp, req->id, PROTOCOL_ERR_INTERNAL, "Buffer error");
        return;
    }
    offset = (size_t)ret;

    for (int i = 0; i < count; i++) {
        ret = snprintf(result + offset, buf_size - offset,
                       "%s\"%s\"", (i > 0) ? "," : "", groups[i]);
        if (ret < 0 || (size_t)ret >= buf_size - offset) {
            protocol_error(resp, req->id, PROTOCOL_ERR_INTERNAL, "Buffer overflow");
            return;
        }
        offset += (size_t)ret;
    }

    ret = snprintf(result + offset, buf_size - offset, "]}");
    if (ret < 0 || (size_t)ret >= buf_size - offset) {
        protocol_error(resp, req->id, PROTOCOL_ERR_INTERNAL, "Buffer overflow");
        return;
    }

    protocol_success(resp, req->id, result);
}

static void handle_import_share(const rpc_request_t *req, rpc_response_t *resp) {
    if (storage_save_share(req->group, req->share) == 0) {
        protocol_success(resp, req->id, "{\"ok\":true}");
    } else {
        protocol_error(resp, req->id, PROTOCOL_ERR_STORAGE, "Storage error");
    }
}

static void handle_delete_share(const rpc_request_t *req, rpc_response_t *resp) {
    if (storage_delete_share(req->group) == 0) {
        protocol_success(resp, req->id, "{\"ok\":true}");
    } else {
        protocol_error(resp, req->id, PROTOCOL_ERR_STORAGE, "Storage error");
    }
}

static void handle_request(const rpc_request_t *req, rpc_response_t *resp) {
    resp->id = req->id;

    // Clean up expired sessions before handling request
    frost_signer_cleanup_stale();

    switch (req->method) {
        case RPC_METHOD_PING:
            handle_ping(req, resp);
            break;
        case RPC_METHOD_GET_SHARE_PUBKEY:
            frost_get_pubkey(req->group, resp);
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
        default:
            protocol_error(resp, req->id, PROTOCOL_ERR_METHOD, "Method not found");
    }
}

void app_main(void) {
    ESP_LOGI(TAG, "=================================");
    ESP_LOGI(TAG, "  Keep Hardware - FROST Signer");
    ESP_LOGI(TAG, "  Version: %s", VERSION);
    ESP_LOGI(TAG, "=================================");

    if (storage_init() != 0) {
        ESP_LOGW(TAG, "Storage init failed, continuing without storage");
    }

    frost_signer_init();

    if (serial_init() != 0) {
        ESP_LOGE(TAG, "Serial init failed, restarting");
        esp_restart();
    }

    ESP_LOGI(TAG, "Initialization complete");

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
            } else {
                protocol_error(&resp, 0, PROTOCOL_ERR_PARSE, "Parse error");
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
