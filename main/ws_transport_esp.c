// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include "ws_transport.h"

#include "esp_crt_bundle.h"
#include "esp_websocket_client.h"
#include "log_compat.h"

#include <freertos/FreeRTOS.h>
#include <stdlib.h>

#define TAG "ws_transport"

#define WS_OPCODE_TEXT 0x01

struct ws_transport {
    esp_websocket_client_handle_t client;
    ws_event_cb_t cb;
    void *user_ctx;
};

static void emit(struct ws_transport *t, ws_event_type_t type, const char *data, size_t len) {
    if (t->cb) {
        ws_event_t event = {.type = type, .data = data, .len = len};
        t->cb(t->user_ctx, &event);
    }
}

static void on_ws_data(struct ws_transport *t, esp_websocket_event_data_t *data) {
    if (data->op_code != WS_OPCODE_TEXT || data->data_len == 0)
        return;

    // Only whole single-frame messages are delivered. The rx buffer bounds the
    // largest event we accept, so a fragmented message is a message we could not
    // have parsed anyway; drop it loudly rather than hand up a truncated prefix.
    if (data->payload_offset != 0 || (size_t)data->data_len != (size_t)data->payload_len) {
        ESP_LOGW(TAG, "Dropping fragmented message (%d of %d bytes)", data->data_len,
                 data->payload_len);
        return;
    }

    emit(t, WS_EVT_DATA, data->data_ptr, (size_t)data->data_len);
}

static void ws_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id,
                             void *event_data) {
    (void)base;
    struct ws_transport *t = handler_args;

    switch (event_id) {
    case WEBSOCKET_EVENT_CONNECTED:
        emit(t, WS_EVT_CONNECTED, NULL, 0);
        break;
    case WEBSOCKET_EVENT_DISCONNECTED:
        emit(t, WS_EVT_DISCONNECTED, NULL, 0);
        break;
    case WEBSOCKET_EVENT_DATA:
        on_ws_data(t, event_data);
        break;
    case WEBSOCKET_EVENT_ERROR:
        emit(t, WS_EVT_ERROR, NULL, 0);
        break;
    default:
        break;
    }
}

ws_transport_handle_t ws_transport_create(const ws_transport_config_t *config, ws_event_cb_t cb,
                                          void *user_ctx) {
    if (!config || !config->url)
        return NULL;

    struct ws_transport *t = calloc(1, sizeof(*t));
    if (!t)
        return NULL;

    t->cb = cb;
    t->user_ctx = user_ctx;

    esp_websocket_client_config_t ws_cfg = {
        .uri = config->url,
        .buffer_size = (int)config->rx_buffer_size,
        .crt_bundle_attach = esp_crt_bundle_attach,
        // The coordinator owns reconnection so it can apply exponential backoff
        // and a max-attempt cap; the client's own retry loop would fight it.
        .disable_auto_reconnect = true,
        .ping_interval_sec = config->ping_interval_sec,
        .pingpong_timeout_sec = (int)config->pong_timeout_sec,
        .network_timeout_ms = (int)config->network_timeout_ms,
    };

    t->client = esp_websocket_client_init(&ws_cfg);
    if (!t->client) {
        free(t);
        return NULL;
    }

    if (esp_websocket_register_events(t->client, WEBSOCKET_EVENT_ANY, ws_event_handler, t) !=
        ESP_OK) {
        esp_websocket_client_destroy(t->client);
        free(t);
        return NULL;
    }

    return t;
}

int ws_transport_start(ws_transport_handle_t handle) {
    if (!handle)
        return -1;
    return esp_websocket_client_start(handle->client) == ESP_OK ? 0 : -1;
}

void ws_transport_destroy(ws_transport_handle_t handle) {
    if (!handle)
        return;
    esp_websocket_client_stop(handle->client);
    esp_websocket_client_destroy(handle->client);
    free(handle);
}

int ws_transport_send_text(ws_transport_handle_t handle, const char *data, size_t len,
                           uint32_t timeout_ms) {
    if (!handle || !data)
        return -1;
    int sent =
        esp_websocket_client_send_text(handle->client, data, (int)len, pdMS_TO_TICKS(timeout_ms));
    return sent < 0 ? -1 : 0;
}
