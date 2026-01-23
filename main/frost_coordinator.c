// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include "frost_coordinator.h"
#include "nostr_frost.h"
#include "crypto_asm.h"
#include "hex_utils.h"
#include "random_utils.h"
#include "cJSON.h"
#include <noscrypt.h>
#include <string.h>
#include <stdlib.h>

#include "log_compat.h"

#ifdef ESP_PLATFORM
#include "esp_websocket_client.h"
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#endif

#define TAG                  "frost_coord"
#define MAX_PUBLISH_MSG_SIZE 4108

static bool is_safe_subscription_id(const char *id) {
    if (!id || *id == '\0')
        return false;
    size_t len = 0;
    for (const char *p = id; *p; p++) {
        char c = *p;
        bool valid = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                     c == '-' || c == '_';
        if (!valid)
            return false;
        if (++len > 64)
            return false;
    }
    return true;
}

#ifdef ESP_PLATFORM
#define COORDINATOR_LOCK()   xSemaphoreTake(g_ctx.mutex, portMAX_DELAY)
#define COORDINATOR_UNLOCK() xSemaphoreGive(g_ctx.mutex)
#else
#define COORDINATOR_LOCK()
#define COORDINATOR_UNLOCK()
#endif

typedef struct {
    char *json;
    size_t len;
} buffered_event_t;

typedef struct {
    char url[RELAY_URL_LEN];
    coordinator_state_t state;
    ws_health_t health;
    ws_reconnect_t reconnect;
    uint32_t success_count;
    uint32_t fail_count;
#ifdef ESP_PLATFORM
    esp_websocket_client_handle_t ws_handle;
#else
    void *ws_handle;
#endif
} relay_connection_t;

typedef struct {
    uint8_t privkey[32];
    uint8_t pubkey[32];
    relay_connection_t relays[COORDINATOR_MAX_RELAYS];
    uint8_t relay_count;
    frost_group_t current_group;
    bool has_group;
    coordinator_state_t state;
    frost_coordinator_callbacks_t callbacks;
    NCContext *nc_ctx;
    char current_subscription[64];
    bool has_subscription;
    buffered_event_t event_buffer[WS_EVENT_BUFFER_SIZE];
    uint8_t buffer_head;
    uint8_t buffer_count;
    uint32_t disconnect_time;
#ifdef ESP_PLATFORM
    SemaphoreHandle_t mutex;
#endif
} coordinator_ctx_t;

static coordinator_ctx_t g_ctx;
static bool g_initialized = false;

#ifdef ESP_PLATFORM
#include "esp_timer.h"
#endif

static uint32_t coordinator_now_ms(void) {
#ifdef ESP_PLATFORM
    return (uint32_t)(esp_timer_get_time() / 1000);
#else
    return 0;
#endif
}

static uint32_t calculate_backoff(uint8_t attempt) {
    uint32_t delay = WS_RECONNECT_BASE_MS;
    for (uint8_t i = 0; i < attempt && delay < WS_RECONNECT_MAX_MS; i++) {
        delay *= 2;
    }
    return (delay > WS_RECONNECT_MAX_MS) ? WS_RECONNECT_MAX_MS : delay;
}

static void buffer_event(const char *event_json) {
    if (g_ctx.buffer_count >= WS_EVENT_BUFFER_SIZE) {
        uint8_t oldest =
            (g_ctx.buffer_head + WS_EVENT_BUFFER_SIZE - g_ctx.buffer_count) % WS_EVENT_BUFFER_SIZE;
        free(g_ctx.event_buffer[oldest].json);
        g_ctx.event_buffer[oldest].json = NULL;
        g_ctx.buffer_count--;
    }

    size_t len = strlen(event_json);
    char *copy = malloc(len + 1);
    if (copy) {
        memcpy(copy, event_json, len + 1);
        g_ctx.event_buffer[g_ctx.buffer_head].json = copy;
        g_ctx.event_buffer[g_ctx.buffer_head].len = len;
        g_ctx.buffer_head = (g_ctx.buffer_head + 1) % WS_EVENT_BUFFER_SIZE;
        g_ctx.buffer_count++;
    }
}

static void clear_event_buffer(void) {
    for (int i = 0; i < WS_EVENT_BUFFER_SIZE; i++) {
        if (g_ctx.event_buffer[i].json) {
            free(g_ctx.event_buffer[i].json);
            g_ctx.event_buffer[i].json = NULL;
        }
    }
    g_ctx.buffer_head = 0;
    g_ctx.buffer_count = 0;
}

static int reconnect_relay(relay_connection_t *relay);
static void send_ping(relay_connection_t *relay);

#ifdef ESP_PLATFORM
static void dispatch_frost_event(int kind, const char *event_str) {
    if (kind == FROST_KIND_SIGN_REQUEST && g_ctx.callbacks.on_sign_request) {
        frost_sign_request_t req;
        if (frost_parse_sign_request(event_str, &g_ctx.current_group, g_ctx.privkey, &req) == 0) {
            g_ctx.callbacks.on_sign_request(&req, g_ctx.callbacks.user_ctx);
            frost_sign_request_free(&req);
        }
    } else if (kind == FROST_KIND_SIGN_RESPONSE && g_ctx.callbacks.on_sign_response) {
        frost_sign_response_t resp;
        if (frost_parse_sign_response(event_str, &g_ctx.current_group, g_ctx.privkey, &resp) == 0) {
            g_ctx.callbacks.on_sign_response(&resp, g_ctx.callbacks.user_ctx);
        }
    } else if (kind == FROST_KIND_DKG_ROUND1 && g_ctx.callbacks.on_dkg_round1) {
        frost_dkg_round1_t r1;
        if (frost_parse_dkg_round1_event(event_str, &g_ctx.current_group, g_ctx.privkey, &r1) ==
            0) {
            g_ctx.callbacks.on_dkg_round1(&r1, g_ctx.callbacks.user_ctx);
        }
    } else if (kind == FROST_KIND_DKG_ROUND2 && g_ctx.callbacks.on_dkg_round2) {
        frost_dkg_round2_t r2;
        if (frost_parse_dkg_round2_event(event_str, &g_ctx.current_group, g_ctx.privkey, &r2) ==
            0) {
            g_ctx.callbacks.on_dkg_round2(&r2, g_ctx.callbacks.user_ctx);
        }
    } else if (kind == NIP46_KIND_NOSTR_CONNECT && g_ctx.callbacks.on_nip46_request) {
        nip46_request_t nip46_req;
        if (frost_parse_nip46_event(event_str, g_ctx.privkey, &nip46_req) == 0) {
            g_ctx.callbacks.on_nip46_request(&nip46_req, g_ctx.callbacks.user_ctx);
            frost_nip46_request_free(&nip46_req);
        }
    }
}

static void handle_nostr_message(const char *msg) {
    cJSON *arr = cJSON_Parse(msg);
    if (!arr || !cJSON_IsArray(arr) || cJSON_GetArraySize(arr) < 1) {
        cJSON_Delete(arr);
        return;
    }

    cJSON *type = cJSON_GetArrayItem(arr, 0);
    if (!type || !cJSON_IsString(type) || strcmp(type->valuestring, "EVENT") != 0 ||
        cJSON_GetArraySize(arr) < 3) {
        cJSON_Delete(arr);
        return;
    }

    cJSON *event = cJSON_GetArrayItem(arr, 2);
    cJSON *kind = event ? cJSON_GetObjectItem(event, "kind") : NULL;
    if (!event || !cJSON_IsObject(event) || !kind || !cJSON_IsNumber(kind)) {
        cJSON_Delete(arr);
        return;
    }

    char *event_str = cJSON_PrintUnformatted(event);
    if (event_str) {
        dispatch_frost_event(kind->valueint, event_str);
        free(event_str);
    }
    cJSON_Delete(arr);
}

static void handle_ws_connected(relay_connection_t *relay) {
    COORDINATOR_LOCK();
    ESP_LOGI(TAG, "Relay connected: %s", relay->url);
    relay->state = COORDINATOR_STATE_CONNECTED;
    relay->health.healthy = true;
    relay->health.missed_pongs = 0;
    relay->health.last_pong_received = coordinator_now_ms();
    relay->success_count++;
    relay->reconnect.attempt_count = 0;
    bool needs_resubscribe = relay->reconnect.had_subscription && g_ctx.has_subscription;
    char sub_id[64];
    if (needs_resubscribe) {
        strncpy(sub_id, g_ctx.current_subscription, sizeof(sub_id) - 1);
        sub_id[sizeof(sub_id) - 1] = '\0';
        relay->reconnect.had_subscription = false;
    }
    COORDINATOR_UNLOCK();

    if (needs_resubscribe) {
        frost_coordinator_subscribe(sub_id);
    }
}

static void handle_ws_disconnected(relay_connection_t *relay) {
    COORDINATOR_LOCK();
    ESP_LOGW(TAG, "Relay disconnected: %s", relay->url);
    relay->reconnect.state_before_disconnect = relay->state;
    relay->reconnect.had_subscription = g_ctx.has_subscription;
    if (g_ctx.has_subscription) {
        strncpy(relay->reconnect.subscription_id, g_ctx.current_subscription, 63);
        relay->reconnect.subscription_id[63] = '\0';
    }
    relay->state = COORDINATOR_STATE_RECONNECTING;
    relay->health.healthy = false;
    relay->fail_count++;
    if (g_ctx.disconnect_time == 0) {
        g_ctx.disconnect_time = coordinator_now_ms();
    }
    COORDINATOR_UNLOCK();
}

static void handle_ws_data(relay_connection_t *relay, esp_websocket_event_data_t *data) {
    COORDINATOR_LOCK();

    if (data->op_code == 0x0A) {
        relay->health.last_pong_received = coordinator_now_ms();
        relay->health.missed_pongs = 0;
        relay->health.healthy = true;
        COORDINATOR_UNLOCK();
        return;
    }

    if (data->op_code != 0x01 || data->data_len == 0) {
        COORDINATOR_UNLOCK();
        return;
    }

    if (data->data_len > WS_MAX_EVENT_JSON_LEN) {
        ESP_LOGW(TAG, "Message too large: %d bytes", data->data_len);
        COORDINATOR_UNLOCK();
        return;
    }

    char *msg = malloc(data->data_len + 1);
    if (!msg) {
        COORDINATOR_UNLOCK();
        return;
    }
    memcpy(msg, data->data_ptr, data->data_len);
    msg[data->data_len] = '\0';

    COORDINATOR_UNLOCK();
    handle_nostr_message(msg);
    free(msg);
}

static void handle_ws_error(relay_connection_t *relay) {
    COORDINATOR_LOCK();
    ESP_LOGE(TAG, "Relay error: %s", relay->url);
    relay->fail_count++;
    relay->health.healthy = false;
    if (relay->reconnect.attempt_count >= WS_RECONNECT_MAX_ATTEMPTS) {
        relay->state = COORDINATOR_STATE_ERROR;
        COORDINATOR_UNLOCK();
        return;
    }
    relay->reconnect.state_before_disconnect = relay->state;
    relay->reconnect.had_subscription = g_ctx.has_subscription;
    relay->state = COORDINATOR_STATE_RECONNECTING;
    if (g_ctx.disconnect_time == 0) {
        g_ctx.disconnect_time = coordinator_now_ms();
    }
    COORDINATOR_UNLOCK();
}

static void websocket_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id,
                                    void *event_data) {
    relay_connection_t *relay = (relay_connection_t *)handler_args;

    switch (event_id) {
    case WEBSOCKET_EVENT_CONNECTED:
        handle_ws_connected(relay);
        break;
    case WEBSOCKET_EVENT_DISCONNECTED:
        handle_ws_disconnected(relay);
        break;
    case WEBSOCKET_EVENT_DATA:
        handle_ws_data(relay, (esp_websocket_event_data_t *)event_data);
        break;
    case WEBSOCKET_EVENT_ERROR:
        handle_ws_error(relay);
        break;
    default:
        break;
    }
}

static void send_ping(relay_connection_t *relay) {
    if (relay->state != COORDINATOR_STATE_CONNECTED || !relay->ws_handle)
        return;

    int ret = esp_websocket_client_send_with_opcode(relay->ws_handle, WS_TRANSPORT_OPCODES_PING,
                                                    NULL, 0, pdMS_TO_TICKS(WS_SEND_TIMEOUT_MS));
    if (ret < 0) {
        ESP_LOGW(TAG, "Ping send timeout: %s", relay->url);
    }
    relay->health.last_ping_sent = coordinator_now_ms();
}

static int reconnect_relay(relay_connection_t *relay) {
    if (relay->ws_handle) {
        esp_websocket_client_stop(relay->ws_handle);
        esp_websocket_client_destroy(relay->ws_handle);
        relay->ws_handle = NULL;
    }

    relay->reconnect.attempt_count++;
    relay->reconnect.next_retry_ms = calculate_backoff(relay->reconnect.attempt_count);
    relay->reconnect.last_attempt_time = coordinator_now_ms();

    ESP_LOGI(TAG, "Reconnecting to %s (attempt %d/%d, backoff %lums)", relay->url,
             relay->reconnect.attempt_count, WS_RECONNECT_MAX_ATTEMPTS,
             (unsigned long)relay->reconnect.next_retry_ms);

    esp_websocket_client_config_t ws_cfg = {
        .uri = relay->url,
        .buffer_size = 4096,
    };

    relay->ws_handle = esp_websocket_client_init(&ws_cfg);
    if (!relay->ws_handle) {
        ESP_LOGE(TAG, "Failed to init websocket for reconnect: %s", relay->url);
        return -1;
    }

    esp_websocket_register_events(relay->ws_handle, WEBSOCKET_EVENT_ANY, websocket_event_handler,
                                  relay);

    esp_err_t err = esp_websocket_client_start(relay->ws_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start websocket for reconnect: %s", relay->url);
        esp_websocket_client_destroy(relay->ws_handle);
        relay->ws_handle = NULL;
        return -1;
    }

    relay->state = COORDINATOR_STATE_CONNECTING;
    return 0;
}
#endif

int frost_coordinator_init(const uint8_t privkey[32]) {
    if (g_initialized) {
        return -1;
    }

    memset(&g_ctx, 0, sizeof(g_ctx));
    memcpy(g_ctx.privkey, privkey, 32);
    g_ctx.state = COORDINATOR_STATE_IDLE;

#ifdef ESP_PLATFORM
    g_ctx.mutex = xSemaphoreCreateMutex();
    if (!g_ctx.mutex) {
        return -1;
    }
#endif

    uint32_t ctx_size = NCGetContextStructSize();
    g_ctx.nc_ctx = malloc(ctx_size);
    if (!g_ctx.nc_ctx) {
        ESP_LOGE(TAG, "Failed to allocate noscrypt context");
#ifdef ESP_PLATFORM
        vSemaphoreDelete(g_ctx.mutex);
#endif
        return -2;
    }

    uint8_t entropy[NC_CONTEXT_ENTROPY_SIZE];
    if (rng_fill_checked(entropy, sizeof(entropy)) != 0) {
        ESP_LOGE(TAG, "RNG health check failed");
        free(g_ctx.nc_ctx);
#ifdef ESP_PLATFORM
        vSemaphoreDelete(g_ctx.mutex);
#endif
        return -3;
    }

    if (NCInitContext(g_ctx.nc_ctx, entropy) != NC_SUCCESS) {
        ESP_LOGE(TAG, "Failed to init noscrypt context");
        free(g_ctx.nc_ctx);
#ifdef ESP_PLATFORM
        vSemaphoreDelete(g_ctx.mutex);
#endif
        return -4;
    }
    secure_memzero(entropy, sizeof(entropy));

    NCSecretKey sk;
    NCPublicKey pk;
    memcpy(sk.key, privkey, 32);

    if (NCGetPublicKey(g_ctx.nc_ctx, &sk, &pk) != NC_SUCCESS) {
        ESP_LOGE(TAG, "Failed to derive public key");
        NCDestroyContext(g_ctx.nc_ctx);
        free(g_ctx.nc_ctx);
#ifdef ESP_PLATFORM
        vSemaphoreDelete(g_ctx.mutex);
#endif
        return -4;
    }
    memcpy(g_ctx.pubkey, pk.key, 32);
    secure_memzero(&sk, sizeof(sk));

    g_initialized = true;
    ESP_LOGI(TAG, "Coordinator initialized");
    return 0;
}

void frost_coordinator_deinit(void) {
    if (!g_initialized)
        return;

    frost_coordinator_disconnect();

    if (g_ctx.nc_ctx) {
        NCDestroyContext(g_ctx.nc_ctx);
        free(g_ctx.nc_ctx);
    }

#ifdef ESP_PLATFORM
    if (g_ctx.mutex) {
        vSemaphoreDelete(g_ctx.mutex);
    }
#endif

    secure_memzero(g_ctx.privkey, 32);
    memset(&g_ctx, 0, sizeof(g_ctx));
    g_initialized = false;

    ESP_LOGI(TAG, "Coordinator deinitialized");
}

coordinator_state_t frost_coordinator_get_state(void) {
    return g_ctx.state;
}

static bool validate_websocket_url(const char *url) {
    if (!url || strlen(url) < 6)
        return false;
    if (strncmp(url, "wss://", 6) == 0 || strncmp(url, "ws://", 5) == 0)
        return true;
    return false;
}

int frost_coordinator_add_relay(const char *url) {
    if (!g_initialized || !url)
        return -1;
    if (g_ctx.relay_count >= COORDINATOR_MAX_RELAYS)
        return -2;
    if (!validate_websocket_url(url)) {
        ESP_LOGE(TAG, "Invalid WebSocket URL: %s", url);
        return -3;
    }

    relay_connection_t *relay = &g_ctx.relays[g_ctx.relay_count];
    memset(relay, 0, sizeof(*relay));
    strncpy(relay->url, url, RELAY_URL_LEN - 1);
    relay->url[RELAY_URL_LEN - 1] = '\0';
    relay->state = COORDINATOR_STATE_IDLE;

    g_ctx.relay_count++;
    ESP_LOGI(TAG, "Added relay: %s", url);
    return 0;
}

int frost_coordinator_connect(void) {
    if (!g_initialized)
        return -1;

#ifdef ESP_PLATFORM
    for (int i = 0; i < g_ctx.relay_count; i++) {
        relay_connection_t *relay = &g_ctx.relays[i];
        if (relay->state != COORDINATOR_STATE_IDLE)
            continue;

        esp_websocket_client_config_t ws_cfg = {
            .uri = relay->url,
            .buffer_size = 4096,
        };

        relay->ws_handle = esp_websocket_client_init(&ws_cfg);
        if (!relay->ws_handle) {
            ESP_LOGE(TAG, "Failed to init websocket for %s", relay->url);
            relay->state = COORDINATOR_STATE_ERROR;
            continue;
        }

        esp_websocket_register_events(relay->ws_handle, WEBSOCKET_EVENT_ANY,
                                      websocket_event_handler, relay);

        esp_err_t err = esp_websocket_client_start(relay->ws_handle);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to start websocket for %s", relay->url);
            esp_websocket_client_destroy(relay->ws_handle);
            relay->ws_handle = NULL;
            relay->state = COORDINATOR_STATE_ERROR;
            continue;
        }

        relay->state = COORDINATOR_STATE_CONNECTING;
        ESP_LOGI(TAG, "Connecting to %s", relay->url);
    }
#endif

    g_ctx.state = COORDINATOR_STATE_CONNECTING;
    return 0;
}

int frost_coordinator_disconnect(void) {
    if (!g_initialized)
        return -1;

#ifdef ESP_PLATFORM
    for (int i = 0; i < g_ctx.relay_count; i++) {
        relay_connection_t *relay = &g_ctx.relays[i];
        if (relay->ws_handle) {
            esp_websocket_client_stop(relay->ws_handle);
            esp_websocket_client_destroy(relay->ws_handle);
            relay->ws_handle = NULL;
        }
        relay->state = COORDINATOR_STATE_IDLE;
        memset(&relay->health, 0, sizeof(relay->health));
        memset(&relay->reconnect, 0, sizeof(relay->reconnect));
    }
#endif

    clear_event_buffer();
    g_ctx.has_subscription = false;
    g_ctx.disconnect_time = 0;
    g_ctx.state = COORDINATOR_STATE_IDLE;
    ESP_LOGI(TAG, "Disconnected from all relays");
    return 0;
}

int frost_coordinator_set_group(const frost_group_t *group) {
    if (!g_initialized || !group)
        return -1;

    memcpy(&g_ctx.current_group, group, sizeof(frost_group_t));
    g_ctx.has_group = true;
    ESP_LOGI(TAG, "Group set (threshold=%d, participants=%d)", group->threshold,
             group->participant_count);
    return 0;
}

int frost_coordinator_subscribe(const char *subscription_id) {
    if (!g_initialized || !g_ctx.has_group)
        return -1;
    if (!is_safe_subscription_id(subscription_id))
        return -2;

    strncpy(g_ctx.current_subscription, subscription_id, sizeof(g_ctx.current_subscription) - 1);
    g_ctx.current_subscription[sizeof(g_ctx.current_subscription) - 1] = '\0';
    g_ctx.has_subscription = true;

    char pubkey_hex[65];
    bytes_to_hex(g_ctx.pubkey, 32, pubkey_hex, sizeof(pubkey_hex));

    char filter[512];
    snprintf(filter, sizeof(filter),
             "[\"REQ\",\"%s\",{\"kinds\":[%d,%d,%d,%d,%d],\"#p\":[\"%s\"]}]", subscription_id,
             FROST_KIND_DKG_ROUND1, FROST_KIND_DKG_ROUND2, FROST_KIND_SIGN_REQUEST,
             FROST_KIND_SIGN_RESPONSE, NIP46_KIND_NOSTR_CONNECT, pubkey_hex);

#ifdef ESP_PLATFORM
    for (int i = 0; i < g_ctx.relay_count; i++) {
        relay_connection_t *relay = &g_ctx.relays[i];
        if (relay->state == COORDINATOR_STATE_CONNECTED && relay->ws_handle) {
            int ret = esp_websocket_client_send_text(relay->ws_handle, filter, strlen(filter),
                                                     pdMS_TO_TICKS(WS_SEND_TIMEOUT_MS));
            if (ret < 0)
                ESP_LOGW(TAG, "Subscribe send failed on %s: %d", relay->url, ret);
            else
                ESP_LOGI(TAG, "Subscribed on %s", relay->url);
        }
    }
#endif

    g_ctx.state = COORDINATOR_STATE_ACTIVE;
    return 0;
}

int frost_coordinator_unsubscribe(const char *subscription_id) {
    if (!g_initialized)
        return -1;
    if (!is_safe_subscription_id(subscription_id))
        return -2;

    g_ctx.has_subscription = false;
    memset(g_ctx.current_subscription, 0, sizeof(g_ctx.current_subscription));

    char close_msg[128];
    snprintf(close_msg, sizeof(close_msg), "[\"CLOSE\",\"%s\"]", subscription_id);

#ifdef ESP_PLATFORM
    for (int i = 0; i < g_ctx.relay_count; i++) {
        relay_connection_t *relay = &g_ctx.relays[i];
        if (relay->state == COORDINATOR_STATE_CONNECTED && relay->ws_handle) {
            int ret = esp_websocket_client_send_text(relay->ws_handle, close_msg, strlen(close_msg),
                                                     pdMS_TO_TICKS(WS_SEND_TIMEOUT_MS));
            if (ret < 0)
                ESP_LOGW(TAG, "Unsubscribe send failed on %s: %d", relay->url, ret);
        }
    }
#endif

    return 0;
}

static int publish_event(const char *event_json) {
    if (!g_initialized)
        return -1;

    size_t msg_len = strlen(event_json) + 12;
    if (msg_len > MAX_PUBLISH_MSG_SIZE)
        return -1;
    char *msg = malloc(msg_len + 1);
    if (!msg)
        return -1;

    snprintf(msg, msg_len + 1, "[\"EVENT\",%s]", event_json);

    int published = 0;
    bool any_reconnecting = false;

#ifdef ESP_PLATFORM
    for (int i = 0; i < g_ctx.relay_count; i++) {
        relay_connection_t *relay = &g_ctx.relays[i];
        if (relay->state == COORDINATOR_STATE_CONNECTED && relay->ws_handle) {
            int ret = esp_websocket_client_send_text(relay->ws_handle, msg, strlen(msg),
                                                     pdMS_TO_TICKS(WS_SEND_TIMEOUT_MS));
            if (ret >= 0)
                published++;
        } else if (relay->state == COORDINATOR_STATE_RECONNECTING) {
            any_reconnecting = true;
        }
    }

    if (published == 0 && any_reconnecting) {
        buffer_event(msg);
        ESP_LOGI(TAG, "Buffered event during reconnection");
    }
#endif
    free(msg);
    if (published > 0) {
        ESP_LOGI(TAG, "Published to %d relays", published);
    }
    return published;
}

int frost_coordinator_publish_sign_request(const frost_sign_request_t *request) {
    if (!g_initialized || !g_ctx.has_group || !request)
        return -1;

    char event_json[4096];
    if (frost_create_sign_request(&g_ctx.current_group, request, g_ctx.privkey, event_json,
                                  sizeof(event_json)) != 0) {
        return -1;
    }

    return publish_event(event_json);
}

int frost_coordinator_publish_sign_response(const frost_sign_response_t *response) {
    if (!g_initialized || !g_ctx.has_group || !response)
        return -1;

    char event_json[2048];
    if (frost_create_sign_response(&g_ctx.current_group, response, g_ctx.privkey, event_json,
                                   sizeof(event_json)) != 0) {
        return -1;
    }

    return publish_event(event_json);
}

int frost_coordinator_publish_dkg_round1(const frost_dkg_round1_t *round1) {
    if (!g_initialized || !g_ctx.has_group || !round1)
        return -1;

    char event_json[2048];
    if (frost_create_dkg_round1_event(&g_ctx.current_group, round1, g_ctx.privkey, event_json,
                                      sizeof(event_json)) != 0) {
        return -1;
    }

    return publish_event(event_json);
}

int frost_coordinator_publish_dkg_round2(const frost_dkg_round2_t *round2,
                                         const uint8_t *recipient_pubkey) {
    if (!g_initialized || !g_ctx.has_group || !round2 || !recipient_pubkey)
        return -1;

    char event_json[2048];
    if (frost_create_dkg_round2_event(&g_ctx.current_group, round2, g_ctx.privkey, recipient_pubkey,
                                      event_json, sizeof(event_json)) != 0) {
        return -1;
    }

    return publish_event(event_json);
}

void frost_coordinator_set_callbacks(const frost_coordinator_callbacks_t *callbacks) {
    if (!g_initialized || !callbacks)
        return;
    memcpy(&g_ctx.callbacks, callbacks, sizeof(frost_coordinator_callbacks_t));
}

int frost_coordinator_poll(int timeout_ms) {
    if (!g_initialized)
        return -1;

#ifdef ESP_PLATFORM
    vTaskDelay(pdMS_TO_TICKS(timeout_ms > 0 ? timeout_ms : 10));
#endif

    COORDINATOR_LOCK();

    uint32_t now = coordinator_now_ms();
    int connected = 0;
    int reconnecting = 0;

    for (int i = 0; i < g_ctx.relay_count; i++) {
        relay_connection_t *relay = &g_ctx.relays[i];

        if (relay->state == COORDINATOR_STATE_CONNECTED) {
#ifdef ESP_PLATFORM
            if (now - relay->health.last_ping_sent >= WS_PING_INTERVAL_MS) {
                send_ping(relay);
            }

            if (now - relay->health.last_pong_received > WS_PONG_TIMEOUT_MS) {
                relay->health.missed_pongs++;
                relay->health.last_pong_received = now;

                if (relay->health.missed_pongs >= WS_MAX_MISSED_PONGS) {
                    ESP_LOGW(TAG, "Relay unhealthy (missed %d pongs): %s",
                             relay->health.missed_pongs, relay->url);
                    relay->health.healthy = false;
                    relay->reconnect.state_before_disconnect = relay->state;
                    relay->reconnect.had_subscription = g_ctx.has_subscription;
                    relay->state = COORDINATOR_STATE_RECONNECTING;
                    relay->fail_count++;
                    if (g_ctx.disconnect_time == 0) {
                        g_ctx.disconnect_time = now;
                    }
                    continue;
                }
            }
#endif
            connected++;
        } else if (relay->state == COORDINATOR_STATE_RECONNECTING) {
            reconnecting++;
#ifdef ESP_PLATFORM
            if (relay->reconnect.attempt_count >= WS_RECONNECT_MAX_ATTEMPTS) {
                ESP_LOGE(TAG, "Max reconnect attempts reached: %s", relay->url);
                relay->state = COORDINATOR_STATE_ERROR;
                continue;
            }

            uint32_t elapsed = now - relay->reconnect.last_attempt_time;
            if (elapsed >= relay->reconnect.next_retry_ms || relay->reconnect.attempt_count == 0) {
                reconnect_relay(relay);
            }
#endif
        }
    }

    if (g_ctx.disconnect_time > 0 && connected == 0) {
        uint32_t disconnect_elapsed = now - g_ctx.disconnect_time;
        if (disconnect_elapsed > WS_SESSION_RECOVERY_MS) {
            ESP_LOGE(TAG, "Session recovery timeout exceeded");
            g_ctx.state = COORDINATOR_STATE_ERROR;
            clear_event_buffer();
            g_ctx.disconnect_time = 0;
            COORDINATOR_UNLOCK();
            return -1;
        }
    }

    if (connected > 0) {
        g_ctx.disconnect_time = 0;

#ifdef ESP_PLATFORM
        if (g_ctx.buffer_count > 0) {
            ESP_LOGI(TAG, "Replaying %d buffered events", g_ctx.buffer_count);
            uint8_t start = (g_ctx.buffer_head + WS_EVENT_BUFFER_SIZE - g_ctx.buffer_count) %
                            WS_EVENT_BUFFER_SIZE;
            for (uint8_t j = 0; j < g_ctx.buffer_count; j++) {
                uint8_t idx = (start + j) % WS_EVENT_BUFFER_SIZE;
                if (g_ctx.event_buffer[idx].json) {
                    for (int k = 0; k < g_ctx.relay_count; k++) {
                        relay_connection_t *relay = &g_ctx.relays[k];
                        if (relay->state == COORDINATOR_STATE_CONNECTED && relay->ws_handle) {
                            esp_websocket_client_send_text(
                                relay->ws_handle, g_ctx.event_buffer[idx].json,
                                g_ctx.event_buffer[idx].len, pdMS_TO_TICKS(WS_SEND_TIMEOUT_MS));
                        }
                    }
                }
            }
            clear_event_buffer();
        }
#endif

        if (g_ctx.state == COORDINATOR_STATE_CONNECTING ||
            g_ctx.state == COORDINATOR_STATE_RECONNECTING) {
            g_ctx.state = COORDINATOR_STATE_CONNECTED;
        }
    } else if (reconnecting > 0 && g_ctx.state != COORDINATOR_STATE_ERROR) {
        g_ctx.state = COORDINATOR_STATE_RECONNECTING;
    }

    COORDINATOR_UNLOCK();
    return connected;
}

int frost_coordinator_get_pubkey(uint8_t pubkey[32]) {
    if (!g_initialized)
        return -1;
    memcpy(pubkey, g_ctx.pubkey, 32);
    return 0;
}

int frost_coordinator_get_status(coordinator_status_t *status) {
    if (!g_initialized || !status)
        return -1;

    COORDINATOR_LOCK();
    memset(status, 0, sizeof(*status));
    status->state = g_ctx.state;
    status->total_relays = g_ctx.relay_count;
    status->session_active = g_ctx.has_subscription;

    for (int i = 0; i < g_ctx.relay_count; i++) {
        relay_connection_t *relay = &g_ctx.relays[i];
        if (relay->state == COORDINATOR_STATE_CONNECTED) {
            status->connected_relays++;
        }
        if (relay->state == COORDINATOR_STATE_RECONNECTING) {
            status->reconnect_attempts += relay->reconnect.attempt_count;
        }
        status->relay_scores[i].relay_index = i;
        status->relay_scores[i].success_count = relay->success_count;
        status->relay_scores[i].fail_count = relay->fail_count;
    }

    COORDINATOR_UNLOCK();
    return 0;
}

bool frost_coordinator_is_healthy(void) {
    if (!g_initialized)
        return false;

    COORDINATOR_LOCK();
    int healthy_count = 0;
    for (int i = 0; i < g_ctx.relay_count; i++) {
        if (g_ctx.relays[i].state == COORDINATOR_STATE_CONNECTED &&
            g_ctx.relays[i].health.healthy) {
            healthy_count++;
        }
    }
    COORDINATOR_UNLOCK();

    return healthy_count > 0;
}
