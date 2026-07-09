// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include "frost_coordinator.h"
#include "cJSON.h"
#include "crypto_asm.h"
#include "hex_utils.h"
#include "nostr_frost.h"
#include "random_utils.h"
#include "ws_transport.h"
#include <noscrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log_compat.h"

#ifdef ESP_PLATFORM
#include "esp_timer.h"
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#else
#include <pthread.h>
#endif

#define TAG                  "frost_coord"
#define MAX_PUBLISH_MSG_SIZE 4108

// We must be able to receive any frame we are willing to publish.
typedef char rx_buffer_holds_largest_publish[(WS_RX_BUFFER_SIZE >= MAX_PUBLISH_MSG_SIZE) ? 1 : -1];

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
    bool needs_resubscribe;
    ws_transport_handle_t ws;
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
    char current_subscription[WS_SUBSCRIPTION_ID_SIZE];
    bool has_subscription;
    buffered_event_t event_buffer[WS_EVENT_BUFFER_SIZE];
    uint8_t buffer_head;
    uint8_t buffer_count;
    uint32_t disconnect_time;
    // Explicit flag: disconnect_time == 0 is a legitimate timestamp at boot.
    bool session_interrupted;
#ifdef ESP_PLATFORM
    SemaphoreHandle_t state_mutex;
    SemaphoreHandle_t op_mutex;
#else
    pthread_mutex_t state_mutex;
    pthread_mutex_t op_mutex;
#endif
} coordinator_ctx_t;

static coordinator_ctx_t g_ctx;
static bool g_initialized = false;

/*
 * Locking rules
 *
 *   state_mutex  Guards every g_ctx and relay_connection_t field. Held only for
 *                short, non-blocking critical sections.
 *   op_mutex     Serializes websocket lifecycle and send operations, so a handle
 *                can never be destroyed while another caller is sending on it.
 *
 * A ws_transport_* call MUST NOT be made while state_mutex is held.
 * ws_transport_destroy() blocks until the transport thread drains, and that
 * thread takes state_mutex in on_ws_event(); holding it across destroy would
 * deadlock permanently. The mock transport asserts this in native test builds.
 */

#ifdef NATIVE_TEST
// Per-thread: "does *this* thread hold state_mutex".
static __thread int g_state_lock_depth;

// The mock transport asserts on this at every entry point, so any websocket call
// made under state_mutex fails the test suite wherever it is written.
bool frost_coordinator_state_lock_held(void) {
    return g_state_lock_depth > 0;
}
#endif

static void state_lock(void) {
#ifdef ESP_PLATFORM
    xSemaphoreTake(g_ctx.state_mutex, portMAX_DELAY);
#else
    pthread_mutex_lock(&g_ctx.state_mutex);
#endif
#ifdef NATIVE_TEST
    g_state_lock_depth++;
#endif
}

static void state_unlock(void) {
#ifdef NATIVE_TEST
    g_state_lock_depth--;
#endif
#ifdef ESP_PLATFORM
    xSemaphoreGive(g_ctx.state_mutex);
#else
    pthread_mutex_unlock(&g_ctx.state_mutex);
#endif
}

// Bounded so a callback that re-enters the public API from the transport thread
// fails its operation instead of deadlocking against an in-flight destroy.
static bool op_lock(void) {
#ifdef ESP_PLATFORM
    return xSemaphoreTake(g_ctx.op_mutex, pdMS_TO_TICKS(WS_OP_LOCK_TIMEOUT_MS)) == pdTRUE;
#else
    return pthread_mutex_lock(&g_ctx.op_mutex) == 0;
#endif
}

static void op_unlock(void) {
#ifdef ESP_PLATFORM
    xSemaphoreGive(g_ctx.op_mutex);
#else
    pthread_mutex_unlock(&g_ctx.op_mutex);
#endif
}

#ifdef NATIVE_TEST
// Read from every thread the coordinator runs on, so keep it atomic.
static uint32_t g_test_now_ms;

void frost_coordinator_test_set_time_ms(uint32_t now_ms) {
    __atomic_store_n(&g_test_now_ms, now_ms, __ATOMIC_RELAXED);
}
#endif

static uint32_t coordinator_now_ms(void) {
#if defined(NATIVE_TEST)
    return __atomic_load_n(&g_test_now_ms, __ATOMIC_RELAXED);
#elif defined(ESP_PLATFORM)
    return (uint32_t)(esp_timer_get_time() / 1000);
#else
    return 0;
#endif
}

static uint32_t calculate_backoff(uint8_t attempt) {
    if (attempt >= 21)
        return WS_RECONNECT_MAX_MS;
    uint32_t delay = (uint32_t)WS_RECONNECT_BASE_MS << attempt;
    return delay > WS_RECONNECT_MAX_MS ? WS_RECONNECT_MAX_MS : delay;
}

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
        if (++len > WS_MAX_SUBSCRIPTION_ID)
            return false;
    }
    return true;
}

// Plaintext ws:// is rejected: relay traffic carries signing coordination for a
// hardware wallet, and an on-path attacker could suppress or reorder it.
static bool validate_websocket_url(const char *url) {
    return url && strncmp(url, "wss://", 6) == 0;
}

/* ---- event buffer (state_mutex held by caller) ---- */

static void buffer_event_take(char *json, size_t len) {
    if (g_ctx.buffer_count >= WS_EVENT_BUFFER_SIZE) {
        uint8_t oldest =
            (g_ctx.buffer_head + WS_EVENT_BUFFER_SIZE - g_ctx.buffer_count) % WS_EVENT_BUFFER_SIZE;
        free(g_ctx.event_buffer[oldest].json);
        g_ctx.event_buffer[oldest].json = NULL;
        g_ctx.buffer_count--;
    }

    g_ctx.event_buffer[g_ctx.buffer_head].json = json;
    g_ctx.event_buffer[g_ctx.buffer_head].len = len;
    g_ctx.buffer_head = (g_ctx.buffer_head + 1) % WS_EVENT_BUFFER_SIZE;
    g_ctx.buffer_count++;
}

static void buffer_event_copy(const char *json) {
    size_t len = strlen(json);
    char *copy = malloc(len + 1);
    if (!copy)
        return;
    memcpy(copy, json, len + 1);
    buffer_event_take(copy, len);
}

// Moves every buffered event to out[] and empties the buffer. Caller owns the
// returned strings and must free or re-buffer each one.
static uint8_t drain_event_buffer(buffered_event_t *out) {
    uint8_t start =
        (g_ctx.buffer_head + WS_EVENT_BUFFER_SIZE - g_ctx.buffer_count) % WS_EVENT_BUFFER_SIZE;
    uint8_t n = 0;
    for (uint8_t i = 0; i < g_ctx.buffer_count; i++) {
        uint8_t idx = (start + i) % WS_EVENT_BUFFER_SIZE;
        if (g_ctx.event_buffer[idx].json)
            out[n++] = g_ctx.event_buffer[idx];
        g_ctx.event_buffer[idx].json = NULL;
    }
    g_ctx.buffer_head = 0;
    g_ctx.buffer_count = 0;
    return n;
}

static void clear_event_buffer_unlocked(void) {
    for (int i = 0; i < WS_EVENT_BUFFER_SIZE; i++) {
        free(g_ctx.event_buffer[i].json);
        g_ctx.event_buffer[i].json = NULL;
    }
    g_ctx.buffer_head = 0;
    g_ctx.buffer_count = 0;
}

/* ---- relay state transitions (state_mutex held by caller) ---- */

static void enter_reconnecting(relay_connection_t *relay) {
    if (relay->state == COORDINATOR_STATE_RECONNECTING || relay->state == COORDINATOR_STATE_ERROR)
        return;

    uint32_t now = coordinator_now_ms();
    relay->reconnect.state_before_disconnect = relay->state;
    relay->reconnect.had_subscription = g_ctx.has_subscription;
    relay->reconnect.last_attempt_time = now;
    relay->reconnect.next_retry_ms = calculate_backoff(relay->reconnect.attempt_count);
    relay->state = COORDINATOR_STATE_RECONNECTING;
    relay->health.healthy = false;
    relay->needs_resubscribe = false;
    relay->fail_count++;

    if (!g_ctx.session_interrupted) {
        g_ctx.session_interrupted = true;
        g_ctx.disconnect_time = now;
    }
}

/* ---- inbound events ---- */

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
    state_lock();
    ESP_LOGI(TAG, "Relay connected: %s", relay->url);
    relay->state = COORDINATOR_STATE_CONNECTED;
    relay->health.healthy = true;
    relay->health.last_event_ms = coordinator_now_ms();
    relay->success_count++;
    relay->reconnect.attempt_count = 0;
    relay->reconnect.next_retry_ms = 0;
    relay->needs_resubscribe = g_ctx.has_subscription;
    state_unlock();
}

static void handle_ws_failure(relay_connection_t *relay) {
    state_lock();
    ESP_LOGW(TAG, "Relay unavailable: %s", relay->url);
    enter_reconnecting(relay);
    state_unlock();
}

static void handle_ws_data(relay_connection_t *relay, const char *data, size_t len) {
    if (len == 0 || len > WS_MAX_EVENT_JSON_LEN) {
        ESP_LOGW(TAG, "Ignoring message of %u bytes", (unsigned)len);
        return;
    }

    char *msg = malloc(len + 1);
    if (!msg)
        return;
    memcpy(msg, data, len);
    msg[len] = '\0';

    state_lock();
    relay->health.last_event_ms = coordinator_now_ms();
    relay->health.healthy = true;
    state_unlock();

    // Parsed outside the lock: callbacks may re-enter the public API.
    handle_nostr_message(msg);
    free(msg);
}

static void on_ws_event(void *user_ctx, const ws_event_t *event) {
    relay_connection_t *relay = user_ctx;

    switch (event->type) {
    case WS_EVT_CONNECTED:
        handle_ws_connected(relay);
        break;
    case WS_EVT_DISCONNECTED:
    case WS_EVT_ERROR:
        handle_ws_failure(relay);
        break;
    case WS_EVT_DATA:
        handle_ws_data(relay, event->data, event->len);
        break;
    }
}

/* ---- websocket operations (op_mutex held, state_mutex NOT held) ---- */

static int start_relay(relay_connection_t *relay) {
    ws_transport_config_t cfg = {
        .url = relay->url,
        .ping_interval_sec = WS_PING_INTERVAL_SEC,
        .pong_timeout_sec = WS_PONG_TIMEOUT_SEC,
        .rx_buffer_size = WS_RX_BUFFER_SIZE,
        .network_timeout_ms = WS_SEND_TIMEOUT_MS,
    };

    ws_transport_handle_t ws = ws_transport_create(&cfg, on_ws_event, relay);
    if (!ws) {
        ESP_LOGE(TAG, "Failed to create transport for %s", relay->url);
        state_lock();
        enter_reconnecting(relay);
        state_unlock();
        return -1;
    }

    // Published before start() so the transport thread never fires an event for a
    // relay whose handle we have not recorded yet.
    state_lock();
    relay->ws = ws;
    relay->state = COORDINATOR_STATE_CONNECTING;
    state_unlock();

    if (ws_transport_start(ws) != 0) {
        ESP_LOGE(TAG, "Failed to start transport for %s", relay->url);
        state_lock();
        relay->ws = NULL;
        enter_reconnecting(relay);
        state_unlock();
        ws_transport_destroy(ws);
        return -1;
    }

    return 0;
}

static int send_to_handles(ws_transport_handle_t *handles, int count, const char *msg, size_t len) {
    int sent = 0;
    for (int i = 0; i < count; i++) {
        if (ws_transport_send_text(handles[i], msg, len, WS_SEND_TIMEOUT_MS) == 0)
            sent++;
    }
    return sent;
}

// Snapshots the handles of every connected relay. Safe to use after unlocking
// because op_mutex keeps any concurrent destroy out.
static int snapshot_connected(ws_transport_handle_t *out, bool *any_reconnecting) {
    int n = 0;
    if (any_reconnecting)
        *any_reconnecting = false;
    for (int i = 0; i < g_ctx.relay_count; i++) {
        relay_connection_t *relay = &g_ctx.relays[i];
        if (relay->state == COORDINATOR_STATE_CONNECTED && relay->ws)
            out[n++] = relay->ws;
        else if (any_reconnecting && (relay->state == COORDINATOR_STATE_RECONNECTING ||
                                      relay->state == COORDINATOR_STATE_CONNECTING))
            *any_reconnecting = true;
    }
    return n;
}

static void build_subscription_filter(char *out, size_t out_size, const char *subscription_id) {
    char pubkey_hex[65];
    bytes_to_hex(g_ctx.pubkey, 32, pubkey_hex, sizeof(pubkey_hex));
    snprintf(out, out_size, "[\"REQ\",\"%s\",{\"kinds\":[%d,%d,%d,%d,%d],\"#p\":[\"%s\"]}]",
             subscription_id, FROST_KIND_DKG_ROUND1, FROST_KIND_DKG_ROUND2, FROST_KIND_SIGN_REQUEST,
             FROST_KIND_SIGN_RESPONSE, NIP46_KIND_NOSTR_CONNECT, pubkey_hex);
}

/* ---- public API ---- */

int frost_coordinator_init(const uint8_t privkey[32]) {
    if (g_initialized)
        return -1;

    memset(&g_ctx, 0, sizeof(g_ctx));
    memcpy(g_ctx.privkey, privkey, 32);
    g_ctx.state = COORDINATOR_STATE_IDLE;

#ifdef ESP_PLATFORM
    g_ctx.state_mutex = xSemaphoreCreateMutex();
    g_ctx.op_mutex = xSemaphoreCreateMutex();
    if (!g_ctx.state_mutex || !g_ctx.op_mutex)
        goto fail_mutex;
#else
    if (pthread_mutex_init(&g_ctx.state_mutex, NULL) != 0) {
        secure_memzero(g_ctx.privkey, 32);
        return -2;
    }
    if (pthread_mutex_init(&g_ctx.op_mutex, NULL) != 0) {
        pthread_mutex_destroy(&g_ctx.state_mutex);
        secure_memzero(g_ctx.privkey, 32);
        return -2;
    }
#endif

    uint32_t ctx_size = NCGetContextStructSize();
    g_ctx.nc_ctx = malloc(ctx_size);
    if (!g_ctx.nc_ctx) {
        ESP_LOGE(TAG, "Failed to allocate noscrypt context");
        goto fail_mutex;
    }

    uint8_t entropy[NC_CONTEXT_ENTROPY_SIZE];
    if (rng_fill_checked(entropy, sizeof(entropy)) != 0) {
        ESP_LOGE(TAG, "RNG health check failed");
        goto fail_ctx;
    }

    if (NCInitContext(g_ctx.nc_ctx, entropy) != NC_SUCCESS) {
        ESP_LOGE(TAG, "Failed to init noscrypt context");
        secure_memzero(entropy, sizeof(entropy));
        goto fail_ctx;
    }
    secure_memzero(entropy, sizeof(entropy));

    NCSecretKey sk;
    NCPublicKey pk;
    memcpy(sk.key, privkey, 32);
    int rc = NCGetPublicKey(g_ctx.nc_ctx, &sk, &pk);
    secure_memzero(&sk, sizeof(sk));
    if (rc != NC_SUCCESS) {
        ESP_LOGE(TAG, "Failed to derive public key");
        NCDestroyContext(g_ctx.nc_ctx);
        goto fail_ctx;
    }
    memcpy(g_ctx.pubkey, pk.key, 32);

    g_initialized = true;
    ESP_LOGI(TAG, "Coordinator initialized");
    return 0;

fail_ctx:
    free(g_ctx.nc_ctx);
    g_ctx.nc_ctx = NULL;
fail_mutex:
#ifdef ESP_PLATFORM
    if (g_ctx.state_mutex)
        vSemaphoreDelete(g_ctx.state_mutex);
    if (g_ctx.op_mutex)
        vSemaphoreDelete(g_ctx.op_mutex);
#else
    pthread_mutex_destroy(&g_ctx.state_mutex);
    pthread_mutex_destroy(&g_ctx.op_mutex);
#endif
    secure_memzero(g_ctx.privkey, 32);
    return -2;
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
    vSemaphoreDelete(g_ctx.state_mutex);
    vSemaphoreDelete(g_ctx.op_mutex);
#else
    pthread_mutex_destroy(&g_ctx.state_mutex);
    pthread_mutex_destroy(&g_ctx.op_mutex);
#endif

    secure_memzero(g_ctx.privkey, 32);
    memset(&g_ctx, 0, sizeof(g_ctx));
    g_initialized = false;

    ESP_LOGI(TAG, "Coordinator deinitialized");
}

coordinator_state_t frost_coordinator_get_state(void) {
    if (!g_initialized)
        return COORDINATOR_STATE_IDLE;
    state_lock();
    coordinator_state_t state = g_ctx.state;
    state_unlock();
    return state;
}

int frost_coordinator_add_relay(const char *url) {
    if (!g_initialized || !url)
        return -1;
    if (!validate_websocket_url(url)) {
        ESP_LOGE(TAG, "Relay URL must use wss://");
        return -3;
    }
    if (strlen(url) >= RELAY_URL_LEN) {
        ESP_LOGE(TAG, "Relay URL too long");
        return -4;
    }

    state_lock();
    if (g_ctx.relay_count >= COORDINATOR_MAX_RELAYS) {
        state_unlock();
        return -2;
    }
    relay_connection_t *relay = &g_ctx.relays[g_ctx.relay_count];
    memset(relay, 0, sizeof(*relay));
    memcpy(relay->url, url, strlen(url) + 1);
    relay->state = COORDINATOR_STATE_IDLE;
    g_ctx.relay_count++;
    state_unlock();

    ESP_LOGI(TAG, "Added relay: %s", url);
    return 0;
}

int frost_coordinator_connect(void) {
    if (!g_initialized)
        return -1;
    if (!op_lock())
        return -1;

    relay_connection_t *pending[COORDINATOR_MAX_RELAYS];
    int pending_count = 0;

    state_lock();
    for (int i = 0; i < g_ctx.relay_count; i++) {
        if (g_ctx.relays[i].state == COORDINATOR_STATE_IDLE)
            pending[pending_count++] = &g_ctx.relays[i];
    }
    g_ctx.state = COORDINATOR_STATE_CONNECTING;
    state_unlock();

    for (int i = 0; i < pending_count; i++)
        start_relay(pending[i]);

    op_unlock();
    return 0;
}

int frost_coordinator_disconnect(void) {
    if (!g_initialized)
        return -1;
    if (!op_lock())
        return -1;

    ws_transport_handle_t doomed[COORDINATOR_MAX_RELAYS];
    int doomed_count = 0;

    state_lock();
    for (int i = 0; i < g_ctx.relay_count; i++) {
        relay_connection_t *relay = &g_ctx.relays[i];
        if (relay->ws)
            doomed[doomed_count++] = relay->ws;
        relay->ws = NULL;
        relay->state = COORDINATOR_STATE_IDLE;
        relay->needs_resubscribe = false;
        memset(&relay->health, 0, sizeof(relay->health));
        memset(&relay->reconnect, 0, sizeof(relay->reconnect));
    }
    clear_event_buffer_unlocked();
    g_ctx.has_subscription = false;
    memset(g_ctx.current_subscription, 0, sizeof(g_ctx.current_subscription));
    g_ctx.disconnect_time = 0;
    g_ctx.session_interrupted = false;
    g_ctx.state = COORDINATOR_STATE_IDLE;
    state_unlock();

    // Ownership of each handle transferred above, so this cannot race a send.
    for (int i = 0; i < doomed_count; i++)
        ws_transport_destroy(doomed[i]);

    op_unlock();
    ESP_LOGI(TAG, "Disconnected from all relays");
    return 0;
}

int frost_coordinator_set_group(const frost_group_t *group) {
    if (!g_initialized || !group)
        return -1;

    state_lock();
    memcpy(&g_ctx.current_group, group, sizeof(frost_group_t));
    g_ctx.has_group = true;
    state_unlock();

    ESP_LOGI(TAG, "Group set (threshold=%d, participants=%d)", group->threshold,
             group->participant_count);
    return 0;
}

int frost_coordinator_subscribe(const char *subscription_id) {
    if (!g_initialized)
        return -1;
    if (!is_safe_subscription_id(subscription_id)) {
        ESP_LOGE(TAG, "Invalid subscription ID");
        return -2;
    }
    if (!op_lock())
        return -1;

    ws_transport_handle_t handles[COORDINATOR_MAX_RELAYS];
    char filter[512];

    state_lock();
    if (!g_ctx.has_group) {
        state_unlock();
        op_unlock();
        return -1;
    }
    memcpy(g_ctx.current_subscription, subscription_id, strlen(subscription_id) + 1);
    g_ctx.has_subscription = true;
    g_ctx.state = COORDINATOR_STATE_ACTIVE;
    int count = snapshot_connected(handles, NULL);
    for (int i = 0; i < g_ctx.relay_count; i++)
        g_ctx.relays[i].needs_resubscribe = false;
    build_subscription_filter(filter, sizeof(filter), subscription_id);
    state_unlock();

    int sent = send_to_handles(handles, count, filter, strlen(filter));
    op_unlock();

    ESP_LOGI(TAG, "Subscribed on %d relays", sent);
    return 0;
}

int frost_coordinator_unsubscribe(const char *subscription_id) {
    if (!g_initialized)
        return -1;
    if (!is_safe_subscription_id(subscription_id))
        return -2;
    if (!op_lock())
        return -1;

    ws_transport_handle_t handles[COORDINATOR_MAX_RELAYS];

    state_lock();
    g_ctx.has_subscription = false;
    memset(g_ctx.current_subscription, 0, sizeof(g_ctx.current_subscription));
    for (int i = 0; i < g_ctx.relay_count; i++)
        g_ctx.relays[i].needs_resubscribe = false;
    int count = snapshot_connected(handles, NULL);
    state_unlock();

    char close_msg[128];
    snprintf(close_msg, sizeof(close_msg), "[\"CLOSE\",\"%s\"]", subscription_id);
    send_to_handles(handles, count, close_msg, strlen(close_msg));

    op_unlock();
    return 0;
}

static int publish_event(const char *event_json) {
    size_t msg_len = strlen(event_json) + 10; /* ["EVENT",  ...  ] */
    if (msg_len > MAX_PUBLISH_MSG_SIZE)
        return -1;

    char *msg = malloc(msg_len + 1);
    if (!msg)
        return -1;
    snprintf(msg, msg_len + 1, "[\"EVENT\",%s]", event_json);

    if (!op_lock()) {
        free(msg);
        return -1;
    }

    ws_transport_handle_t handles[COORDINATOR_MAX_RELAYS];
    bool any_reconnecting = false;

    state_lock();
    int count = snapshot_connected(handles, &any_reconnecting);
    state_unlock();

    int published = send_to_handles(handles, count, msg, strlen(msg));

    if (published == 0 && any_reconnecting) {
        state_lock();
        buffer_event_copy(msg);
        state_unlock();
        ESP_LOGI(TAG, "Buffered event during reconnection");
    }

    op_unlock();
    free(msg);

    if (published > 0)
        ESP_LOGI(TAG, "Published to %d relays", published);
    return published;
}

int frost_coordinator_publish_sign_request(const frost_sign_request_t *request) {
    if (!g_initialized || !request)
        return -1;

    char event_json[4096];
    state_lock();
    int rc = g_ctx.has_group
                 ? frost_create_sign_request(&g_ctx.current_group, request, g_ctx.privkey,
                                             event_json, sizeof(event_json))
                 : -1;
    state_unlock();
    if (rc != 0)
        return -1;

    return publish_event(event_json);
}

int frost_coordinator_publish_sign_response(const frost_sign_response_t *response) {
    if (!g_initialized || !response)
        return -1;

    char event_json[2048];
    state_lock();
    int rc = g_ctx.has_group
                 ? frost_create_sign_response(&g_ctx.current_group, response, g_ctx.privkey,
                                              event_json, sizeof(event_json))
                 : -1;
    state_unlock();
    if (rc != 0)
        return -1;

    return publish_event(event_json);
}

int frost_coordinator_publish_dkg_round1(const frost_dkg_round1_t *round1) {
    if (!g_initialized || !round1)
        return -1;

    char event_json[2048];
    state_lock();
    int rc = g_ctx.has_group
                 ? frost_create_dkg_round1_event(&g_ctx.current_group, round1, g_ctx.privkey,
                                                 event_json, sizeof(event_json))
                 : -1;
    state_unlock();
    if (rc != 0)
        return -1;

    return publish_event(event_json);
}

int frost_coordinator_publish_dkg_round2(const frost_dkg_round2_t *round2,
                                         const uint8_t *recipient_pubkey) {
    if (!g_initialized || !round2 || !recipient_pubkey)
        return -1;

    char event_json[2048];
    state_lock();
    int rc = g_ctx.has_group
                 ? frost_create_dkg_round2_event(&g_ctx.current_group, round2, g_ctx.privkey,
                                                 recipient_pubkey, event_json, sizeof(event_json))
                 : -1;
    state_unlock();
    if (rc != 0)
        return -1;

    return publish_event(event_json);
}

void frost_coordinator_set_callbacks(const frost_coordinator_callbacks_t *callbacks) {
    if (!g_initialized || !callbacks)
        return;
    state_lock();
    memcpy(&g_ctx.callbacks, callbacks, sizeof(frost_coordinator_callbacks_t));
    state_unlock();
}

// Schedules due reconnects, taking ownership of each stale handle so it can be
// destroyed after the state lock is dropped. Relays that have exhausted their
// attempts hand their handle to `doomed`: it is destroyed but never restarted.
static int schedule_reconnects(uint32_t now, relay_connection_t **relays,
                               ws_transport_handle_t *stale, ws_transport_handle_t *doomed,
                               int *doomed_count) {
    int n = 0;
    *doomed_count = 0;

    for (int i = 0; i < g_ctx.relay_count; i++) {
        relay_connection_t *relay = &g_ctx.relays[i];
        if (relay->state != COORDINATOR_STATE_RECONNECTING)
            continue;

        if (relay->reconnect.attempt_count >= WS_RECONNECT_MAX_ATTEMPTS) {
            ESP_LOGE(TAG, "Max reconnect attempts reached: %s", relay->url);
            if (relay->ws)
                doomed[(*doomed_count)++] = relay->ws;
            relay->ws = NULL;
            relay->state = COORDINATOR_STATE_ERROR;
            continue;
        }
        if (now - relay->reconnect.last_attempt_time < relay->reconnect.next_retry_ms)
            continue;

        // next_retry_ms is owned by enter_reconnecting(), which runs on every
        // failure and recomputes the delay from the updated attempt_count.
        relay->reconnect.attempt_count++;
        relay->reconnect.last_attempt_time = now;
        ESP_LOGI(TAG, "Reconnecting to %s (attempt %d/%d)", relay->url,
                 relay->reconnect.attempt_count, WS_RECONNECT_MAX_ATTEMPTS);

        relays[n] = relay;
        stale[n] = relay->ws;
        n++;
        relay->ws = NULL;
        relay->state = COORDINATOR_STATE_CONNECTING;
    }
    return n;
}

int frost_coordinator_poll(int timeout_ms) {
    if (!g_initialized)
        return -1;

#ifdef ESP_PLATFORM
    vTaskDelay(pdMS_TO_TICKS(timeout_ms > 0 ? timeout_ms : 10));
#else
    (void)timeout_ms;
#endif

    if (!op_lock())
        return -1;

    uint32_t now = coordinator_now_ms();

    relay_connection_t *retry[COORDINATOR_MAX_RELAYS];
    ws_transport_handle_t stale[COORDINATOR_MAX_RELAYS];
    ws_transport_handle_t doomed[COORDINATOR_MAX_RELAYS];
    int doomed_count = 0;

    state_lock();
    int retry_count = schedule_reconnects(now, retry, stale, doomed, &doomed_count);
    state_unlock();

    for (int i = 0; i < doomed_count; i++)
        ws_transport_destroy(doomed[i]);

    for (int i = 0; i < retry_count; i++) {
        if (stale[i])
            ws_transport_destroy(stale[i]);
        start_relay(retry[i]);
    }

    ws_transport_handle_t connected_handles[COORDINATOR_MAX_RELAYS];
    ws_transport_handle_t resub[COORDINATOR_MAX_RELAYS];
    relay_connection_t *resub_relay[COORDINATOR_MAX_RELAYS];
    buffered_event_t drained[WS_EVENT_BUFFER_SIZE];
    char filter[512];
    int resub_count = 0;
    uint8_t drained_count = 0;
    bool session_lost = false;

    state_lock();
    int connected = 0;
    int pending = 0;
    for (int i = 0; i < g_ctx.relay_count; i++) {
        relay_connection_t *relay = &g_ctx.relays[i];
        if (relay->state == COORDINATOR_STATE_CONNECTED) {
            connected++;
            if (relay->needs_resubscribe && relay->ws) {
                resub_relay[resub_count] = relay;
                resub[resub_count++] = relay->ws;
                relay->needs_resubscribe = false;
            }
        } else if (relay->state == COORDINATOR_STATE_RECONNECTING ||
                   relay->state == COORDINATOR_STATE_CONNECTING) {
            pending++;
        }
    }

    if (connected > 0) {
        g_ctx.disconnect_time = 0;
        g_ctx.session_interrupted = false;
        if (g_ctx.has_subscription)
            build_subscription_filter(filter, sizeof(filter), g_ctx.current_subscription);
        else
            resub_count = 0;
        drained_count = drain_event_buffer(drained);
        connected = snapshot_connected(connected_handles, NULL);
        g_ctx.state =
            g_ctx.has_subscription ? COORDINATOR_STATE_ACTIVE : COORDINATOR_STATE_CONNECTED;
    } else {
        if (g_ctx.session_interrupted && now - g_ctx.disconnect_time > WS_SESSION_RECOVERY_MS) {
            ESP_LOGE(TAG, "Session recovery timeout exceeded");
            g_ctx.state = COORDINATOR_STATE_ERROR;
            clear_event_buffer_unlocked();
            g_ctx.disconnect_time = 0;
            g_ctx.session_interrupted = false;
            session_lost = true;
        } else if (pending > 0 && g_ctx.state != COORDINATOR_STATE_ERROR) {
            g_ctx.state = COORDINATOR_STATE_RECONNECTING;
        }
    }
    state_unlock();

    // A relay whose REQ fails to send stays flagged, so the next poll retries it
    // rather than leaving it silently unsubscribed.
    for (int i = 0; i < resub_count; i++) {
        if (ws_transport_send_text(resub[i], filter, strlen(filter), WS_SEND_TIMEOUT_MS) == 0) {
            ESP_LOGI(TAG, "Resubscribed after reconnect");
        } else {
            ESP_LOGW(TAG, "Resubscribe failed; will retry");
            state_lock();
            resub_relay[i]->needs_resubscribe = true;
            state_unlock();
        }
    }

    // Replay preserves order; anything that fails to reach a relay goes back on
    // the buffer rather than being dropped.
    for (uint8_t i = 0; i < drained_count; i++) {
        int sent = send_to_handles(connected_handles, connected, drained[i].json, drained[i].len);
        if (sent > 0) {
            free(drained[i].json);
        } else {
            state_lock();
            buffer_event_take(drained[i].json, drained[i].len);
            state_unlock();
        }
    }
    if (drained_count > 0)
        ESP_LOGI(TAG, "Replayed %u buffered events", (unsigned)drained_count);

    op_unlock();

    if (session_lost)
        return -1;
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

    state_lock();
    memset(status, 0, sizeof(*status));
    status->state = g_ctx.state;
    status->total_relays = g_ctx.relay_count;
    status->session_active = g_ctx.has_subscription;

    for (int i = 0; i < g_ctx.relay_count; i++) {
        relay_connection_t *relay = &g_ctx.relays[i];
        if (relay->state == COORDINATOR_STATE_CONNECTED)
            status->connected_relays++;
        status->reconnect_attempts += relay->reconnect.attempt_count;
        status->relay_scores[i].relay_index = i;
        status->relay_scores[i].success_count = relay->success_count;
        status->relay_scores[i].fail_count = relay->fail_count;
    }
    state_unlock();
    return 0;
}

bool frost_coordinator_is_healthy(void) {
    if (!g_initialized)
        return false;

    state_lock();
    bool healthy = false;
    for (int i = 0; i < g_ctx.relay_count && !healthy; i++) {
        if (g_ctx.relays[i].state == COORDINATOR_STATE_CONNECTED && g_ctx.relays[i].health.healthy)
            healthy = true;
    }
    state_unlock();
    return healthy;
}
