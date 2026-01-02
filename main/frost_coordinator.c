#include "frost_coordinator.h"
#include "nostr_frost.h"
#include "crypto_asm.h"
#include "cJSON.h"
#include <noscrypt.h>

#ifdef ESP_PLATFORM
#include "esp_log.h"
#include "esp_websocket_client.h"
#include "esp_random.h"
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#else
#include <stdio.h>
#define ESP_LOGI(tag, fmt, ...) printf("[%s] " fmt "\n", tag, ##__VA_ARGS__)
#define ESP_LOGE(tag, fmt, ...) printf("[%s] ERROR: " fmt "\n", tag, ##__VA_ARGS__)
#define ESP_LOGW(tag, fmt, ...) printf("[%s] WARN: " fmt "\n", tag, ##__VA_ARGS__)

static int secure_random_fill(uint8_t *buf, size_t len) {
    FILE *fp = fopen("/dev/urandom", "r");
    if (!fp) {
        fprintf(stderr, "FATAL: Cannot open /dev/urandom\n");
        return -1;
    }
    size_t total = 0;
    while (total < len) {
        size_t n = fread(buf + total, 1, len - total, fp);
        if (n == 0) {
            fclose(fp);
            fprintf(stderr, "FATAL: Failed to read from /dev/urandom\n");
            return -1;
        }
        total += n;
    }
    fclose(fp);
    return 0;
}
#endif

#include <string.h>
#include <stdlib.h>

#define TAG "frost_coord"

typedef struct {
    char url[RELAY_URL_LEN];
    coordinator_state_t state;
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
#ifdef ESP_PLATFORM
    SemaphoreHandle_t mutex;
#endif
} coordinator_ctx_t;

static coordinator_ctx_t g_ctx;
static bool g_initialized = false;

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(out + 2*i, "%02x", bytes[i]);
    }
    out[len*2] = '\0';
}

#ifdef ESP_PLATFORM
static void websocket_event_handler(void *handler_args, esp_event_base_t base,
                                     int32_t event_id, void *event_data) {
    esp_websocket_event_data_t *data = (esp_websocket_event_data_t *)event_data;
    relay_connection_t *relay = (relay_connection_t *)handler_args;

    switch (event_id) {
        case WEBSOCKET_EVENT_CONNECTED:
            ESP_LOGI(TAG, "Relay connected: %s", relay->url);
            relay->state = COORDINATOR_STATE_CONNECTED;
            break;

        case WEBSOCKET_EVENT_DISCONNECTED:
            ESP_LOGW(TAG, "Relay disconnected: %s", relay->url);
            relay->state = COORDINATOR_STATE_IDLE;
            break;

        case WEBSOCKET_EVENT_DATA:
            if (data->op_code == 0x01 && data->data_len > 0) {
                char *msg = malloc(data->data_len + 1);
                if (msg) {
                    memcpy(msg, data->data_ptr, data->data_len);
                    msg[data->data_len] = '\0';

                    cJSON *arr = cJSON_Parse(msg);
                    if (arr && cJSON_IsArray(arr) && cJSON_GetArraySize(arr) >= 1) {
                        cJSON *type = cJSON_GetArrayItem(arr, 0);
                        if (type && cJSON_IsString(type)) {
                            if (strcmp(type->valuestring, "EVENT") == 0 && cJSON_GetArraySize(arr) >= 3) {
                                cJSON *event = cJSON_GetArrayItem(arr, 2);
                                if (event && cJSON_IsObject(event)) {
                                    cJSON *kind = cJSON_GetObjectItem(event, "kind");
                                    if (kind && cJSON_IsNumber(kind)) {
                                        char *event_str = cJSON_PrintUnformatted(event);
                                        if (event_str) {
                                            int k = kind->valueint;
                                            if (k == FROST_KIND_SIGN_REQUEST && g_ctx.callbacks.on_sign_request) {
                                                frost_sign_request_t req;
                                                if (frost_parse_sign_request(event_str, &g_ctx.current_group,
                                                                              g_ctx.privkey, &req) == 0) {
                                                    g_ctx.callbacks.on_sign_request(&req, g_ctx.callbacks.user_ctx);
                                                    frost_sign_request_free(&req);
                                                }
                                            } else if (k == FROST_KIND_SIGN_RESPONSE && g_ctx.callbacks.on_sign_response) {
                                                frost_sign_response_t resp;
                                                if (frost_parse_sign_response(event_str, &g_ctx.current_group,
                                                                               g_ctx.privkey, &resp) == 0) {
                                                    g_ctx.callbacks.on_sign_response(&resp, g_ctx.callbacks.user_ctx);
                                                }
                                            } else if (k == FROST_KIND_DKG_ROUND1 && g_ctx.callbacks.on_dkg_round1) {
                                                frost_dkg_round1_t r1;
                                                if (frost_parse_dkg_round1_event(event_str, &g_ctx.current_group, g_ctx.privkey, &r1) == 0) {
                                                    g_ctx.callbacks.on_dkg_round1(&r1, g_ctx.callbacks.user_ctx);
                                                }
                                            }
                                            free(event_str);
                                        }
                                    }
                                }
                            }
                        }
                        cJSON_Delete(arr);
                    } else if (arr) {
                        cJSON_Delete(arr);
                    }
                    free(msg);
                }
            }
            break;

        case WEBSOCKET_EVENT_ERROR:
            ESP_LOGE(TAG, "Relay error: %s", relay->url);
            relay->state = COORDINATOR_STATE_ERROR;
            break;

        default:
            break;
    }
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
#ifdef ESP_PLATFORM
    esp_fill_random(entropy, sizeof(entropy));
#else
    if (secure_random_fill(entropy, sizeof(entropy)) != 0) {
        ESP_LOGE(TAG, "Failed to get entropy from /dev/urandom");
        free(g_ctx.nc_ctx);
        return -3;
    }
#endif

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
    if (!g_initialized) return;

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

int frost_coordinator_add_relay(const char *url) {
    if (!g_initialized || !url) return -1;
    if (g_ctx.relay_count >= COORDINATOR_MAX_RELAYS) return -2;

    relay_connection_t *relay = &g_ctx.relays[g_ctx.relay_count];
    strncpy(relay->url, url, RELAY_URL_LEN - 1);
    relay->url[RELAY_URL_LEN - 1] = '\0';
    relay->state = COORDINATOR_STATE_IDLE;
    relay->ws_handle = NULL;

    g_ctx.relay_count++;
    ESP_LOGI(TAG, "Added relay: %s", url);
    return 0;
}

int frost_coordinator_connect(void) {
    if (!g_initialized) return -1;

#ifdef ESP_PLATFORM
    for (int i = 0; i < g_ctx.relay_count; i++) {
        relay_connection_t *relay = &g_ctx.relays[i];
        if (relay->state != COORDINATOR_STATE_IDLE) continue;

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
    if (!g_initialized) return -1;

#ifdef ESP_PLATFORM
    for (int i = 0; i < g_ctx.relay_count; i++) {
        relay_connection_t *relay = &g_ctx.relays[i];
        if (relay->ws_handle) {
            esp_websocket_client_stop(relay->ws_handle);
            esp_websocket_client_destroy(relay->ws_handle);
            relay->ws_handle = NULL;
        }
        relay->state = COORDINATOR_STATE_IDLE;
    }
#endif

    g_ctx.state = COORDINATOR_STATE_IDLE;
    ESP_LOGI(TAG, "Disconnected from all relays");
    return 0;
}

int frost_coordinator_set_group(const frost_group_t *group) {
    if (!g_initialized || !group) return -1;

    memcpy(&g_ctx.current_group, group, sizeof(frost_group_t));
    g_ctx.has_group = true;
    ESP_LOGI(TAG, "Group set (threshold=%d, participants=%d)",
             group->threshold, group->participant_count);
    return 0;
}

int frost_coordinator_subscribe(const char *subscription_id) {
    if (!g_initialized || !g_ctx.has_group) return -1;

    char pubkey_hex[65];
    bytes_to_hex(g_ctx.pubkey, 32, pubkey_hex);

    char filter[512];
    snprintf(filter, sizeof(filter),
             "[\"REQ\",\"%s\",{\"kinds\":[%d,%d,%d,%d,%d],\"#p\":[\"%s\"]}]",
             subscription_id,
             FROST_KIND_DKG_ROUND1, FROST_KIND_DKG_ROUND2,
             FROST_KIND_SIGN_REQUEST, FROST_KIND_SIGN_RESPONSE,
             NIP46_KIND_NOSTR_CONNECT,
             pubkey_hex);

#ifdef ESP_PLATFORM
    for (int i = 0; i < g_ctx.relay_count; i++) {
        relay_connection_t *relay = &g_ctx.relays[i];
        if (relay->state == COORDINATOR_STATE_CONNECTED && relay->ws_handle) {
            esp_websocket_client_send_text(relay->ws_handle, filter, strlen(filter), portMAX_DELAY);
            ESP_LOGI(TAG, "Subscribed on %s", relay->url);
        }
    }
#endif

    g_ctx.state = COORDINATOR_STATE_ACTIVE;
    return 0;
}

int frost_coordinator_unsubscribe(const char *subscription_id) {
    if (!g_initialized) return -1;

    char close_msg[128];
    snprintf(close_msg, sizeof(close_msg), "[\"CLOSE\",\"%s\"]", subscription_id);

#ifdef ESP_PLATFORM
    for (int i = 0; i < g_ctx.relay_count; i++) {
        relay_connection_t *relay = &g_ctx.relays[i];
        if (relay->state == COORDINATOR_STATE_CONNECTED && relay->ws_handle) {
            esp_websocket_client_send_text(relay->ws_handle, close_msg, strlen(close_msg), portMAX_DELAY);
        }
    }
#endif

    return 0;
}

static int publish_event(const char *event_json) {
    if (!g_initialized) return -1;

    char *msg = malloc(strlen(event_json) + 32);
    if (!msg) return -1;

    sprintf(msg, "[\"EVENT\",%s]", event_json);

    int published = 0;
#ifdef ESP_PLATFORM
    for (int i = 0; i < g_ctx.relay_count; i++) {
        relay_connection_t *relay = &g_ctx.relays[i];
        if (relay->state == COORDINATOR_STATE_CONNECTED && relay->ws_handle) {
            esp_websocket_client_send_text(relay->ws_handle, msg, strlen(msg), portMAX_DELAY);
            published++;
        }
    }
#endif

    free(msg);
    ESP_LOGI(TAG, "Published to %d relays", published);
    return published;
}

int frost_coordinator_publish_sign_request(const frost_sign_request_t *request) {
    if (!g_initialized || !g_ctx.has_group || !request) return -1;

    char event_json[4096];
    if (frost_create_sign_request(&g_ctx.current_group, request,
                                   g_ctx.privkey, event_json, sizeof(event_json)) != 0) {
        return -1;
    }

    return publish_event(event_json);
}

int frost_coordinator_publish_sign_response(const frost_sign_response_t *response) {
    if (!g_initialized || !g_ctx.has_group || !response) return -1;

    char event_json[2048];
    if (frost_create_sign_response(&g_ctx.current_group, response,
                                    g_ctx.privkey, event_json, sizeof(event_json)) != 0) {
        return -1;
    }

    return publish_event(event_json);
}

int frost_coordinator_publish_dkg_round1(const frost_dkg_round1_t *round1) {
    if (!g_initialized || !g_ctx.has_group || !round1) return -1;

    char event_json[2048];
    if (frost_create_dkg_round1_event(&g_ctx.current_group, round1,
                                       g_ctx.privkey, event_json, sizeof(event_json)) != 0) {
        return -1;
    }

    return publish_event(event_json);
}

int frost_coordinator_publish_dkg_round2(const frost_dkg_round2_t *round2,
                                          const uint8_t *recipient_pubkey) {
    if (!g_initialized || !g_ctx.has_group || !round2 || !recipient_pubkey) return -1;

    char event_json[2048];
    if (frost_create_dkg_round2_event(&g_ctx.current_group, round2,
                                       g_ctx.privkey, recipient_pubkey,
                                       event_json, sizeof(event_json)) != 0) {
        return -1;
    }

    return publish_event(event_json);
}

void frost_coordinator_set_callbacks(const frost_coordinator_callbacks_t *callbacks) {
    if (!g_initialized || !callbacks) return;
    memcpy(&g_ctx.callbacks, callbacks, sizeof(frost_coordinator_callbacks_t));
}

int frost_coordinator_poll(int timeout_ms) {
    if (!g_initialized) return -1;

#ifdef ESP_PLATFORM
    vTaskDelay(pdMS_TO_TICKS(timeout_ms > 0 ? timeout_ms : 10));
#endif

    int connected = 0;
    for (int i = 0; i < g_ctx.relay_count; i++) {
        if (g_ctx.relays[i].state == COORDINATOR_STATE_CONNECTED) {
            connected++;
        }
    }

    if (connected > 0 && g_ctx.state == COORDINATOR_STATE_CONNECTING) {
        g_ctx.state = COORDINATOR_STATE_CONNECTED;
    }

    return connected;
}

int frost_coordinator_get_pubkey(uint8_t pubkey[32]) {
    if (!g_initialized) return -1;
    memcpy(pubkey, g_ctx.pubkey, 32);
    return 0;
}
