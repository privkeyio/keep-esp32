#include "nostr_client.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef ESP_PLATFORM
#include "esp_websocket_client.h"
#include "esp_log.h"
#include "cJSON.h"
#include <nostr.h>

static const char *TAG = "nostr";

static void ws_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data) {
    nostr_client_t *client = (nostr_client_t *)arg;
    esp_websocket_event_data_t *ws_data = (esp_websocket_event_data_t *)data;

    switch (id) {
    case WEBSOCKET_EVENT_CONNECTED:
        client->connected = true;
        ESP_LOGI(TAG, "Connected to relay");
        break;
    case WEBSOCKET_EVENT_DISCONNECTED:
        client->connected = false;
        ESP_LOGI(TAG, "Disconnected from relay");
        break;
    case WEBSOCKET_EVENT_DATA:
        if (ws_data->op_code == 0x01 && ws_data->data_len > 0) {
            char *msg = malloc(ws_data->data_len + 1);
            if (msg) {
                memcpy(msg, ws_data->data_ptr, ws_data->data_len);
                msg[ws_data->data_len] = '\0';

                cJSON *arr = cJSON_Parse(msg);
                if (arr && cJSON_IsArray(arr)) {
                    cJSON *type = cJSON_GetArrayItem(arr, 0);
                    if (type && cJSON_IsString(type) && strcmp(type->valuestring, "EVENT") == 0) {
                        cJSON *event = cJSON_GetArrayItem(arr, 2);
                        if (event) {
                            cJSON *content = cJSON_GetObjectItem(event, "content");
                            if (content && cJSON_IsString(content) && client->on_message) {
                                client->on_message(content->valuestring, client->user_ctx);
                            }
                        }
                    }
                }
                if (arr) cJSON_Delete(arr);
                free(msg);
            }
        }
        break;
    default:
        break;
    }
}

int nostr_client_init(nostr_client_t *client, const uint8_t *privkey) {
    memset(client, 0, sizeof(*client));
    memcpy(client->privkey, privkey, 32);

    nostr_privkey priv;
    nostr_keypair keypair;
    memcpy(priv.data, privkey, 32);
    if (nostr_keypair_from_private_key(&keypair, &priv) != NOSTR_OK) return -1;
    memcpy(client->pubkey, keypair.pubkey.data, 32);

    return 0;
}

int nostr_client_connect(nostr_client_t *client, const char *relay_url) {
    strncpy(client->relay_url, relay_url, sizeof(client->relay_url) - 1);

    esp_websocket_client_config_t ws_cfg = {
        .uri = relay_url,
        .buffer_size = 4096,
    };

    client->ws_client = esp_websocket_client_init(&ws_cfg);
    if (!client->ws_client) return -1;

    esp_websocket_register_events(client->ws_client, WEBSOCKET_EVENT_ANY, ws_event_handler, client);

    if (esp_websocket_client_start(client->ws_client) != ESP_OK) {
        esp_websocket_client_destroy(client->ws_client);
        client->ws_client = NULL;
        return -2;
    }

    return 0;
}

void nostr_client_disconnect(nostr_client_t *client) {
    if (client->ws_client) {
        esp_websocket_client_stop(client->ws_client);
        esp_websocket_client_destroy(client->ws_client);
        client->ws_client = NULL;
    }
    client->connected = false;
}

static void hex_encode(const uint8_t *data, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) sprintf(out + i * 2, "%02x", data[i]);
    out[len * 2] = '\0';
}

int nostr_client_subscribe(nostr_client_t *client, const uint8_t *group_pubkey) {
    if (!client->connected) return -1;

    snprintf(client->sub_id, sizeof(client->sub_id), "kfp%08x", (unsigned)esp_random());

    char gpk_hex[65];
    hex_encode(group_pubkey, 32, gpk_hex);

    char req[512];
    snprintf(req, sizeof(req),
        "[\"REQ\",\"%s\",{\"kinds\":[24242],\"#p\":[\"%s\"]}]",
        client->sub_id, gpk_hex);

    return esp_websocket_client_send_text(client->ws_client, req, strlen(req), portMAX_DELAY) > 0 ? 0 : -1;
}

int nostr_client_unsubscribe(nostr_client_t *client) {
    if (!client->connected || !client->sub_id[0]) return -1;

    char req[64];
    snprintf(req, sizeof(req), "[\"CLOSE\",\"%s\"]", client->sub_id);
    client->sub_id[0] = '\0';

    return esp_websocket_client_send_text(client->ws_client, req, strlen(req), portMAX_DELAY) > 0 ? 0 : -1;
}

int nostr_client_publish(nostr_client_t *client, const uint8_t *recipient_pubkey,
                         const char *content, bool encrypted) {
    if (!client->connected) return -1;

    char *payload = NULL;
    if (encrypted && recipient_pubkey) {
        nostr_privkey priv;
        nostr_key recip;
        memcpy(priv.data, client->privkey, 32);
        memcpy(recip.data, recipient_pubkey, 32);
        if (nostr_nip44_encrypt(&priv, &recip, content, strlen(content), &payload) != NOSTR_OK) {
            return -2;
        }
    } else {
        payload = strdup(content);
    }
    if (!payload) return -3;

    nostr_event *event = NULL;
    if (nostr_event_create(&event) != NOSTR_OK) {
        free(payload);
        return -4;
    }

    event->kind = 24242;
    nostr_event_set_content(event, payload);

    if (recipient_pubkey) {
        char p_hex[65];
        hex_encode(recipient_pubkey, 32, p_hex);
        const char *tag_vals[] = {"p", p_hex};
        nostr_event_add_tag(event, tag_vals, 2);
    }

    nostr_privkey priv;
    memcpy(priv.data, client->privkey, 32);
    nostr_event_sign(event, &priv);

    char *event_json = NULL;
    nostr_event_to_json(event, &event_json);
    nostr_event_destroy(event);
    free(payload);

    if (!event_json) return -5;

    char *msg = malloc(strlen(event_json) + 32);
    sprintf(msg, "[\"EVENT\",%s]", event_json);
    free(event_json);

    int ret = esp_websocket_client_send_text(client->ws_client, msg, strlen(msg), portMAX_DELAY);
    free(msg);

    return ret > 0 ? 0 : -6;
}

void nostr_client_set_callback(nostr_client_t *client, nostr_msg_cb cb, void *ctx) {
    client->on_message = cb;
    client->user_ctx = ctx;
}

#else

int nostr_client_init(nostr_client_t *client, const uint8_t *privkey) {
    memset(client, 0, sizeof(*client));
    memcpy(client->privkey, privkey, 32);
    return 0;
}

int nostr_client_connect(nostr_client_t *client, const char *relay_url) {
    (void)client; (void)relay_url;
    return -1;
}

void nostr_client_disconnect(nostr_client_t *client) { (void)client; }

int nostr_client_subscribe(nostr_client_t *client, const uint8_t *group_pubkey) {
    (void)client; (void)group_pubkey;
    return -1;
}

int nostr_client_unsubscribe(nostr_client_t *client) {
    (void)client;
    return -1;
}

int nostr_client_publish(nostr_client_t *client, const uint8_t *recipient_pubkey,
                         const char *content, bool encrypted) {
    (void)client; (void)recipient_pubkey; (void)content; (void)encrypted;
    return -1;
}

void nostr_client_set_callback(nostr_client_t *client, nostr_msg_cb cb, void *ctx) {
    client->on_message = cb;
    client->user_ctx = ctx;
}

#endif
