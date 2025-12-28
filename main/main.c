#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"

#include "kfp.h"
#include "session.h"
#include "frost.h"
#include "nostr_client.h"

static const uint8_t NOSTR_KEY_DOMAIN[] = "keep-esp32-nostr-v1";

static const char *TAG = "frost";

#define WIFI_SSID CONFIG_WIFI_SSID
#define WIFI_PASS CONFIG_WIFI_PASSWORD
#define RELAY_URL CONFIG_NOSTR_RELAY_URL

static EventGroupHandle_t wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0

static frost_state_t frost;
static nostr_client_t nostr;
static session_t sessions[MAX_ACTIVE_SESSIONS];
static uint8_t active_session_count = 0;

static void wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data) {
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wifi_init(void) {
    wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_handler, NULL);
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event_handler, NULL);

    wifi_config_t wifi_cfg = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    xEventGroupWaitBits(wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdTRUE, portMAX_DELAY);
    ESP_LOGI(TAG, "WiFi connected");
}

static int load_share_from_nvs(uint8_t *share_out, size_t *len_out) {
    nvs_handle_t nvs;
    esp_err_t err = nvs_open("frost", NVS_READONLY, &nvs);
    if (err != ESP_OK) return -1;

    size_t len = 128;
    err = nvs_get_blob(nvs, "share", share_out, &len);
    nvs_close(nvs);

    if (err == ESP_OK) {
        *len_out = len;
        return 0;
    }
    return -1;
}

static session_t *find_session(const uint8_t *session_id) {
    for (int i = 0; i < active_session_count; i++) {
        if (memcmp(sessions[i].session_id, session_id, 32) == 0) {
            return &sessions[i];
        }
    }
    return NULL;
}

static session_t *create_session(const kfp_sign_request_t *req) {
    if (active_session_count >= MAX_ACTIVE_SESSIONS) {
        for (int i = 0; i < MAX_ACTIVE_SESSIONS; i++) {
            session_state_t st = session_state(&sessions[i]);
            if (st == SESSION_COMPLETE || st == SESSION_FAILED || st == SESSION_EXPIRED) {
                session_init(&sessions[i], req, frost.threshold);
                return &sessions[i];
            }
        }
        return NULL;
    }
    session_init(&sessions[active_session_count], req, frost.threshold);
    return &sessions[active_session_count++];
}

static void send_commitment(session_t *s) {
    uint8_t commitment[132];
    size_t len;
    if (frost_create_commitment(&frost, s, commitment, &len) != 0) {
        ESP_LOGE(TAG, "Failed to create commitment");
        return;
    }

    kfp_commitment_t c;
    memcpy(c.session_id, s->session_id, 32);
    c.share_index = frost.share_index;
    memcpy(c.commitment, commitment, len);
    c.commitment_len = len;

    char *json = kfp_serialize_commitment(&c);
    if (json) {
        nostr_client_publish(&nostr, frost.group_pubkey, json, true);
        free(json);
        ESP_LOGI(TAG, "Sent commitment");
    }
}

static void send_signature_share(session_t *s) {
    uint8_t msg_hash[32];
    memcpy(msg_hash, s->message, 32 < s->message_len ? 32 : s->message_len);

    uint8_t share[36];
    size_t len;
    if (frost_sign(&frost, s, msg_hash, 32, share, &len) != 0) {
        ESP_LOGE(TAG, "Failed to create signature share");
        return;
    }

    kfp_signature_share_t ss;
    memcpy(ss.session_id, s->session_id, 32);
    ss.share_index = frost.share_index;
    memcpy(ss.signature_share, share, len);
    ss.share_len = len;

    char *json = kfp_serialize_signature_share(&ss);
    if (json) {
        nostr_client_publish(&nostr, frost.group_pubkey, json, true);
        free(json);
        ESP_LOGI(TAG, "Sent signature share");
    }
}

static void handle_sign_request(const kfp_sign_request_t *req) {
    if (memcmp(req->group_pubkey, frost.group_pubkey, 32) != 0) return;

    bool is_participant = false;
    for (int i = 0; i < req->participant_count; i++) {
        if (req->participants[i] == frost.share_index) {
            is_participant = true;
            break;
        }
    }
    if (!is_participant) return;

    if (find_session(req->session_id)) return;

    session_t *s = create_session(req);
    if (!s) {
        ESP_LOGE(TAG, "Cannot create session");
        return;
    }

    ESP_LOGI(TAG, "New signing session");
    send_commitment(s);
}

static void handle_commitment(const kfp_commitment_t *c) {
    if (c->share_index == frost.share_index) return;

    session_t *s = find_session(c->session_id);
    if (!s) return;

    if (session_add_commitment(s, c->share_index, c->commitment, c->commitment_len) != 0) return;

    if (session_has_all_commitments(s)) {
        ESP_LOGI(TAG, "All commitments received");
        send_signature_share(s);
    }
}

static void handle_signature_share(const kfp_signature_share_t *ss) {
    if (ss->share_index == frost.share_index) return;

    session_t *s = find_session(ss->session_id);
    if (!s) return;

    session_add_signature_share(s, ss->share_index, ss->signature_share, ss->share_len);
}

static void handle_ping(const kfp_ping_t *ping) {
    kfp_pong_t pong;
    memcpy(pong.challenge, ping->challenge, 32);
    pong.timestamp = ping->timestamp;

    char *json = kfp_serialize_pong(&pong);
    if (json) {
        nostr_client_publish(&nostr, NULL, json, false);
        free(json);
    }
}

static void nostr_message_handler(const char *json, void *ctx) {
    kfp_msg_t msg;
    kfp_msg_type_t t = kfp_parse(json, &msg);

    switch (t) {
    case KFP_MSG_SIGN_REQUEST:
        handle_sign_request(&msg.sign_request);
        break;
    case KFP_MSG_COMMITMENT:
        handle_commitment(&msg.commitment);
        break;
    case KFP_MSG_SIGNATURE_SHARE:
        handle_signature_share(&msg.signature_share);
        break;
    case KFP_MSG_PING:
        handle_ping(&msg.ping);
        break;
    default:
        break;
    }
}

void app_main(void) {
    ESP_LOGI(TAG, "FROST Participant starting");

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    uint8_t share[128];
    size_t share_len;
    if (load_share_from_nvs(share, &share_len) != 0) {
        ESP_LOGE(TAG, "No FROST share in NVS");
        return;
    }

    if (frost_init(&frost, share, share_len) != 0) {
        mbedtls_platform_zeroize(share, sizeof(share));
        ESP_LOGE(TAG, "Failed to init FROST");
        return;
    }
    ESP_LOGI(TAG, "FROST initialized, share index %d", frost.share_index);

    mbedtls_platform_zeroize(share, sizeof(share));

    wifi_init();

    uint8_t nostr_privkey[32];
    int hkdf_ret = mbedtls_hkdf(
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        NOSTR_KEY_DOMAIN, sizeof(NOSTR_KEY_DOMAIN) - 1,
        frost.group_pubkey, 32,
        (const uint8_t *)"nostr-signing-key", 17,
        nostr_privkey, 32
    );
    if (hkdf_ret != 0) {
        ESP_LOGE(TAG, "Failed to derive Nostr key");
        frost_free(&frost);
        return;
    }

    if (nostr_client_init(&nostr, nostr_privkey) != 0) {
        mbedtls_platform_zeroize(nostr_privkey, sizeof(nostr_privkey));
        ESP_LOGE(TAG, "Failed to init Nostr");
        frost_free(&frost);
        return;
    }
    mbedtls_platform_zeroize(nostr_privkey, sizeof(nostr_privkey));

    nostr_client_set_callback(&nostr, nostr_message_handler, NULL);

    if (nostr_client_connect(&nostr, RELAY_URL) != 0) {
        ESP_LOGE(TAG, "Failed to connect to relay");
        return;
    }

    vTaskDelay(pdMS_TO_TICKS(1000));

    if (nostr_client_subscribe(&nostr, frost.group_pubkey) != 0) {
        ESP_LOGE(TAG, "Failed to subscribe");
        return;
    }

    ESP_LOGI(TAG, "Subscribed, waiting for sign requests");

    kfp_announce_t ann;
    ann.version = KFP_VERSION;
    memcpy(ann.group_pubkey, frost.group_pubkey, 32);
    ann.share_index = frost.share_index;
    ann.name[0] = '\0';

    char *ann_json = kfp_serialize_announce(&ann);
    if (ann_json) {
        nostr_client_publish(&nostr, frost.group_pubkey, ann_json, true);
        free(ann_json);
        ESP_LOGI(TAG, "Announced presence");
    }

    while (1) {
        for (int i = 0; i < active_session_count; i++) {
            session_state(&sessions[i]);
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}
