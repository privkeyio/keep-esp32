#include "storage.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "mbedtls/sha256.h"
#include <string.h>
#include <stdio.h>

#define TAG "storage"
#define NVS_NAMESPACE "frost_shares"

static nvs_handle_t storage_nvs;
static bool initialized = false;

static int hex_to_bytes(const char *hex, unsigned char *out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > out_len) return -1;

    for (size_t i = 0; i < hex_len / 2; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1) return -1;
        out[i] = (unsigned char)byte;
    }
    return hex_len / 2;
}

static void bytes_to_hex(const unsigned char *bytes, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(out + 2 * i, "%02x", bytes[i]);
    }
    out[len * 2] = '\0';
}

static void make_nvs_key(const char *group, char *key, size_t key_len) {
    unsigned char hash[32];
    mbedtls_sha256((const unsigned char *)group, strlen(group), hash, 0);
    if (key_len < 12) {
        key[0] = '\0';
        return;
    }
    snprintf(key, key_len, "sh_%02x%02x%02x%02x", hash[0], hash[1], hash[2], hash[3]);
}

int storage_init(void) {
    if (initialized) return 0;

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS needs erase");
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &storage_nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
        return -1;
    }

    initialized = true;
    ESP_LOGI(TAG, "Storage initialized");
    return 0;
}

int storage_save_share(const char *group, const char *share_hex) {
    if (!initialized) return -1;

    unsigned char share_bytes[STORAGE_SHARE_LEN];
    int share_len = hex_to_bytes(share_hex, share_bytes, sizeof(share_bytes));
    if (share_len < 0) {
        ESP_LOGE(TAG, "Invalid share hex");
        return -1;
    }

    char key[16];
    make_nvs_key(group, key, sizeof(key));

    esp_err_t err = nvs_set_blob(storage_nvs, key, share_bytes, share_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to save share: %s", esp_err_to_name(err));
        return -1;
    }

    char group_key[16];
    snprintf(group_key, sizeof(group_key), "g_%s", key + 3);
    nvs_set_str(storage_nvs, group_key, group);

    err = nvs_commit(storage_nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to commit: %s", esp_err_to_name(err));
        return -1;
    }

    ESP_LOGI(TAG, "Saved share for group %.16s...", group);
    return 0;
}

int storage_load_share(const char *group, char *share_hex, size_t len) {
    if (!initialized) return -1;

    char key[16];
    make_nvs_key(group, key, sizeof(key));

    unsigned char share_bytes[STORAGE_SHARE_LEN];
    size_t share_len = sizeof(share_bytes);

    esp_err_t err = nvs_get_blob(storage_nvs, key, share_bytes, &share_len);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return -1;
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to load share: %s", esp_err_to_name(err));
        return -1;
    }

    if (share_len * 2 + 1 > len) {
        ESP_LOGE(TAG, "Output buffer too small");
        return -1;
    }

    bytes_to_hex(share_bytes, share_len, share_hex);
    return 0;
}

int storage_delete_share(const char *group) {
    if (!initialized) return -1;

    char key[16];
    make_nvs_key(group, key, sizeof(key));

    nvs_erase_key(storage_nvs, key);

    char group_key[16];
    snprintf(group_key, sizeof(group_key), "g_%s", key + 3);
    nvs_erase_key(storage_nvs, group_key);

    nvs_commit(storage_nvs);

    ESP_LOGI(TAG, "Deleted share for group %.16s...", group);
    return 0;
}

int storage_list_shares(char groups[][STORAGE_GROUP_LEN + 1], int max_groups) {
    if (!initialized) return 0;

    nvs_iterator_t it = NULL;
    esp_err_t err = nvs_entry_find(NVS_DEFAULT_PART_NAME, NVS_NAMESPACE, NVS_TYPE_STR, &it);

    int count = 0;
    while (err == ESP_OK && count < max_groups) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);

        if (strncmp(info.key, "g_", 2) == 0) {
            size_t len = STORAGE_GROUP_LEN;
            nvs_get_str(storage_nvs, info.key, groups[count], &len);
            count++;
        }

        err = nvs_entry_next(&it);
    }
    nvs_release_iterator(it);

    return count;
}

bool storage_has_share(const char *group) {
    if (!initialized) return false;

    char key[16];
    make_nvs_key(group, key, sizeof(key));

    size_t len = 0;
    esp_err_t err = nvs_get_blob(storage_nvs, key, NULL, &len);
    return (err == ESP_OK && len > 0);
}
