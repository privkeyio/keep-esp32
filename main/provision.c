#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs_sec_provider.h"
#include "esp_partition.h"
#include "mbedtls/platform_util.h"

static const char *TAG = "provision";
static int encrypted_nvs_available = 0;

static int hex_decode(const char *hex, uint8_t *out, size_t max_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > max_len) return -1;

    for (size_t i = 0; i < hex_len / 2; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return hex_len / 2;
}

static esp_err_t init_encrypted_nvs(void) {
    const esp_partition_t *part = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS_KEYS, "nvs_key");
    if (!part) return ESP_ERR_NOT_FOUND;

    nvs_sec_cfg_t cfg;
    esp_err_t err = nvs_flash_read_security_cfg(part, &cfg);
    if (err == ESP_ERR_NVS_KEYS_NOT_INITIALIZED) {
        err = nvs_flash_generate_keys(part, &cfg);
    }
    if (err != ESP_OK) return err;

    return nvs_flash_secure_init_partition("frost_nvs", &cfg);
}

int provision_share(const char *share_hex) {
    uint8_t share[128];
    int len = hex_decode(share_hex, share, sizeof(share));
    if (len < 0) {
        ESP_LOGE(TAG, "Invalid hex");
        return -1;
    }

    esp_err_t enc_err = init_encrypted_nvs();
    if (enc_err != ESP_OK) {
        ESP_LOGE(TAG, "Encrypted NVS required but unavailable (0x%x)", enc_err);
        mbedtls_platform_zeroize(share, sizeof(share));
        return -5;
    }
    encrypted_nvs_available = 1;

    nvs_handle_t nvs;
    esp_err_t err = nvs_open("frost", NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS");
        mbedtls_platform_zeroize(share, sizeof(share));
        return -2;
    }

    err = nvs_set_blob(nvs, "share", share, len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to write share");
        nvs_close(nvs);
        mbedtls_platform_zeroize(share, sizeof(share));
        return -3;
    }

    err = nvs_commit(nvs);
    nvs_close(nvs);
    mbedtls_platform_zeroize(share, sizeof(share));

    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Share provisioned (%d bytes)", len);
        return 0;
    }
    return -4;
}

int erase_share(void) {
    nvs_handle_t nvs;
    esp_err_t err = nvs_open("frost", NVS_READWRITE, &nvs);
    if (err != ESP_OK) return -1;

    nvs_erase_key(nvs, "share");
    nvs_commit(nvs);
    nvs_close(nvs);

    ESP_LOGI(TAG, "Share erased");
    return 0;
}
