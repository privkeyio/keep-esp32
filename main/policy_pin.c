// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include "policy.h"
#include "nvs.h"
#include <string.h>

#define PIN_NAMESPACE "policy_pin"
#define PIN_KEY       "pin"

int policy_pin_read(policy_pin_t *pin) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(PIN_NAMESPACE, NVS_READONLY, &handle);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return POLICY_ERR_NOT_FOUND;
    }
    if (err != ESP_OK) {
        return POLICY_ERR_STORAGE;
    }
    size_t len = sizeof(*pin);
    err = nvs_get_blob(handle, PIN_KEY, pin, &len);
    nvs_close(handle);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return POLICY_ERR_NOT_FOUND;
    }
    if (err != ESP_OK || len != sizeof(*pin)) {
        return POLICY_ERR_STORAGE;
    }
    return 0;
}

int policy_pin_write(const policy_pin_t *pin) {
    nvs_handle_t handle;
    if (nvs_open(PIN_NAMESPACE, NVS_READWRITE, &handle) != ESP_OK) {
        return POLICY_ERR_STORAGE;
    }
    esp_err_t err = nvs_set_blob(handle, PIN_KEY, pin, sizeof(*pin));
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    nvs_close(handle);
    return err == ESP_OK ? 0 : POLICY_ERR_STORAGE;
}
