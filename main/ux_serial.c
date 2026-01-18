#include "ux_interface.h"
#include "esp_log.h"

#define TAG "ux_serial"

static int serial_init(void) {
    ESP_LOGI(TAG, "Serial UX backend initialized");
    return 0;
}

static void serial_deinit(void) {
}

static void serial_show_idle(const char *device_name, bool policy_loaded, uint32_t policy_version) {
    ESP_LOGI(TAG, "Device ready: %s, policy=%s v%lu", device_name, policy_loaded ? "yes" : "no",
             (unsigned long)policy_version);
}

static void serial_show_scanning(void) {
    ESP_LOGI(TAG, "Awaiting data via serial protocol");
}

static void serial_show_signing(int current, int total) {
    ESP_LOGI(TAG, "Signing input %d/%d", current, total);
}

static void serial_show_success(const char *message) {
    ESP_LOGI(TAG, "Success: %s", message);
}

static void serial_show_error(const char *title, const char *message) {
    ESP_LOGE(TAG, "Error [%s]: %s", title, message);
}

static void serial_confirm_transaction(const ux_tx_info_t *tx, ux_decision_cb_t cb,
                                       void *user_data) {
    if (cb == NULL) {
        ESP_LOGE(TAG, "Null callback in confirm_transaction");
        return;
    }
    if (tx == NULL) {
        ESP_LOGW(TAG, "Null tx info, rejecting transaction");
        cb(false, user_data);
        return;
    }
    if (tx->policy_approved) {
        ESP_LOGI(TAG, "Transaction auto-approved by policy");
        cb(true, user_data);
    } else {
        ESP_LOGW(TAG, "Transaction rejected - outside policy (headless mode)");
        cb(false, user_data);
    }
}

static void serial_show_qr(const char *data, size_t len) {
    (void)data;
    (void)len;
    ESP_LOGW(TAG, "QR display not available in serial mode");
}

static int serial_scan_qr(char *data, size_t max_len, uint32_t timeout_ms) {
    (void)data;
    (void)max_len;
    (void)timeout_ms;
    ESP_LOGW(TAG, "QR scan not available in serial mode");
    return -1;
}

static bool serial_wait_any_input(uint32_t timeout_ms) {
    (void)timeout_ms;
    return false;
}

static bool serial_is_available(void) {
    return true;
}

const ux_backend_t ux_serial_backend = {
    .name = "serial",
    .init = serial_init,
    .deinit = serial_deinit,
    .show_idle = serial_show_idle,
    .show_scanning = serial_show_scanning,
    .show_signing = serial_show_signing,
    .show_success = serial_show_success,
    .show_error = serial_show_error,
    .confirm_transaction = serial_confirm_transaction,
    .show_qr = serial_show_qr,
    .scan_qr = serial_scan_qr,
    .wait_any_input = serial_wait_any_input,
    .is_available = serial_is_available,
};
