#include "esp_random.h"
#include "esp_log.h"
#include "secp256k1.h"
#include <stddef.h>

static const char *TAG = "secp256k1";

int fill_random(unsigned char *buf, size_t len) {
    if (buf == NULL || len == 0) {
        return 0;
    }
    esp_fill_random(buf, len);
    return 1;
}

void secp256k1_default_error_callback_fn(const char *message, void *data) {
    (void)data;
    ESP_LOGE(TAG, "internal error: %s", message ? message : "(null)");
}

void secp256k1_default_illegal_callback_fn(const char *message, void *data) {
    (void)data;
    ESP_LOGE(TAG, "illegal argument: %s", message ? message : "(null)");
}

secp256k1_context *frost_context_create(void) {
    return secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

void frost_context_destroy(secp256k1_context *ctx) {
    if (ctx) {
        secp256k1_context_destroy(ctx);
    }
}
