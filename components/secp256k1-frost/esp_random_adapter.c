// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include "esp_random.h"
#include "esp_log.h"
#include "secp256k1.h"
#include <stddef.h>

static const char *TAG = "secp256k1";

/*
 * The symbol libsecp256k1's own helpers expect. Nothing in this firmware calls
 * it today -- FROST nonce and key material go through rng_fill_checked() in
 * main/ -- but it is a public symbol, so it must not be the one weak path in
 * the image. esp_fill_random() is a true RNG here only because
 * hw_entropy_init() enables the SAR ADC entropy source at boot and never
 * disables it; this component cannot depend on main/, so that invariant is
 * enforced by scripts/check-rng-hygiene.sh rather than by a call into it.
 */
int fill_random(unsigned char *buf, size_t len) {
    if (buf == NULL || len == 0) {
        return 0;
    }
    // rng-hygiene: ok - see the comment above; sound while the boot-time
    // entropy source stays enabled, which the hygiene guard pins.
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
