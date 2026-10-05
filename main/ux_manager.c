// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include "ux_interface.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <stdio.h>
#include <string.h>

#define TAG             "ux_manager"
#define UX_MAX_BACKENDS 4

static const ux_backend_t *backends[UX_MAX_BACKENDS];
static int backend_count = 0;
static const ux_backend_t *active_backend = NULL;

extern const ux_backend_t ux_serial_backend;
#ifdef CONFIG_KEEP_DISPLAY_ENABLED
extern const ux_backend_t ux_display_backend;
#endif

void ux_register_backend(const ux_backend_t *backend) {
    if (backend_count < UX_MAX_BACKENDS) {
        backends[backend_count++] = backend;
        ESP_LOGI(TAG, "Registered UX backend: %s", backend->name);
    }
}

const ux_backend_t *ux_get_backend(void) {
    return active_backend;
}

int ux_set_backend(const char *name) {
    for (int i = 0; i < backend_count; i++) {
        if (strcmp(backends[i]->name, name) == 0) {
            if (backends[i]->is_available && !backends[i]->is_available()) {
                ESP_LOGW(TAG, "Backend '%s' not available", name);
                return -1;
            }
            active_backend = backends[i];
            ESP_LOGI(TAG, "Set active UX backend: %s", name);
            return 0;
        }
    }
    ESP_LOGE(TAG, "Unknown UX backend: %s", name);
    return -1;
}

static bool display_available(void) {
#ifdef CONFIG_KEEP_DISPLAY_ENABLED
    return ux_display_backend.is_available && ux_display_backend.is_available();
#else
    return false;
#endif
}

int ux_init(void) {
    ux_register_backend(&ux_serial_backend);
#ifdef CONFIG_KEEP_DISPLAY_ENABLED
    ux_register_backend(&ux_display_backend);
#endif

#if defined(CONFIG_KEEP_UX_SERIAL)
    active_backend = &ux_serial_backend;
#elif defined(CONFIG_KEEP_UX_DISPLAY)
    if (!display_available()) {
        ESP_LOGE(TAG, "Display backend not available but forced");
        return -1;
    }
    active_backend = &ux_display_backend;
#elif defined(CONFIG_KEEP_DISPLAY_ENABLED)
    active_backend = display_available() ? &ux_display_backend : &ux_serial_backend;
#else
    active_backend = &ux_serial_backend;
#endif

    ESP_LOGI(TAG, "UX initialized with backend: %s", active_backend->name);

    if (active_backend->init) {
        return active_backend->init();
    }
    return 0;
}

static SemaphoreHandle_t pin_decision_sem = NULL;
static volatile bool pin_decision = false;

static void pin_decision_cb(bool approved, void *user_data) {
    (void)user_data;
    pin_decision = approved;
    xSemaphoreGive(pin_decision_sem);
}

bool ux_confirm_warden_pin(const uint8_t pubkey[32], uint32_t timeout_ms) {
    if (!active_backend || !active_backend->confirm_warden_pin || !pubkey) {
        return false;
    }
    if (!pin_decision_sem) {
        pin_decision_sem = xSemaphoreCreateBinary();
        if (!pin_decision_sem) {
            return false;
        }
    }
    xSemaphoreTake(pin_decision_sem, 0);
    pin_decision = false;

    char fingerprint[UX_WARDEN_FINGERPRINT_LEN];
    char *p = fingerprint;
    for (int i = 0; i < 32; i++) {
        p += snprintf(p, 3, "%02x", pubkey[i]);
        if (i % 4 == 3 && i != 31) {
            *p++ = ' ';
        }
    }
    *p = '\0';

    active_backend->confirm_warden_pin(fingerprint, pin_decision_cb, NULL);
    bool approved =
        xSemaphoreTake(pin_decision_sem, pdMS_TO_TICKS(timeout_ms)) == pdTRUE && pin_decision;

    if (!approved && active_backend->show_error) {
        active_backend->show_error("Policy", "Warden key not confirmed");
    }
    return approved;
}

void ux_report_warden_pin(bool saved) {
    if (!active_backend) {
        return;
    }
    if (saved && active_backend->set_policy_loaded) {
        active_backend->set_policy_loaded(true);
    }
    if (saved && active_backend->show_success) {
        active_backend->show_success("Warden key pinned");
    } else if (!saved && active_backend->show_error) {
        active_backend->show_error("Policy", "Warden key could not be saved");
    }
}
