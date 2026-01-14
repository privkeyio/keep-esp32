#include "ux_interface.h"
#include "esp_log.h"
#include <string.h>

#define TAG "ux_manager"
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
