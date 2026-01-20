// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifdef CONFIG_KEEP_DISPLAY_ENABLED

#include "touch_input.h"
#include "bsp/esp-bsp.h"
#include "esp_lcd_touch.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

extern esp_lcd_touch_handle_t bsp_touch_handle;

bool touch_poll(touch_point_t *point) {
    if (point == NULL || bsp_touch_handle == NULL) {
        return false;
    }

    uint16_t x, y;
    uint8_t count = 0;

    esp_lcd_touch_read_data(bsp_touch_handle);
    esp_lcd_touch_get_coordinates(bsp_touch_handle, &x, &y, NULL, &count, 1);

    if (count > 0) {
        point->x = x;
        point->y = y;
        point->pressed = true;
        return true;
    }

    point->pressed = false;
    return false;
}

bool touch_wait_any(uint32_t timeout_ms) {
    TickType_t start = xTaskGetTickCount();
    TickType_t timeout = pdMS_TO_TICKS(timeout_ms);
    touch_point_t point;

    while ((xTaskGetTickCount() - start) < timeout) {
        if (touch_poll(&point) && point.pressed) {
            return true;
        }
        vTaskDelay(pdMS_TO_TICKS(20));
    }

    return false;
}

bool touch_wait_release(uint32_t timeout_ms) {
    TickType_t start = xTaskGetTickCount();
    TickType_t timeout = pdMS_TO_TICKS(timeout_ms);
    touch_point_t point;

    while ((xTaskGetTickCount() - start) < timeout) {
        if (!touch_poll(&point) || !point.pressed) {
            return true;
        }
        vTaskDelay(pdMS_TO_TICKS(20));
    }

    return false;
}

#endif
