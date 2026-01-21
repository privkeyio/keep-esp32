// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "touch_input.h"
#include "bsp/touch.h"
#include "esp_lcd_touch.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define TAG              "touch_input"
#define DEBOUNCE_MS      50
#define POLL_INTERVAL_MS 20

static esp_lcd_touch_handle_t touch_handle = NULL;
static bool last_pressed = false;
static TickType_t last_change_tick = 0;
static bool single_threaded_check_done = false;
static TaskHandle_t owner_task = NULL;

static void assert_single_threaded(void) {
    TaskHandle_t current = xTaskGetCurrentTaskHandle();
    if (!single_threaded_check_done) {
        owner_task = current;
        single_threaded_check_done = true;
    } else if (owner_task != current) {
        ESP_LOGE(TAG, "Touch module accessed from multiple tasks - not thread-safe!");
        configASSERT(0);
    }
}

static bool touch_init_if_needed(void) {
    if (touch_handle != NULL) {
        return true;
    }
    bsp_touch_config_t cfg = {.dummy = NULL};
    if (bsp_touch_new(&cfg, &touch_handle) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize touch");
        return false;
    }
    return true;
}

bool touch_poll(touch_point_t *point) {
    if (point == NULL) {
        return false;
    }
    assert_single_threaded();

    point->pressed = false;
    point->x = 0;
    point->y = 0;

    if (!touch_init_if_needed()) {
        return false;
    }

    if (esp_lcd_touch_read_data(touch_handle) != ESP_OK) {
        return false;
    }

    esp_lcd_touch_point_data_t point_data;
    uint8_t point_num = 0;

    if (esp_lcd_touch_get_data(touch_handle, &point_data, &point_num, 1) != ESP_OK) {
        return true;
    }

    bool pressed = (point_num > 0);
    TickType_t now = xTaskGetTickCount();

    if (pressed != last_pressed) {
        if ((now - last_change_tick) < pdMS_TO_TICKS(DEBOUNCE_MS)) {
            point->pressed = last_pressed;
            return true;
        }
        last_pressed = pressed;
        last_change_tick = now;
    }

    point->pressed = pressed;
    if (pressed) {
        point->x = (int16_t)point_data.x;
        point->y = (int16_t)point_data.y;
    }

    return true;
}

bool touch_wait_any(uint32_t timeout_ms) {
    if (!touch_init_if_needed()) {
        vTaskDelay(pdMS_TO_TICKS(timeout_ms));
        return false;
    }

    TickType_t start = xTaskGetTickCount();
    TickType_t timeout = pdMS_TO_TICKS(timeout_ms);

    while ((xTaskGetTickCount() - start) < timeout) {
        touch_point_t point;
        if (touch_poll(&point) && point.pressed) {
            return true;
        }
        vTaskDelay(pdMS_TO_TICKS(POLL_INTERVAL_MS));
    }
    return false;
}

bool touch_wait_release(uint32_t timeout_ms) {
    if (!touch_init_if_needed()) {
        vTaskDelay(pdMS_TO_TICKS(timeout_ms));
        return true;
    }

    TickType_t start = xTaskGetTickCount();
    TickType_t timeout = pdMS_TO_TICKS(timeout_ms);

    while ((xTaskGetTickCount() - start) < timeout) {
        touch_point_t point;
        if (touch_poll(&point) && !point.pressed) {
            return true;
        }
        vTaskDelay(pdMS_TO_TICKS(POLL_INTERVAL_MS));
    }
    return false;
}
