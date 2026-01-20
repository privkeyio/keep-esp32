// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "touch_input.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

bool touch_poll(touch_point_t *point) {
    if (point == NULL) {
        return false;
    }
    point->pressed = false;
    return false;
}

bool touch_wait_any(uint32_t timeout_ms) {
    vTaskDelay(pdMS_TO_TICKS(timeout_ms));
    return false;
}

bool touch_wait_release(uint32_t timeout_ms) {
    vTaskDelay(pdMS_TO_TICKS(timeout_ms));
    return true;
}
