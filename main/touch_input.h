// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef TOUCH_INPUT_H
#define TOUCH_INPUT_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    int16_t x;
    int16_t y;
    bool pressed;
} touch_point_t;

bool touch_poll(touch_point_t *point);
bool touch_wait_any(uint32_t timeout_ms);
bool touch_wait_release(uint32_t timeout_ms);

#endif
