// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#ifndef UI_HARNESS_H
#define UI_HARNESS_H

#include <stdbool.h>
#include <stdint.h>

/* The test thread plays the LVGL task: every step holds the display lock, as
 * esp_lvgl_port does, while the code under test runs on ui_call threads the way
 * request handlers run on the device. Time only moves when the test advances it. */

void ui_run(uint32_t ms);
bool ui_settle(bool (*done)(void *), void *arg);

void ui_press(int x, int y);
void ui_release(void);
void ui_tap(int x, int y);
bool ui_find_text(const char *text, int *x, int *y);
bool ui_has_text(const char *text);
bool ui_tap_text(const char *text);

int ui_screenshot(const char *path);

typedef struct ui_call ui_call_t;
ui_call_t *ui_call_start(void *(*fn)(void *), void *arg);
bool ui_call_done(void *call);
bool ui_sem_waiting(void *unused);
void *ui_call_join(ui_call_t *call);

#endif
