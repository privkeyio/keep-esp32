// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#ifndef ESP_BSP_SHIM_H
#define ESP_BSP_SHIM_H

#include <stdbool.h>
#include <stdint.h>
#include "lvgl.h"

typedef int esp_err_t;
#define ESP_OK 0

typedef struct {
    int task_affinity;
} lvgl_port_cfg_t;

#define ESP_LVGL_PORT_INIT_CONFIG() \
    { .task_affinity = -1 }

typedef struct {
    lvgl_port_cfg_t lvgl_port_cfg;
    uint32_t buffer_size;
    bool double_buffer;
    struct {
        unsigned buff_dma : 1;
        unsigned buff_spiram : 1;
    } flags;
} bsp_display_cfg_t;

lv_display_t *bsp_display_start_with_config(const bsp_display_cfg_t *cfg);
esp_err_t bsp_display_backlight_on(void);
esp_err_t bsp_display_backlight_off(void);
bool bsp_display_lock(uint32_t timeout_ms);
void bsp_display_unlock(void);

#endif
