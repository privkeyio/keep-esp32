// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

/* Ticks are milliseconds of the harness's virtual clock, which only the test advances. */
#ifndef FREERTOS_H
#define FREERTOS_H

#include <stdint.h>

typedef uint32_t TickType_t;
typedef int BaseType_t;

#define pdTRUE            1
#define pdFALSE           0
#define portMAX_DELAY     0xffffffffu
#define pdMS_TO_TICKS(ms) ((TickType_t)(ms))

TickType_t xTaskGetTickCount(void);
void vTaskDelay(TickType_t ticks);

#endif
