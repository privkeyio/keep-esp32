// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#ifndef LOG_COMPAT_H
#define LOG_COMPAT_H

#ifdef ESP_PLATFORM
#include "esp_log.h"
#else
#include <stdio.h>
#ifndef ESP_LOGE
#define ESP_LOGE(tag, fmt, ...) fprintf(stderr, "E (%s): " fmt "\n", tag, ##__VA_ARGS__)
#endif
#ifndef ESP_LOGW
#define ESP_LOGW(tag, fmt, ...) fprintf(stderr, "W (%s): " fmt "\n", tag, ##__VA_ARGS__)
#endif
#ifndef ESP_LOGI
#define ESP_LOGI(tag, fmt, ...) printf("I (%s): " fmt "\n", tag, ##__VA_ARGS__)
#endif
#endif

#endif
