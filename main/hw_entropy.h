// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#ifndef HW_ENTROPY_H
#define HW_ENTROPY_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/*
 * Thread-safety: hw_entropy_init() must be called once before any other
 * hw_entropy functions, typically at startup. After initialization,
 * hw_entropy_fill() is NOT thread-safe and must be protected by external
 * locking if called from multiple threads. On ESP32, consider using a mutex
 * or restricting calls to a single task.
 */

int hw_entropy_init(void);
int hw_entropy_fill(uint8_t *buf, size_t len);

/*
 * Whether the hardware entropy source backing esp_random() is running.
 * False means every RNG draw on this device is pseudo-random only; callers
 * must refuse to produce key material rather than continue quietly.
 */
bool hw_entropy_source_enabled(void);

void hw_entropy_add_debiasing_failure(void);
uint32_t hw_entropy_get_debiasing_failures(void);

#endif
