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
 * Whether hw_entropy_init() has run. Gates hw_entropy_fill(): drawing before
 * init means drawing with the entropy source still off.
 */
bool hw_entropy_initialized(void);

/*
 * Whether the peripheral state that carries entropy into the hardware RNG is
 * actually switched on, read back from the SAR ADC and RNG clock registers
 * rather than inferred from having called the enable function. False means
 * every draw on this device is pseudo-random only.
 *
 * A state check, not a noise measurement: it says the path is open, not that
 * the ADC is producing entropy.
 */
bool hw_entropy_source_verified(void);

void hw_entropy_add_debiasing_failure(void);
uint32_t hw_entropy_get_debiasing_failures(void);

#endif
