// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#ifndef RANDOM_UTILS_H
#define RANDOM_UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "hw_entropy.h"

typedef struct {
    uint32_t total_calls;
    uint32_t failed_checks;
    uint32_t retries;
    uint32_t debiasing_failures;
    bool healthy;
    /* False means the HWRNG has no entropy source and is pseudo-random only. */
    bool entropy_source_enabled;
} rng_health_stats_t;

static inline int secure_random_fill(uint8_t *buf, size_t len) {
    return hw_entropy_fill(buf, len);
}

int rng_init(void);
int rng_fill_checked(uint8_t *buf, size_t len);
int rng_health_check(const uint8_t *buf, size_t len);
void rng_get_health(rng_health_stats_t *stats);
bool rng_is_healthy(void);

#include "secresult.h"
secresult_t rng_is_healthy_secure(void);

#endif
