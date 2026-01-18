// SPDX-FileCopyrightText: © 2026 Privkey Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef RANDOM_UTILS_H
#define RANDOM_UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <nostr.h>

typedef struct {
    uint32_t total_calls;
    uint32_t failed_checks;
    uint32_t retries;
    bool healthy;
} rng_health_stats_t;

static inline int secure_random_fill(uint8_t *buf, size_t len) {
    return nostr_random_bytes(buf, len) == 1 ? 0 : -1;
}

int rng_init(void);
int rng_fill_checked(uint8_t *buf, size_t len);
int rng_health_check(const uint8_t *buf, size_t len);
void rng_get_health(rng_health_stats_t *stats);
bool rng_is_healthy(void);

#endif
