#ifndef RANDOM_UTILS_H
#define RANDOM_UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct {
    uint32_t total_calls;
    uint32_t failed_checks;
    uint32_t retries;
    bool healthy;
} rng_health_stats_t;

int rng_init(void);
int secure_random_fill(uint8_t *buf, size_t len);
int rng_fill_checked(uint8_t *buf, size_t len);
int rng_health_check(const uint8_t *buf, size_t len);
void rng_get_health(rng_health_stats_t *stats);

#endif
