#ifndef RANDOM_UTILS_H
#define RANDOM_UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

typedef struct {
    uint32_t total_calls;
    uint32_t failed_checks;
    uint32_t retries;
    bool healthy;
} rng_health_stats_t;

#ifndef RANDOM_UTILS_CUSTOM_IMPL
static inline int rng_fill_checked(uint8_t *buf, size_t len) {
    memset(buf, 0x77, len);
    return 0;
}

static inline bool rng_is_healthy(void) {
    return true;
}

static inline int rng_init(void) {
    return 0;
}

static inline void rng_get_health(rng_health_stats_t *stats) {
    if (stats) {
        stats->total_calls = 0;
        stats->failed_checks = 0;
        stats->retries = 0;
        stats->healthy = true;
    }
}
#endif

#endif
