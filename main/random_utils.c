// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "random_utils.h"
#include <string.h>

#define RNG_SELF_TEST_SIZE        64
#define RNG_DEGRADATION_THRESHOLD 5

static rng_health_stats_t g_rng_stats = {0};

#ifdef ESP_PLATFORM
#include "esp_log.h"
static const char *TAG = "rng";
#define RNG_LOG_ERROR(fmt, ...) ESP_LOGE(TAG, fmt, ##__VA_ARGS__)
#define RNG_LOG_WARN(fmt, ...)  ESP_LOGW(TAG, fmt, ##__VA_ARGS__)
#define RNG_LOG_INFO(fmt, ...)  ESP_LOGI(TAG, fmt, ##__VA_ARGS__)
#else
#define RNG_LOG_ERROR(fmt, ...) ((void)0)
#define RNG_LOG_WARN(fmt, ...)  ((void)0)
#define RNG_LOG_INFO(fmt, ...)  ((void)0)
#endif

int rng_health_check(const uint8_t *buf, size_t len) {
    if (len < 8)
        return 0;

    uint32_t zeros = 0, ones = 0;
    uint32_t bit_count = 0;
    uint32_t transitions = 0;
    uint8_t prev_bit = buf[0] & 1;

    for (size_t i = 0; i < len; i++) {
        uint8_t b = buf[i];
        if (b == 0x00)
            zeros++;
        if (b == 0xFF)
            ones++;
        bit_count += __builtin_popcount(b);

        int start_bit = (i == 0) ? 1 : 0;
        for (int j = start_bit; j < 8; j++) {
            uint8_t curr_bit = (b >> j) & 1;
            transitions += curr_bit ^ prev_bit;
            prev_bit = curr_bit;
        }
    }

    if (zeros > len / 2 || ones > len / 2) {
        return -1;
    }

    uint32_t total_bits = len * 8;
    uint32_t expected_bits = total_bits / 2;
    uint32_t bit_tolerance = expected_bits / 4;
    if (bit_count < expected_bits - bit_tolerance || bit_count > expected_bits + bit_tolerance) {
        return -2;
    }

    uint32_t expected_trans = (total_bits - 1) / 2;
    uint32_t trans_tolerance = expected_trans / 4;
    if (transitions < expected_trans - trans_tolerance ||
        transitions > expected_trans + trans_tolerance) {
        return -3;
    }

    return 0;
}

int rng_fill_checked(uint8_t *buf, size_t len) {
    g_rng_stats.total_calls++;

    for (int attempt = 0; attempt < 2; attempt++) {
        if (secure_random_fill(buf, len) != 0) {
            g_rng_stats.failed_checks++;
            return -1;
        }
        if (rng_health_check(buf, len) == 0) {
            return 0;
        }
        if (attempt == 0) {
            g_rng_stats.retries++;
        }
    }

    g_rng_stats.failed_checks++;
    if (g_rng_stats.failed_checks >= RNG_DEGRADATION_THRESHOLD && g_rng_stats.healthy) {
        RNG_LOG_WARN("RNG health degraded: %lu failures", (unsigned long)g_rng_stats.failed_checks);
        g_rng_stats.healthy = false;
    }

    return -1;
}

int rng_init(void) {
    if (hw_entropy_init() != 0) {
        RNG_LOG_ERROR("Hardware entropy init failed");
        return -1;
    }

    uint8_t test_buf[RNG_SELF_TEST_SIZE];
    int pass_count = 0;

    for (int i = 0; i < 3; i++) {
        if (secure_random_fill(test_buf, sizeof(test_buf)) == 0 &&
            rng_health_check(test_buf, sizeof(test_buf)) == 0)
            pass_count++;
    }

    memset(test_buf, 0, sizeof(test_buf));

    if (pass_count < 2) {
        RNG_LOG_ERROR("RNG self-test failed: %d/3 passed", pass_count);
        return -1;
    }

    g_rng_stats = (rng_health_stats_t){.healthy = true};

    RNG_LOG_INFO("RNG self-test passed");
    return 0;
}

void rng_get_health(rng_health_stats_t *stats) {
    if (stats) {
        *stats = g_rng_stats;
    }
}

bool rng_is_healthy(void) {
    return g_rng_stats.healthy;
}
