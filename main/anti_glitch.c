#include "anti_glitch.h"
#include "secure_element.h"
#include <string.h>

#ifdef ESP_PLATFORM
#include "esp_random.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_timer.h"

static const char *TAG = "anti_glitch";

static uint32_t get_random_range(uint32_t min, uint32_t max) {
    if (min >= max)
        return min;
    uint32_t range = max - min;
    uint32_t limit = UINT32_MAX - (UINT32_MAX % range);
    uint32_t r;
    do {
        r = esp_random();
    } while (r >= limit);
    return min + (r % range);
}

void ag_random_delay_us(uint32_t min_us, uint32_t max_us) {
    uint32_t delay = get_random_range(min_us, max_us);
    esp_rom_delay_us(delay);
}

void ag_random_delay_ms(uint32_t min_ms, uint32_t max_ms) {
    uint32_t delay = get_random_range(min_ms, max_ms);
    vTaskDelay(pdMS_TO_TICKS(delay));
}

uint32_t ag_get_cycle_count(void) {
    uint32_t cycles;
    __asm__ __volatile__("rsr %0, ccount" : "=r"(cycles));
    return cycles;
}

#else
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

static uint32_t native_random(void) {
    uint32_t r;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, &r, sizeof(r));
        close(fd);
        if (n == sizeof(r))
            return r;
    }
    return (uint32_t)rand();
}

static uint32_t get_random_range(uint32_t min, uint32_t max) {
    if (min >= max)
        return min;
    uint32_t range = max - min;
    uint32_t limit = UINT32_MAX - (UINT32_MAX % range);
    uint32_t r;
    do {
        r = native_random();
    } while (r >= limit);
    return min + (r % range);
}

void ag_random_delay_us(uint32_t min_us, uint32_t max_us) {
    uint32_t delay = get_random_range(min_us, max_us);
    usleep(delay);
}

void ag_random_delay_ms(uint32_t min_ms, uint32_t max_ms) {
    uint32_t delay = get_random_range(min_ms, max_ms);
    usleep(delay * 1000);
}

uint32_t ag_get_cycle_count(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t microsecs = (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000;
    return (uint32_t)microsecs;
}

#endif

static bool g_initialized = false;
static uint32_t g_boot_counter = 0;

int ag_init(void) {
    if (g_initialized)
        return 0;

    ag_random_delay_ms(AG_BOOT_DELAY_MIN_MS, AG_BOOT_DELAY_MAX_MS);

    se_status_t se_ret = se_init();
    if (se_ret == SE_OK) {
        uint32_t counter = 0;
        if (se_increment_counter(&counter) == SE_OK) {
            g_boot_counter = counter;
#ifdef ESP_PLATFORM
            ESP_LOGI(TAG, "Boot counter: %lu", (unsigned long)g_boot_counter);
#endif
        } else {
#ifdef ESP_PLATFORM
            ESP_LOGW(TAG, "Secure element counter increment failed");
#endif
        }
    } else {
#ifdef ESP_PLATFORM
        ESP_LOGW(TAG, "Secure element init failed, monotonic counter unavailable");
#endif
    }

    g_initialized = true;
    ag_random_delay_ms(AG_BOOT_DELAY_MIN_MS, AG_BOOT_DELAY_MAX_MS);
    return 0;
}

int ag_increment_boot_counter(void) {
    uint32_t new_value;
    se_status_t ret = se_increment_counter(&new_value);
    if (ret != SE_OK)
        return -1;
    g_boot_counter = new_value;
    return 0;
}

int ag_get_boot_counter(uint32_t *value) {
    if (!value)
        return -1;

    uint32_t se_value;
    se_status_t ret = se_get_counter(&se_value);
    if (ret == SE_OK) {
        *value = se_value;
        return 0;
    }

    *value = g_boot_counter;
    return 0;
}

bool ag_check_min_cycles(uint32_t start, uint32_t min_cycles) {
    uint32_t current = ag_get_cycle_count();
    uint32_t elapsed = (current >= start) ? (current - start) : (UINT32_MAX - start + current + 1);
    return elapsed >= min_cycles;
}

secresult_t ag_verify_condition_secure(secresult_t condition) {
    volatile secresult_t r1 = condition;
    ag_random_delay_us(AG_DELAY_MIN_US / 10, AG_DELAY_MAX_US / 10);
    volatile secresult_t r2 = condition;
    ag_random_delay_us(AG_DELAY_MIN_US / 20, AG_DELAY_MAX_US / 20);
    volatile secresult_t r3 = condition;

    if (r1 != r2 || r2 != r3)
        return SECRESULT_FALSE;

    if (r1 == 0 || r1 == UINT32_MAX)
        return SECRESULT_FALSE;

    return r1;
}
