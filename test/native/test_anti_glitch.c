#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "anti_glitch.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name)                 \
    do {                           \
        printf("  %s... ", #name); \
        tests_run++;               \
        if (test_##name()) {       \
            printf("PASS\n");      \
            tests_passed++;        \
        } else {                   \
            printf("FAIL\n");      \
        }                          \
    } while (0)

static bool test_random_delay_us(void) {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    ag_random_delay_us(1000, 2000);
    clock_gettime(CLOCK_MONOTONIC, &end);

    long elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
    long elapsed_us = elapsed_ns / 1000;

    return elapsed_us >= 1000;
}

static bool test_random_delay_ms(void) {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    ag_random_delay_ms(10, 20);
    clock_gettime(CLOCK_MONOTONIC, &end);

    long elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
    long elapsed_ms = elapsed_ns / 1000000;

    return elapsed_ms >= 10;
}

static bool test_verify_condition_secure_true(void) {
    secresult_t result = ag_verify_condition_secure(SECRESULT_TRUE);
    return SECRESULT_IS_TRUE(result);
}

static bool test_verify_condition_secure_false(void) {
    secresult_t result = ag_verify_condition_secure(SECRESULT_FALSE);
    return SECRESULT_IS_FALSE(result);
}

static bool test_verify_condition_secure_error(void) {
    secresult_t result = ag_verify_condition_secure(SECRESULT_ERR_POLICY_DENIED);
    return result == SECRESULT_ERR_POLICY_DENIED;
}

static bool test_verify_condition_secure_rejects_zero(void) {
    secresult_t result = ag_verify_condition_secure(0);
    return SECRESULT_IS_FALSE(result);
}

static bool test_verify_condition_secure_rejects_max(void) {
    secresult_t result = ag_verify_condition_secure(UINT32_MAX);
    return SECRESULT_IS_FALSE(result);
}

static bool test_init(void) {
    int ret = ag_init();
    return ret == 0;
}

static bool test_boot_counter(void) {
    uint32_t counter = 0;
    int ret = ag_get_boot_counter(&counter);
    return ret == 0;
}

static bool test_cycle_count(void) {
    uint32_t start = ag_get_cycle_count();
    ag_random_delay_us(100, 200);
    uint32_t end = ag_get_cycle_count();
    return end != start;
}

static bool test_check_min_cycles(void) {
    uint32_t start = ag_get_cycle_count();
    ag_random_delay_us(1000, 2000);
    bool result = ag_check_min_cycles(start, 100);
    return result;
}

int main(void) {
    printf("Anti-Glitch Tests\n");
    printf("=================\n");

    TEST(init);
    TEST(random_delay_us);
    TEST(random_delay_ms);
    TEST(verify_condition_secure_true);
    TEST(verify_condition_secure_false);
    TEST(verify_condition_secure_error);
    TEST(verify_condition_secure_rejects_zero);
    TEST(verify_condition_secure_rejects_max);
    TEST(boot_counter);
    TEST(cycle_count);
    TEST(check_min_cycles);

    printf("\nResults: %d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
