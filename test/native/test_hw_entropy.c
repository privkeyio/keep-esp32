#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define NATIVE_TEST 1

#include "hw_entropy.h"
#include "random_utils.h"

#define TEST(name) printf("  TEST: %s\n", name)
#define PASS()     printf("    PASS\n")
#define FAIL(msg)                      \
    do {                               \
        printf("    FAIL: %s\n", msg); \
        return 1;                      \
    } while (0)

static int test_hw_entropy_init(void) {
    TEST("hw_entropy_init");
    if (hw_entropy_init() != 0)
        FAIL("init failed");
    PASS();
    return 0;
}

static int test_hw_entropy_fill_basic(void) {
    TEST("hw_entropy_fill basic");
    uint8_t buf[32];
    memset(buf, 0, sizeof(buf));
    if (hw_entropy_fill(buf, sizeof(buf)) != 0)
        FAIL("fill failed");
    uint8_t zero_buf[32] = {0};
    if (memcmp(buf, zero_buf, sizeof(buf)) == 0)
        FAIL("output all zeros");
    PASS();
    return 0;
}

static int test_hw_entropy_fill_different(void) {
    TEST("hw_entropy_fill produces different output");
    uint8_t buf1[32], buf2[32];
    if (hw_entropy_fill(buf1, sizeof(buf1)) != 0)
        FAIL("fill 1 failed");
    if (hw_entropy_fill(buf2, sizeof(buf2)) != 0)
        FAIL("fill 2 failed");
    if (memcmp(buf1, buf2, sizeof(buf1)) == 0)
        FAIL("outputs identical");
    PASS();
    return 0;
}

static int test_hw_entropy_edge_cases(void) {
    TEST("hw_entropy_fill edge cases");
    if (hw_entropy_fill(NULL, 32) != -1)
        FAIL("NULL accepted");
    uint8_t buf[1];
    if (hw_entropy_fill(buf, 0) != -1)
        FAIL("zero len accepted");
    PASS();
    return 0;
}

static int test_secure_random_fill(void) {
    TEST("secure_random_fill integration");
    uint8_t buf[64];
    if (secure_random_fill(buf, sizeof(buf)) != 0)
        FAIL("secure_random_fill failed");
    if (rng_health_check(buf, sizeof(buf)) != 0)
        FAIL("health check failed");
    PASS();
    return 0;
}

static int test_rng_init(void) {
    TEST("rng_init");
    if (rng_init() != 0)
        FAIL("rng_init failed");
    if (!rng_is_healthy())
        FAIL("not healthy after init");
    PASS();
    return 0;
}

int main(void) {
    printf("Running hw_entropy tests\n");
    int failed = 0;
    failed += test_hw_entropy_init();
    failed += test_hw_entropy_fill_basic();
    failed += test_hw_entropy_fill_different();
    failed += test_hw_entropy_edge_cases();
    failed += test_secure_random_fill();
    failed += test_rng_init();
    printf("\n%d test(s) failed\n", failed);
    return failed;
}
