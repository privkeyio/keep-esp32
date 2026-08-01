#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define NATIVE_TEST 1

#include "hw_entropy.h"
#include "random_utils.h"
#include "secresult.h"

#ifdef HAS_OPENSSL
#include <openssl/sha.h>
#endif

#define TEST(name) printf("  TEST: %s\n", name)
#define PASS()     printf("    PASS\n")
#define FAIL(msg)                      \
    do {                               \
        printf("    FAIL: %s\n", msg); \
        return 1;                      \
    } while (0)

static int test_hw_entropy_init(void) {
    TEST("hw_entropy_init");
    if (hw_entropy_initialized())
        FAIL("reported initialized before init");
    if (hw_entropy_source_verified())
        FAIL("entropy source reported verified before init");
    if (hw_entropy_init() != 0)
        FAIL("init failed");
    if (!hw_entropy_initialized())
        FAIL("not reported initialized after init");
    if (!hw_entropy_source_verified())
        FAIL("entropy source not reported verified after init");
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

static int test_rng_is_healthy_secure(void) {
    TEST("rng_is_healthy_secure");
    if (rng_init() != 0)
        FAIL("rng_init failed");
    secresult_t result = rng_is_healthy_secure();
    if (!SECRESULT_IS_TRUE(result))
        FAIL("should return SECRESULT_TRUE when healthy");
    PASS();
    return 0;
}

static int test_health_stats_counters(void) {
    TEST("health stats include entropy counters");
    rng_health_stats_t stats;
    rng_get_health(&stats);
    (void)stats.debiasing_failures;
    if (!stats.entropy_source_verified)
        FAIL("health stats report no entropy source after rng_init");
    PASS();
    return 0;
}

#ifdef HAS_OPENSSL
static int test_sha256_whitening_mock(void) {
    TEST("SHA-256 whitening with mock input");
    uint8_t biased_input[96];
    memset(biased_input, 0xAA, 32);
    memset(biased_input + 32, 0x55, 32);
    memset(biased_input + 64, 0xFF, 32);

    uint8_t hash1[32], hash2[32];
    SHA256(biased_input, sizeof(biased_input), hash1);

    biased_input[0] ^= 1;
    SHA256(biased_input, sizeof(biased_input), hash2);

    if (memcmp(hash1, hash2, 32) == 0)
        FAIL("SHA-256 did not differentiate inputs");

    int ones1 = 0, ones2 = 0;
    for (int i = 0; i < 32; i++) {
        ones1 += __builtin_popcount(hash1[i]);
        ones2 += __builtin_popcount(hash2[i]);
    }
    if (ones1 < 64 || ones1 > 192)
        FAIL("hash1 bit distribution too biased");
    if (ones2 < 64 || ones2 > 192)
        FAIL("hash2 bit distribution too biased");

    PASS();
    return 0;
}

static int test_sha256_whitening_deterministic(void) {
    TEST("SHA-256 whitening is deterministic");
    uint8_t input[96] = {0};
    for (int i = 0; i < 96; i++)
        input[i] = (uint8_t)i;

    uint8_t hash1[32], hash2[32];
    SHA256(input, sizeof(input), hash1);
    SHA256(input, sizeof(input), hash2);

    if (memcmp(hash1, hash2, 32) != 0)
        FAIL("same input produced different hashes");

    PASS();
    return 0;
}
#endif

int main(void) {
    printf("Running hw_entropy tests\n");
    int failed = 0;
    failed += test_hw_entropy_init();
    failed += test_hw_entropy_fill_basic();
    failed += test_hw_entropy_fill_different();
    failed += test_hw_entropy_edge_cases();
    failed += test_secure_random_fill();
    failed += test_rng_init();
    failed += test_rng_is_healthy_secure();
    failed += test_health_stats_counters();
#ifdef HAS_OPENSSL
    failed += test_sha256_whitening_mock();
    failed += test_sha256_whitening_deterministic();
#endif
    printf("\n%d test(s) failed\n", failed);
    return failed;
}
