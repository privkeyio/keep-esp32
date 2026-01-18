#include <stdio.h>
#include <stdint.h>
#include "secresult.h"

#define TEST(name) printf("  TEST: %s\n", name)
#define PASS() printf("    PASS\n")
#define FAIL(msg) do { printf("    FAIL: %s\n", msg); return 1; } while(0)

static int test_patterns_unique(void) {
    TEST("patterns are unique");

    secresult_t values[] = {
        SECRESULT_TRUE,
        SECRESULT_FALSE,
        SECRESULT_ERR_INVALID_SIG,
        SECRESULT_ERR_POLICY_DENIED,
        SECRESULT_ERR_SESSION_INVALID,
        SECRESULT_ERR_POLICY_CHANGED,
        SECRESULT_ERR_HASH_MISMATCH,
        SECRESULT_ERR_LOAD_FAILED
    };
    int count = sizeof(values) / sizeof(values[0]);

    for (int i = 0; i < count; i++) {
        for (int j = i + 1; j < count; j++) {
            if (values[i] == values[j]) FAIL("duplicate values found");
        }
    }

    PASS();
    return 0;
}

static int test_macros(void) {
    TEST("SECRESULT_IS_TRUE/FALSE/ERROR macros");

    if (!SECRESULT_IS_TRUE(SECRESULT_TRUE)) FAIL("IS_TRUE(TRUE) should be true");
    if (SECRESULT_IS_TRUE(SECRESULT_FALSE)) FAIL("IS_TRUE(FALSE) should be false");
    if (SECRESULT_IS_TRUE(SECRESULT_ERR_INVALID_SIG)) FAIL("IS_TRUE(error) should be false");

    if (!SECRESULT_IS_FALSE(SECRESULT_FALSE)) FAIL("IS_FALSE(FALSE) should be true");
    if (SECRESULT_IS_FALSE(SECRESULT_TRUE)) FAIL("IS_FALSE(TRUE) should be false");
    if (SECRESULT_IS_FALSE(SECRESULT_ERR_INVALID_SIG)) FAIL("IS_FALSE(error) should be false");

    if (SECRESULT_IS_ERROR(SECRESULT_TRUE)) FAIL("IS_ERROR(TRUE) should be false");
    if (SECRESULT_IS_ERROR(SECRESULT_FALSE)) FAIL("IS_ERROR(FALSE) should be false");
    if (!SECRESULT_IS_ERROR(SECRESULT_ERR_INVALID_SIG)) FAIL("IS_ERROR(ERR_INVALID_SIG) should be true");
    if (!SECRESULT_IS_ERROR(SECRESULT_ERR_POLICY_DENIED)) FAIL("IS_ERROR(ERR_POLICY_DENIED) should be true");
    if (!SECRESULT_IS_ERROR(SECRESULT_ERR_SESSION_INVALID)) FAIL("IS_ERROR(ERR_SESSION_INVALID) should be true");
    if (!SECRESULT_IS_ERROR(SECRESULT_ERR_POLICY_CHANGED)) FAIL("IS_ERROR(ERR_POLICY_CHANGED) should be true");
    if (!SECRESULT_IS_ERROR(SECRESULT_ERR_HASH_MISMATCH)) FAIL("IS_ERROR(ERR_HASH_MISMATCH) should be true");
    if (!SECRESULT_IS_ERROR(SECRESULT_ERR_LOAD_FAILED)) FAIL("IS_ERROR(ERR_LOAD_FAILED) should be true");

    PASS();
    return 0;
}

static int test_from_bool(void) {
    TEST("secresult_from_bool");

    if (secresult_from_bool(1) != SECRESULT_TRUE) FAIL("from_bool(1) should be TRUE");
    if (secresult_from_bool(0) != SECRESULT_FALSE) FAIL("from_bool(0) should be FALSE");
    if (secresult_from_bool(42) != SECRESULT_TRUE) FAIL("from_bool(42) should be TRUE");

    PASS();
    return 0;
}

static int test_error_patterns(void) {
    TEST("error codes use correct pattern");

    secresult_t errors[] = {
        SECRESULT_ERR_INVALID_SIG,
        SECRESULT_ERR_POLICY_DENIED,
        SECRESULT_ERR_SESSION_INVALID,
        SECRESULT_ERR_POLICY_CHANGED,
        SECRESULT_ERR_HASH_MISMATCH,
        SECRESULT_ERR_LOAD_FAILED
    };
    int count = sizeof(errors) / sizeof(errors[0]);

    for (int i = 0; i < count; i++) {
        uint32_t v = errors[i];
        uint8_t b0 = v & 0xFF;
        uint8_t b1 = (v >> 8) & 0xFF;
        uint8_t b2 = (v >> 16) & 0xFF;
        uint8_t b3 = (v >> 24) & 0xFF;
        if (b0 != b1 || b1 != b2 || b2 != b3) FAIL("error code bytes should be identical");
    }

    PASS();
    return 0;
}

static int test_true_false_patterns(void) {
    TEST("TRUE/FALSE use expected patterns");

    if (SECRESULT_TRUE != 0xAAAAAAAAu) FAIL("TRUE should be 0xAAAAAAAA");
    if (SECRESULT_FALSE != 0x55555555u) FAIL("FALSE should be 0x55555555");

    PASS();
    return 0;
}

static int test_hamming_distance(void) {
    TEST("all values have Hamming distance >= 4");

    secresult_t values[] = {
        SECRESULT_TRUE,
        SECRESULT_FALSE,
        SECRESULT_ERR_INVALID_SIG,
        SECRESULT_ERR_POLICY_DENIED,
        SECRESULT_ERR_SESSION_INVALID,
        SECRESULT_ERR_POLICY_CHANGED,
        SECRESULT_ERR_HASH_MISMATCH,
        SECRESULT_ERR_LOAD_FAILED
    };
    int count = sizeof(values) / sizeof(values[0]);

    for (int i = 0; i < count; i++) {
        for (int j = i + 1; j < count; j++) {
            uint32_t xor_diff = values[i] ^ values[j];
            int bits_different = 0;
            while (xor_diff) {
                bits_different += xor_diff & 1;
                xor_diff >>= 1;
            }
            if (bits_different < 4) FAIL("Hamming distance < 4 between values");
        }
    }

    PASS();
    return 0;
}

int main(void) {
    printf("\n=== Secure Result Type Tests ===\n\n");

    int failures = 0;
    failures += test_patterns_unique();
    failures += test_macros();
    failures += test_from_bool();
    failures += test_error_patterns();
    failures += test_true_false_patterns();
    failures += test_hamming_distance();

    printf("\n");
    if (failures == 0) {
        printf("=== All tests passed ===\n\n");
        return 0;
    } else {
        printf("=== %d test(s) failed ===\n\n", failures);
        return 1;
    }
}
