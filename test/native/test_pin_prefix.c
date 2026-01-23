// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "crypto_asm.h"
#include "pin_prefix.h"
#include "pin_prefix.c"

#define TEST(name) printf("  TEST: %s\n", name)
#define PASS()     printf("    PASS\n")
#define FAIL(msg)                      \
    do {                               \
        printf("    FAIL: %s\n", msg); \
        return 1;                      \
    } while (0)

static const uint8_t TEST_SECRET[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                                        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                                        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

static int test_derive_words_basic(void) {
    TEST("derive words basic");

    pin_prefix_t prefix = {.digits = {1, 2, 3, 4}, .len = 4};
    uint16_t word1, word2;

    if (pin_prefix_derive_words(&prefix, TEST_SECRET, sizeof(TEST_SECRET), &word1, &word2) != 0)
        FAIL("derive failed");

    if (word1 >= BIP39_WORD_COUNT)
        FAIL("word1 index out of range");
    if (word2 >= BIP39_WORD_COUNT)
        FAIL("word2 index out of range");

    PASS();
    return 0;
}

static int test_derive_words_deterministic(void) {
    TEST("derive words deterministic");

    pin_prefix_t prefix = {.digits = {1, 2, 3, 4}, .len = 4};
    uint16_t word1_a, word2_a, word1_b, word2_b;

    if (pin_prefix_derive_words(&prefix, TEST_SECRET, sizeof(TEST_SECRET), &word1_a, &word2_a) != 0)
        FAIL("first derive failed");
    if (pin_prefix_derive_words(&prefix, TEST_SECRET, sizeof(TEST_SECRET), &word1_b, &word2_b) != 0)
        FAIL("second derive failed");

    if (word1_a != word1_b)
        FAIL("word1 not deterministic");
    if (word2_a != word2_b)
        FAIL("word2 not deterministic");

    PASS();
    return 0;
}

static int test_different_prefix_different_words(void) {
    TEST("different prefix different words");

    pin_prefix_t prefix1 = {.digits = {1, 2, 3, 4}, .len = 4};
    pin_prefix_t prefix2 = {.digits = {5, 6, 7, 8}, .len = 4};
    uint16_t word1_a, word2_a, word1_b, word2_b;

    if (pin_prefix_derive_words(&prefix1, TEST_SECRET, sizeof(TEST_SECRET), &word1_a, &word2_a) != 0)
        FAIL("first derive failed");
    if (pin_prefix_derive_words(&prefix2, TEST_SECRET, sizeof(TEST_SECRET), &word1_b, &word2_b) != 0)
        FAIL("second derive failed");

    if (word1_a == word1_b && word2_a == word2_b)
        FAIL("different prefixes should produce different words");

    PASS();
    return 0;
}

static int test_different_secret_different_words(void) {
    TEST("different secret different words");

    pin_prefix_t prefix = {.digits = {1, 2, 3, 4}, .len = 4};
    uint8_t secret2[32];
    memcpy(secret2, TEST_SECRET, sizeof(secret2));
    secret2[0] ^= 0xFF;

    uint16_t word1_a, word2_a, word1_b, word2_b;

    if (pin_prefix_derive_words(&prefix, TEST_SECRET, sizeof(TEST_SECRET), &word1_a, &word2_a) != 0)
        FAIL("first derive failed");
    if (pin_prefix_derive_words(&prefix, secret2, sizeof(secret2), &word1_b, &word2_b) != 0)
        FAIL("second derive failed");

    if (word1_a == word1_b && word2_a == word2_b)
        FAIL("different secrets should produce different words");

    PASS();
    return 0;
}

static int test_min_prefix_len(void) {
    TEST("minimum prefix length");

    pin_prefix_t prefix = {.digits = {1, 2}, .len = 2};
    uint16_t word1, word2;

    if (pin_prefix_derive_words(&prefix, TEST_SECRET, sizeof(TEST_SECRET), &word1, &word2) != 0)
        FAIL("derive with 2 digits should work");

    PASS();
    return 0;
}

static int test_prefix_too_short(void) {
    TEST("prefix too short");

    pin_prefix_t prefix = {.digits = {1}, .len = 1};
    uint16_t word1, word2;

    if (pin_prefix_derive_words(&prefix, TEST_SECRET, sizeof(TEST_SECRET), &word1, &word2) == 0)
        FAIL("should fail with 1 digit");

    PASS();
    return 0;
}

static int test_prefix_too_long(void) {
    TEST("prefix too long");

    pin_prefix_t prefix = {.digits = {1, 2, 3, 4}, .len = 5};
    uint16_t word1, word2;

    if (pin_prefix_derive_words(&prefix, TEST_SECRET, sizeof(TEST_SECRET), &word1, &word2) == 0)
        FAIL("should fail with 5 digits");

    PASS();
    return 0;
}

static int test_null_params(void) {
    TEST("null parameters");

    pin_prefix_t prefix = {.digits = {1, 2, 3, 4}, .len = 4};
    uint16_t word1, word2;

    if (pin_prefix_derive_words(NULL, TEST_SECRET, sizeof(TEST_SECRET), &word1, &word2) == 0)
        FAIL("should fail with null prefix");
    if (pin_prefix_derive_words(&prefix, NULL, sizeof(TEST_SECRET), &word1, &word2) == 0)
        FAIL("should fail with null secret");
    if (pin_prefix_derive_words(&prefix, TEST_SECRET, sizeof(TEST_SECRET), NULL, &word2) == 0)
        FAIL("should fail with null word1");
    if (pin_prefix_derive_words(&prefix, TEST_SECRET, sizeof(TEST_SECRET), &word1, NULL) == 0)
        FAIL("should fail with null word2");

    PASS();
    return 0;
}

static int test_zero_secret_len(void) {
    TEST("zero secret length");

    pin_prefix_t prefix = {.digits = {1, 2, 3, 4}, .len = 4};
    uint16_t word1, word2;

    if (pin_prefix_derive_words(&prefix, TEST_SECRET, 0, &word1, &word2) == 0)
        FAIL("should fail with zero secret length");

    PASS();
    return 0;
}

static int test_bip39_get_word(void) {
    TEST("bip39_get_word");

    const char *first = bip39_get_word(0);
    const char *last = bip39_get_word(2047);

    if (!first)
        FAIL("first word is null");
    if (!last)
        FAIL("last word is null");
    if (strcmp(first, "abandon") != 0)
        FAIL("first word should be 'abandon'");
    if (strcmp(last, "zoo") != 0)
        FAIL("last word should be 'zoo'");
    if (bip39_get_word(2048) != NULL)
        FAIL("out of range should return null");

    PASS();
    return 0;
}

static int test_get_words(void) {
    TEST("get_words convenience function");

    pin_prefix_t prefix = {.digits = {1, 2, 3, 4}, .len = 4};
    char word1[16], word2[16];

    if (pin_prefix_get_words(&prefix, TEST_SECRET, sizeof(TEST_SECRET), word1, sizeof(word1), word2,
                             sizeof(word2)) != 0)
        FAIL("get_words failed");

    if (strlen(word1) == 0)
        FAIL("word1 is empty");
    if (strlen(word2) == 0)
        FAIL("word2 is empty");

    PASS();
    return 0;
}

static int test_get_words_buffer_too_small(void) {
    TEST("get_words buffer too small");

    pin_prefix_t prefix = {.digits = {1, 2, 3, 4}, .len = 4};
    char word1[2], word2[16];

    if (pin_prefix_get_words(&prefix, TEST_SECRET, sizeof(TEST_SECRET), word1, sizeof(word1), word2,
                             sizeof(word2)) == 0)
        FAIL("should fail with small buffer");

    PASS();
    return 0;
}

static int test_set_digit(void) {
    TEST("set_digit");

    pin_prefix_t prefix;
    pin_prefix_clear(&prefix);

    if (pin_prefix_set_digit(&prefix, 1) != 0)
        FAIL("set first digit failed");
    if (pin_prefix_set_digit(&prefix, 2) != 0)
        FAIL("set second digit failed");
    if (prefix.len != 2)
        FAIL("length should be 2");
    if (prefix.digits[0] != 1 || prefix.digits[1] != 2)
        FAIL("digits mismatch");

    PASS();
    return 0;
}

static int test_set_digit_overflow(void) {
    TEST("set_digit overflow");

    pin_prefix_t prefix = {.digits = {1, 2, 3, 4}, .len = 4};

    if (pin_prefix_set_digit(&prefix, 5) == 0)
        FAIL("should fail when full");

    PASS();
    return 0;
}

static int test_set_digit_invalid(void) {
    TEST("set_digit invalid digit");

    pin_prefix_t prefix;
    pin_prefix_clear(&prefix);

    if (pin_prefix_set_digit(&prefix, 10) == 0)
        FAIL("should reject digit > 9");

    PASS();
    return 0;
}

static int test_is_ready(void) {
    TEST("is_ready");

    pin_prefix_t prefix;
    pin_prefix_clear(&prefix);

    if (pin_prefix_is_ready(&prefix))
        FAIL("should not be ready with 0 digits");

    pin_prefix_set_digit(&prefix, 1);
    if (pin_prefix_is_ready(&prefix))
        FAIL("should not be ready with 1 digit");

    pin_prefix_set_digit(&prefix, 2);
    if (!pin_prefix_is_ready(&prefix))
        FAIL("should be ready with 2 digits");

    PASS();
    return 0;
}

static int test_clear(void) {
    TEST("clear");

    pin_prefix_t prefix = {.digits = {1, 2, 3, 4}, .len = 4};
    pin_prefix_clear(&prefix);

    if (prefix.len != 0)
        FAIL("length should be 0");
    for (int i = 0; i < PIN_PREFIX_MAX_LEN; i++) {
        if (prefix.digits[i] != 0)
            FAIL("digits should be zeroed");
    }

    PASS();
    return 0;
}

static int test_word_index_distribution(void) {
    TEST("word index distribution");

    int seen_different = 0;
    uint16_t prev_word1 = 0, prev_word2 = 0;

    for (int i = 0; i < 10; i++) {
        pin_prefix_t prefix = {.digits = {(uint8_t)i, (uint8_t)((i + 1) % 10)}, .len = 2};
        uint16_t word1, word2;

        if (pin_prefix_derive_words(&prefix, TEST_SECRET, sizeof(TEST_SECRET), &word1, &word2) != 0)
            FAIL("derive failed");

        if (i > 0 && (word1 != prev_word1 || word2 != prev_word2)) {
            seen_different = 1;
        }
        prev_word1 = word1;
        prev_word2 = word2;
    }

    if (!seen_different)
        FAIL("all prefixes produced same words");

    PASS();
    return 0;
}

int main(void) {
    printf("\n=== PIN Prefix Anti-Phishing Tests ===\n\n");

    int failures = 0;
    failures += test_derive_words_basic();
    failures += test_derive_words_deterministic();
    failures += test_different_prefix_different_words();
    failures += test_different_secret_different_words();
    failures += test_min_prefix_len();
    failures += test_prefix_too_short();
    failures += test_prefix_too_long();
    failures += test_null_params();
    failures += test_zero_secret_len();
    failures += test_bip39_get_word();
    failures += test_get_words();
    failures += test_get_words_buffer_too_small();
    failures += test_set_digit();
    failures += test_set_digit_overflow();
    failures += test_set_digit_invalid();
    failures += test_is_ready();
    failures += test_clear();
    failures += test_word_index_distribution();

    printf("\n");
    if (failures == 0) {
        printf("=== All tests passed ===\n\n");
        return 0;
    } else {
        printf("=== %d test(s) failed ===\n\n", failures);
        return 1;
    }
}
