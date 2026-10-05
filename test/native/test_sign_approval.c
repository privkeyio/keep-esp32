// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "sign_approval.h"

#define TEST(name) printf("  TEST: %s\n", name)
#define PASS()     printf("    PASS\n")
#define FAIL(msg)                      \
    do {                               \
        printf("    FAIL: %s\n", msg); \
        return 1;                      \
    } while (0)

static void msg_of(uint8_t out[32], uint8_t tag) {
    memset(out, tag, 32);
}

static int test_single_use(void) {
    TEST("an approval is consumed once");
    sign_approval_clear();
    uint8_t m[32];
    msg_of(m, 1);
    sign_approval_add(m, 1000);
    if (!sign_approval_consume(m, 1001))
        FAIL("first consume refused");
    if (sign_approval_consume(m, 1002))
        FAIL("second consume accepted");
    PASS();
    return 0;
}

static int test_other_message(void) {
    TEST("a different message is never approved");
    sign_approval_clear();
    uint8_t a[32], b[32];
    msg_of(a, 1);
    msg_of(b, 1);
    b[31] ^= 1;
    sign_approval_add(a, 0);
    if (sign_approval_consume(b, 1))
        FAIL("different message accepted");
    if (!sign_approval_consume(a, 1))
        FAIL("the approved one was lost");
    PASS();
    return 0;
}

static int test_expiry(void) {
    TEST("an approval expires after the TTL, including across timer wrap");
    sign_approval_clear();
    uint8_t m[32];
    msg_of(m, 2);
    sign_approval_add(m, 5000);
    if (sign_approval_consume(m, 5000 + SIGN_APPROVAL_TTL_MS))
        FAIL("accepted at the TTL");
    sign_approval_add(m, UINT32_MAX - 10);
    if (!sign_approval_consume(m, 20))
        FAIL("refused just after the timer wrapped");
    sign_approval_add(m, UINT32_MAX - 10);
    if (sign_approval_consume(m, SIGN_APPROVAL_TTL_MS))
        FAIL("accepted past the TTL across the wrap");
    PASS();
    return 0;
}

static int test_refresh_and_eviction(void) {
    TEST("re-adding refreshes, and a full table evicts the oldest");
    sign_approval_clear();
    uint8_t m[32];
    for (int i = 0; i < SIGN_APPROVAL_SLOTS; i++) {
        msg_of(m, (uint8_t)(10 + i));
        sign_approval_add(m, (uint32_t)(100 + i));
    }
    msg_of(m, 10);
    sign_approval_add(m, 200);
    msg_of(m, 99);
    sign_approval_add(m, 201);
    msg_of(m, 11);
    if (sign_approval_consume(m, 202))
        FAIL("the oldest entry was not the one evicted");
    msg_of(m, 10);
    if (!sign_approval_consume(m, 202))
        FAIL("the refreshed entry was evicted");
    msg_of(m, 99);
    if (!sign_approval_consume(m, 202))
        FAIL("the newest entry is missing");
    for (int i = 2; i < SIGN_APPROVAL_SLOTS; i++) {
        msg_of(m, (uint8_t)(10 + i));
        if (!sign_approval_consume(m, 202))
            FAIL("an unrelated entry was lost");
    }
    PASS();
    return 0;
}

static int test_clear(void) {
    TEST("clear drops every approval");
    uint8_t m[32];
    msg_of(m, 3);
    sign_approval_add(m, 0);
    sign_approval_clear();
    if (sign_approval_consume(m, 1))
        FAIL("approval survived clear");
    PASS();
    return 0;
}

int main(void) {
    printf("\n=== Sign Approval Tests ===\n\n");
    int failures = 0;
    failures += test_single_use();
    failures += test_other_message();
    failures += test_expiry();
    failures += test_refresh_and_eviction();
    failures += test_clear();
    printf("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED", failures);
    return failures ? 1 : 0;
}
