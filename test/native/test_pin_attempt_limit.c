// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#define SECURE_ELEMENT_H
#define MOCK_SECURE_ELEMENT_H
#define SE_SLOT_COUNT  16
#define SE_SLOT_SIZE   72
#define SE_SERIAL_SIZE 9

typedef enum {
    SE_OK = 0,
    SE_ERR_INVALID_PARAM = -1,
    SE_ERR_NOT_PROVISIONED = -2,
    SE_ERR_COMM_FAIL = -3,
    SE_ERR_LOCKED = -4,
    SE_ERR_NOT_INITIALIZED = -5
} se_status_t;

static uint8_t mock_se_slots[SE_SLOT_COUNT][SE_SLOT_SIZE];
static bool mock_se_available = false;

se_status_t se_init(void) {
    if (mock_se_available) {
        return SE_OK;
    }
    return SE_ERR_NOT_PROVISIONED;
}

bool se_is_provisioned(void) {
    return mock_se_available;
}

se_status_t se_read_slot(uint8_t slot, uint8_t *data, size_t len) {
    if (!mock_se_available) {
        return SE_ERR_NOT_PROVISIONED;
    }
    if (slot >= SE_SLOT_COUNT || !data || len > SE_SLOT_SIZE) {
        return SE_ERR_INVALID_PARAM;
    }
    memcpy(data, mock_se_slots[slot], len);
    return SE_OK;
}

se_status_t se_write_slot(uint8_t slot, const uint8_t *data, size_t len) {
    if (!mock_se_available) {
        return SE_ERR_NOT_PROVISIONED;
    }
    if (slot >= SE_SLOT_COUNT || !data || len > SE_SLOT_SIZE) {
        return SE_ERR_INVALID_PARAM;
    }
    memcpy(mock_se_slots[slot], data, len);
    return SE_OK;
}

se_status_t se_increment_counter(uint32_t *new_value) {
    (void)new_value;
    return SE_ERR_NOT_PROVISIONED;
}

se_status_t se_get_counter(uint32_t *value) {
    (void)value;
    return SE_ERR_NOT_PROVISIONED;
}

se_status_t se_get_serial(uint8_t serial[SE_SERIAL_SIZE]) {
    (void)serial;
    return SE_ERR_NOT_PROVISIONED;
}

#define UNIT_TEST 1

#define STORAGE_CRYPTO_H
#define STORAGE_CRYPTO_KEY_SIZE    32
#define STORAGE_CRYPTO_NONCE_SIZE  12
#define STORAGE_CRYPTO_TAG_SIZE    16
#define STORAGE_CRYPTO_MAX_PIN_LEN 64

#include "crypto_asm.h"
#include "random_utils.h"
#include "error_codes.h"

#include "storage_crypto.c"

#define TEST(name) printf("  TEST: %s\n", name)
#define PASS()     printf("    PASS\n")
#define FAIL(msg)                      \
    do {                               \
        printf("    FAIL: %s\n", msg); \
        return 1;                      \
    } while (0)

static void reset_test_state(void) {
    storage_crypto_reset_rate_limit();
    memset(mock_se_slots, 0, sizeof(mock_se_slots));
    mock_se_available = false;
}

static int test_initial_state(void) {
    TEST("initial state allows PIN attempts");
    reset_test_state();

    if (storage_crypto_check_rate_limit() != 0)
        FAIL("initial state should allow attempts");
    if (storage_crypto_get_attempts() != 0)
        FAIL("initial attempts should be 0");
    if (storage_crypto_is_bricked())
        FAIL("should not be bricked initially");

    PASS();
    return 0;
}

static int test_delay_schedule(void) {
    TEST("exponential delay schedule");
    reset_test_state();

    if (get_delay_ms(0) != 0)
        FAIL("0 attempts should have no delay");
    if (get_delay_ms(3) != 0)
        FAIL("3 attempts should have no delay");
    if (get_delay_ms(4) != 15000)
        FAIL("4 attempts should have 15s delay");
    if (get_delay_ms(6) != 15000)
        FAIL("6 attempts should have 15s delay");
    if (get_delay_ms(7) != 60000)
        FAIL("7 attempts should have 1min delay");
    if (get_delay_ms(9) != 60000)
        FAIL("9 attempts should have 1min delay");
    if (get_delay_ms(10) != 900000)
        FAIL("10 attempts should have 15min delay");
    if (get_delay_ms(12) != 900000)
        FAIL("12 attempts should have 15min delay");
    if (get_delay_ms(13) != 900000)
        FAIL("13 attempts should have 15min delay");
    if (get_delay_ms(20) != 900000)
        FAIL("20 attempts should have 15min delay");
    if (get_delay_ms(21) != UINT32_MAX)
        FAIL("21 attempts should return max delay (bricked)");

    PASS();
    return 0;
}

static int test_attempt_tracking(void) {
    TEST("failed attempt tracking");
    reset_test_state();

    storage_crypto_record_attempt(false);
    if (storage_crypto_get_attempts() != 1)
        FAIL("should have 1 attempt");

    storage_crypto_record_attempt(false);
    storage_crypto_record_attempt(false);
    if (storage_crypto_get_attempts() != 3)
        FAIL("should have 3 attempts");

    PASS();
    return 0;
}

static int test_success_resets_counter(void) {
    TEST("successful attempt resets counter");
    reset_test_state();

    for (int i = 0; i < 5; i++) {
        storage_crypto_record_attempt(false);
    }
    if (storage_crypto_get_attempts() != 5)
        FAIL("should have 5 attempts");

    storage_crypto_record_attempt(true);
    if (storage_crypto_get_attempts() != 0)
        FAIL("success should reset counter to 0");

    PASS();
    return 0;
}

static int test_bricking_after_max_attempts(void) {
    TEST("device bricks after max attempts");
    reset_test_state();

    for (int i = 0; i < 20; i++) {
        storage_crypto_record_attempt(false);
    }
    if (storage_crypto_is_bricked())
        FAIL("should not be bricked at 20 attempts");

    storage_crypto_record_attempt(false);
    if (!storage_crypto_is_bricked())
        FAIL("should be bricked at 21 attempts");

    PASS();
    return 0;
}

static int test_bricked_device_rejects_attempts(void) {
    TEST("bricked device rejects all PIN attempts");
    reset_test_state();

    storage_crypto_set_bricked_for_test(true);

    if (storage_crypto_check_rate_limit() != ERR_PIN_BRICKED)
        FAIL("bricked device should return ERR_PIN_BRICKED");
    if (storage_crypto_init("1234") != ERR_PIN_BRICKED)
        FAIL("bricked device should reject PIN init");

    PASS();
    return 0;
}

static int test_max_attempts_getter(void) {
    TEST("max attempts getter returns correct value");
    reset_test_state();

    if (storage_crypto_get_max_attempts() != 21)
        FAIL("max attempts should be 21");

    PASS();
    return 0;
}

static int test_delay_remaining(void) {
    TEST("delay remaining calculation");
    reset_test_state();

    storage_crypto_set_attempts_for_test(5);

    uint32_t delay = storage_crypto_get_delay_remaining();
    if (delay == 0)
        FAIL("should have delay remaining after 5 failed attempts");
    if (delay > 15000)
        FAIL("delay should not exceed 15s for 5 attempts");

    PASS();
    return 0;
}

static int test_se_persistence(void) {
    TEST("SE-based state persistence");
    reset_test_state();
    mock_se_available = true;
    pin_state_loaded = false;

    storage_crypto_record_attempt(false);
    storage_crypto_record_attempt(false);

    if (memcmp(mock_se_slots[0], "PIN", 3) != 0)
        FAIL("SE slot should contain PIN magic");

    PASS();
    return 0;
}

#ifndef MOCK_MBEDTLS
static int test_pbkdf2_key_derivation(void) {
    TEST("PBKDF2 key derivation completes");
    reset_test_state();
    salt_initialized = false;

    uint8_t device_id[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    uint8_t key[32];

    int ret = derive_key(device_id, sizeof(device_id), (const uint8_t *)"testpin", 7, key);
    if (ret != 0)
        FAIL("PBKDF2 key derivation should succeed");

    PASS();
    return 0;
}

static int test_hmac_tamper_detection(void) {
    TEST("HMAC detects state tampering");
    reset_test_state();

    pin_state_t state1, state2;
    memcpy(state1.magic, "PIN\0", 4);
    state1.failed_attempts = 5;
    state1.lockout_deadline = 12345;
    state1.bricked = 0;
    memset(state1.reserved, 0, sizeof(state1.reserved));

    memcpy(&state2, &state1, sizeof(state1));
    state2.failed_attempts = 0;

    uint8_t hmac1[32], hmac2[32];

    if (compute_state_hmac(&state1, hmac1) != 0)
        FAIL("compute_state_hmac should succeed for state1");
    if (compute_state_hmac(&state2, hmac2) != 0)
        FAIL("compute_state_hmac should succeed for state2");

    if (memcmp(hmac1, hmac2, 32) == 0)
        FAIL("different states should produce different HMACs");

    PASS();
    return 0;
}
#endif

static int test_attempt_overflow_protection(void) {
    TEST("attempt counter overflow protection");
    reset_test_state();

    pin_state.failed_attempts = 254;
    pin_state_loaded = true;

    storage_crypto_record_attempt(false);
    if (pin_state.failed_attempts != 255)
        FAIL("should increment to 255");

    storage_crypto_record_attempt(false);
    if (pin_state.failed_attempts != 255)
        FAIL("should stay at 255 (no overflow)");

    PASS();
    return 0;
}

int main(void) {
    printf("\n=== PIN Attempt Limiting Tests ===\n\n");

    int failures = 0;
    failures += test_initial_state();
    failures += test_delay_schedule();
    failures += test_attempt_tracking();
    failures += test_success_resets_counter();
    failures += test_bricking_after_max_attempts();
    failures += test_bricked_device_rejects_attempts();
    failures += test_max_attempts_getter();
    failures += test_delay_remaining();
    failures += test_se_persistence();
#ifndef MOCK_MBEDTLS
    failures += test_pbkdf2_key_derivation();
    failures += test_hmac_tamper_detection();
#else
    printf("  SKIPPED: PBKDF2 and HMAC tests (mocked mbedtls)\n");
#endif
    failures += test_attempt_overflow_protection();

    printf("\n");
    if (failures == 0) {
        printf("=== All tests passed ===\n\n");
        return 0;
    } else {
        printf("=== %d test(s) failed ===\n\n", failures);
        return 1;
    }
}
