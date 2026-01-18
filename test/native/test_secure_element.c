/**
 * Native tests for secure element mock implementation.
 * Compile: gcc -I../../components/secure_element/include test_secure_element.c -o test_se
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* Stub esp_log.h for native builds */
#define ESP_LOGW(tag, fmt, ...)

/* Enable mock mode and include implementation inline for testing */
#define CONFIG_SE_MOCK_MODE 1
#include "secure_element.h"

/* Mock implementation (copied for standalone testing) */
static uint8_t mock_slots[SE_SLOT_COUNT][SE_SLOT_SIZE];
static uint32_t mock_counter = 0;
static bool mock_initialized = false;
static uint8_t mock_serial[SE_SERIAL_SIZE] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x01};

#define CHECK_INIT()                       \
    do {                                   \
        if (!mock_initialized)             \
            return SE_ERR_NOT_INITIALIZED; \
    } while (0)
#define CHECK_NULL(ptr)                  \
    do {                                 \
        if ((ptr) == NULL)               \
            return SE_ERR_INVALID_PARAM; \
    } while (0)

se_status_t se_init(void) {
    mock_initialized = true;
    return SE_OK;
}

se_status_t se_read_slot(uint8_t slot, uint8_t *data, size_t len) {
    CHECK_INIT();
    if (slot >= SE_SLOT_COUNT || data == NULL || len == 0 || len > SE_SLOT_SIZE) {
        return SE_ERR_INVALID_PARAM;
    }
    memcpy(data, mock_slots[slot], len);
    return SE_OK;
}

se_status_t se_write_slot(uint8_t slot, const uint8_t *data, size_t len) {
    CHECK_INIT();
    if (slot >= SE_SLOT_COUNT || data == NULL || len == 0 || len > SE_SLOT_SIZE) {
        return SE_ERR_INVALID_PARAM;
    }
    memcpy(mock_slots[slot], data, len);
    return SE_OK;
}

se_status_t se_increment_counter(uint32_t *new_value) {
    CHECK_INIT();
    CHECK_NULL(new_value);
    *new_value = ++mock_counter;
    return SE_OK;
}

se_status_t se_get_counter(uint32_t *value) {
    CHECK_INIT();
    CHECK_NULL(value);
    *value = mock_counter;
    return SE_OK;
}

se_status_t se_get_serial(uint8_t serial[SE_SERIAL_SIZE]) {
    CHECK_INIT();
    CHECK_NULL(serial);
    memcpy(serial, mock_serial, SE_SERIAL_SIZE);
    return SE_OK;
}

bool se_is_provisioned(void) {
    return mock_initialized;
}

/* Test framework */
static int test_count = 0;
static int fail_count = 0;

#define TEST(name)                    \
    do {                              \
        printf("  TEST: %s\n", name); \
        test_count++;                 \
    } while (0)
#define ASSERT(cond, msg)                  \
    do {                                   \
        if (!(cond)) {                     \
            printf("    FAIL: %s\n", msg); \
            fail_count++;                  \
            return;                        \
        }                                  \
    } while (0)
#define PASS() printf("    PASS\n")

static void reset_mock(void) {
    memset(mock_slots, 0, sizeof(mock_slots));
    mock_counter = 0;
    mock_initialized = false;
}

static void test_init(void) {
    TEST("se_init");
    reset_mock();

    ASSERT(se_init() == SE_OK, "init failed");
    ASSERT(se_is_provisioned(), "should be provisioned after init");
    PASS();
}

static void test_slot_read_write(void) {
    TEST("slot read/write");
    reset_mock();
    se_init();

    uint8_t write_data[32], read_data[32];
    memset(write_data, 0x42, sizeof(write_data));

    ASSERT(se_write_slot(4, write_data, 32) == SE_OK, "write failed");
    ASSERT(se_read_slot(4, read_data, 32) == SE_OK, "read failed");
    ASSERT(memcmp(write_data, read_data, 32) == 0, "data mismatch");
    PASS();
}

static void test_slot_boundaries(void) {
    TEST("slot boundaries");
    reset_mock();
    se_init();

    uint8_t data[SE_SLOT_SIZE];
    memset(data, 0xAA, sizeof(data));

    ASSERT(se_write_slot(0, data, SE_SLOT_SIZE) == SE_OK, "slot 0 write failed");
    ASSERT(se_write_slot(15, data, SE_SLOT_SIZE) == SE_OK, "slot 15 write failed");
    ASSERT(se_write_slot(16, data, SE_SLOT_SIZE) == SE_ERR_INVALID_PARAM, "slot 16 should fail");
    PASS();
}

static void test_counter(void) {
    TEST("counter operations");
    reset_mock();
    se_init();

    uint32_t value;
    ASSERT(se_get_counter(&value) == SE_OK && value == 0, "counter should start at 0");
    ASSERT(se_increment_counter(&value) == SE_OK && value == 1, "counter should be 1");
    ASSERT(se_increment_counter(&value) == SE_OK && value == 2, "counter should be 2");
    ASSERT(se_get_counter(&value) == SE_OK && value == 2, "counter verify failed");
    PASS();
}

static void test_serial(void) {
    TEST("serial number");
    reset_mock();
    se_init();

    uint8_t serial[SE_SERIAL_SIZE];
    ASSERT(se_get_serial(serial) == SE_OK, "get serial failed");
    ASSERT(serial[0] == 0xDE && serial[1] == 0xAD, "serial prefix wrong");
    ASSERT(serial[2] == 0xBE && serial[3] == 0xEF, "serial bytes 2-3 wrong");
    PASS();
}

static void test_invalid_params(void) {
    TEST("invalid parameters");
    reset_mock();
    se_init();

    uint8_t data[32];

    ASSERT(se_read_slot(20, data, 32) == SE_ERR_INVALID_PARAM, "invalid slot should fail");
    ASSERT(se_read_slot(4, NULL, 32) == SE_ERR_INVALID_PARAM, "NULL data should fail");
    ASSERT(se_read_slot(4, data, 0) == SE_ERR_INVALID_PARAM, "zero len read should fail");
    ASSERT(se_read_slot(4, data, 100) == SE_ERR_INVALID_PARAM, "oversized len should fail");

    ASSERT(se_write_slot(20, data, 32) == SE_ERR_INVALID_PARAM, "invalid slot write should fail");
    ASSERT(se_write_slot(4, NULL, 32) == SE_ERR_INVALID_PARAM, "NULL data write should fail");
    ASSERT(se_write_slot(4, data, 0) == SE_ERR_INVALID_PARAM, "zero len write should fail");
    ASSERT(se_write_slot(4, data, 100) == SE_ERR_INVALID_PARAM, "oversized write should fail");

    ASSERT(se_increment_counter(NULL) == SE_ERR_INVALID_PARAM, "NULL counter should fail");
    ASSERT(se_get_counter(NULL) == SE_ERR_INVALID_PARAM, "NULL get counter should fail");
    ASSERT(se_get_serial(NULL) == SE_ERR_INVALID_PARAM, "NULL serial should fail");
    PASS();
}

static void test_uninitialized(void) {
    TEST("operations before init");
    reset_mock();

    uint8_t data[32];
    uint32_t counter;
    uint8_t serial[SE_SERIAL_SIZE];

    ASSERT(se_read_slot(4, data, 32) == SE_ERR_NOT_INITIALIZED, "read should fail");
    ASSERT(se_write_slot(4, data, 32) == SE_ERR_NOT_INITIALIZED, "write should fail");
    ASSERT(se_increment_counter(&counter) == SE_ERR_NOT_INITIALIZED, "increment should fail");
    ASSERT(se_get_counter(&counter) == SE_ERR_NOT_INITIALIZED, "get counter should fail");
    ASSERT(se_get_serial(serial) == SE_ERR_NOT_INITIALIZED, "get serial should fail");
    ASSERT(!se_is_provisioned(), "should not be provisioned");
    PASS();
}

static void test_all_slots(void) {
    TEST("all 16 slots");
    reset_mock();
    se_init();

    /* Write unique pattern to each slot */
    for (uint8_t slot = 0; slot < SE_SLOT_COUNT; slot++) {
        uint8_t write_data[SE_SLOT_SIZE];
        memset(write_data, slot, sizeof(write_data));
        ASSERT(se_write_slot(slot, write_data, SE_SLOT_SIZE) == SE_OK, "write failed");
    }

    /* Verify each slot */
    for (uint8_t slot = 0; slot < SE_SLOT_COUNT; slot++) {
        uint8_t read_data[SE_SLOT_SIZE];
        ASSERT(se_read_slot(slot, read_data, SE_SLOT_SIZE) == SE_OK, "read failed");
        for (size_t i = 0; i < SE_SLOT_SIZE; i++) {
            if (read_data[i] != slot) {
                printf("    FAIL: data mismatch slot %d byte %zu\n", slot, i);
                fail_count++;
                return;
            }
        }
    }
    PASS();
}

int main(void) {
    printf("\n=== Secure Element Mock Tests ===\n\n");

    test_init();
    test_slot_read_write();
    test_slot_boundaries();
    test_counter();
    test_serial();
    test_invalid_params();
    test_uninitialized();
    test_all_slots();

    printf("\n");
    if (fail_count == 0) {
        printf("=== All %d tests passed ===\n\n", test_count);
        return 0;
    }
    printf("=== %d of %d tests failed ===\n\n", fail_count, test_count);
    return 1;
}
