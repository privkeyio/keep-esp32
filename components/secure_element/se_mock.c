// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include "sdkconfig.h"

#if defined(CONFIG_SE_MOCK_MODE) && defined(CONFIG_PRODUCTION_BUILD)
#error "Mock SE cannot be used in production builds"
#endif

#ifdef CONFIG_SE_MOCK_MODE

#include "secure_element.h"
#include "esp_log.h"
#include <string.h>

static const char *TAG = "se_mock";

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
#define MOCK_WARN() ESP_LOGW(TAG, "MOCK MODE - NOT SECURE, DEV ONLY")

se_status_t se_init(void) {
    MOCK_WARN();
    mock_initialized = true;
    return SE_OK;
}

se_status_t se_read_slot(uint8_t slot, uint8_t *data, size_t len) {
    MOCK_WARN();
    CHECK_INIT();
    if (slot >= SE_SLOT_COUNT || data == NULL || len == 0 || len > SE_SLOT_SIZE) {
        return SE_ERR_INVALID_PARAM;
    }
    memcpy(data, mock_slots[slot], len);
    return SE_OK;
}

se_status_t se_write_slot(uint8_t slot, const uint8_t *data, size_t len) {
    MOCK_WARN();
    CHECK_INIT();
    if (slot >= SE_SLOT_COUNT || data == NULL || len == 0 || len > SE_SLOT_SIZE) {
        return SE_ERR_INVALID_PARAM;
    }
    memcpy(mock_slots[slot], data, len);
    return SE_OK;
}

se_status_t se_increment_counter(uint32_t *new_value) {
    MOCK_WARN();
    CHECK_INIT();
    CHECK_NULL(new_value);
    *new_value = ++mock_counter;
    return SE_OK;
}

se_status_t se_get_counter(uint32_t *value) {
    MOCK_WARN();
    CHECK_INIT();
    CHECK_NULL(value);
    *value = mock_counter;
    return SE_OK;
}

se_status_t se_get_serial(uint8_t serial[SE_SERIAL_SIZE]) {
    MOCK_WARN();
    CHECK_INIT();
    CHECK_NULL(serial);
    memcpy(serial, mock_serial, SE_SERIAL_SIZE);
    return SE_OK;
}

bool se_is_provisioned(void) {
    MOCK_WARN();
    return mock_initialized;
}

#else

#include "secure_element.h"

se_status_t se_init(void) {
    return SE_ERR_NOT_PROVISIONED;
}

se_status_t se_read_slot(uint8_t slot, uint8_t *data, size_t len) {
    (void)slot;
    (void)data;
    (void)len;
    return SE_ERR_NOT_PROVISIONED;
}

se_status_t se_write_slot(uint8_t slot, const uint8_t *data, size_t len) {
    (void)slot;
    (void)data;
    (void)len;
    return SE_ERR_NOT_PROVISIONED;
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

bool se_is_provisioned(void) {
    return false;
}

#endif
