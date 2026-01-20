#ifndef MOCK_SECURE_ELEMENT_H
#define MOCK_SECURE_ELEMENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

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

#ifndef SE_MOCK_SKIP_IMPL

static uint32_t __mock_se_counter = 0;
static bool __mock_se_initialized = false;

static inline se_status_t se_init(void) {
    __mock_se_initialized = true;
    return SE_OK;
}

static inline se_status_t se_read_slot(uint8_t slot, uint8_t *data, size_t len) {
    (void)slot;
    (void)data;
    (void)len;
    return SE_OK;
}

static inline se_status_t se_write_slot(uint8_t slot, const uint8_t *data, size_t len) {
    (void)slot;
    (void)data;
    (void)len;
    return SE_OK;
}

static inline se_status_t se_increment_counter(uint32_t *new_value) {
    if (!new_value)
        return SE_ERR_INVALID_PARAM;
    *new_value = ++__mock_se_counter;
    return SE_OK;
}

static inline se_status_t se_get_counter(uint32_t *value) {
    if (!value)
        return SE_ERR_INVALID_PARAM;
    *value = __mock_se_counter;
    return SE_OK;
}

static inline se_status_t se_get_serial(uint8_t serial[SE_SERIAL_SIZE]) {
    if (!serial)
        return SE_ERR_INVALID_PARAM;
    memset(serial, 0xDE, SE_SERIAL_SIZE);
    return SE_OK;
}

static inline bool se_is_provisioned(void) {
    return __mock_se_initialized;
}

#endif

#endif
