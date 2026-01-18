#ifndef SECURE_ELEMENT_H
#define SECURE_ELEMENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

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

/** Initialize the secure element. Must be called before other functions. */
se_status_t se_init(void);

/** Read data from a slot. Returns SE_ERR_INVALID_PARAM if slot >= SE_SLOT_COUNT. */
se_status_t se_read_slot(uint8_t slot, uint8_t *data, size_t len);

/** Write data to a slot. Returns SE_ERR_INVALID_PARAM if slot >= SE_SLOT_COUNT. */
se_status_t se_write_slot(uint8_t slot, const uint8_t *data, size_t len);

/** Increment the monotonic counter and return the new value. */
se_status_t se_increment_counter(uint32_t *new_value);

/** Get the current monotonic counter value. */
se_status_t se_get_counter(uint32_t *value);

/** Get the unique serial number of the secure element. */
se_status_t se_get_serial(uint8_t serial[SE_SERIAL_SIZE]);

/** Check if the secure element is provisioned and ready for use. */
bool se_is_provisioned(void);

#ifdef __cplusplus
}
#endif

#endif
