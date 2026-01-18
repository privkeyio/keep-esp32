#ifndef ESP_PARTITION_H
#define ESP_PARTITION_H

#include <stddef.h>
#include <stdint.h>

#define ESP_OK            0
#define ESP_FAIL          -1
#define ESP_ERR_NOT_FOUND -2

typedef int esp_err_t;
typedef int esp_partition_type_t;
typedef int esp_partition_subtype_t;

#define ESP_PARTITION_TYPE_DATA   0
#define ESP_PARTITION_SUBTYPE_ANY 0

typedef struct {
    const char *label;
    size_t size;
    uint32_t address;
} esp_partition_t;

const esp_partition_t *esp_partition_find_first(esp_partition_type_t type,
                                                esp_partition_subtype_t subtype, const char *label);
esp_err_t esp_partition_read(const esp_partition_t *partition, size_t src_offset, void *dst,
                             size_t size);
esp_err_t esp_partition_write(const esp_partition_t *partition, size_t dst_offset, const void *src,
                              size_t size);
esp_err_t esp_partition_erase_range(const esp_partition_t *partition, size_t offset, size_t size);

#endif
