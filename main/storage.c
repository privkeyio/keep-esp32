#include "storage.h"
#include "esp_partition.h"
#include "esp_log.h"
#include "mbedtls/platform_util.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define TAG "storage"
#define PARTITION_NAME "storage"
#define MAX_SHARES 8
#define SHARE_SLOT_SIZE 512
#define SECTOR_SIZE 4096

typedef struct {
    char group[STORAGE_GROUP_LEN + 1];
    uint16_t share_len;
    uint8_t share_data[STORAGE_SHARE_LEN];
    uint8_t reserved[189];
} __attribute__((packed)) share_slot_t;

static const esp_partition_t *storage_partition = NULL;
static bool initialized = false;
static uint8_t sector_buf[SECTOR_SIZE];
static share_slot_t work_slot;

static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes(const char *hex, unsigned char *out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > out_len) return -1;

    for (size_t i = 0; i < hex_len / 2; i++) {
        int hi = hex_digit(hex[2 * i]);
        int lo = hex_digit(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return hex_len / 2;
}

static int validate_group_name(const char *group) {
    size_t len = strnlen(group, STORAGE_GROUP_LEN + 1);
    if (len == 0 || len > STORAGE_GROUP_LEN) return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)group[i];
        if (!isalnum(c) && c != '_' && c != '-') return 0;
    }
    return 1;
}

static void bytes_to_hex(const unsigned char *bytes, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(out + 2 * i, "%02x", bytes[i]);
    }
    out[len * 2] = '\0';
}

int storage_init(void) {
    if (initialized) return 0;

    storage_partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, PARTITION_NAME);
    if (!storage_partition) {
        ESP_LOGE(TAG, "Storage partition '%s' not found", PARTITION_NAME);
        return -1;
    }

    ESP_LOGI(TAG, "Storage initialized: %s at 0x%lx (%lu bytes)",
             storage_partition->label, storage_partition->address, storage_partition->size);
    initialized = true;
    return 0;
}

int storage_save_share(const char *group, const char *share_hex) {
    if (!initialized) return -1;
    if (!validate_group_name(group)) return -1;

    unsigned char share_bytes[STORAGE_SHARE_LEN];
    int share_len = hex_to_bytes(share_hex, share_bytes, sizeof(share_bytes));
    if (share_len < 0) {
        mbedtls_platform_zeroize(share_bytes, sizeof(share_bytes));
        return -1;
    }

    int free_slot = -1;
    for (int i = 0; i < MAX_SHARES; i++) {
        share_slot_t slot;
        esp_err_t err = esp_partition_read(storage_partition, i * SHARE_SLOT_SIZE, &slot, sizeof(slot));
        if (err != ESP_OK) continue;
        if (strcmp(slot.group, group) == 0) {
            free_slot = i;
            break;
        }
        if (free_slot < 0 && (slot.share_len == 0 || slot.share_len == 0xFFFF || (unsigned char)slot.group[0] == 0xFF)) {
            free_slot = i;
        }
    }
    if (free_slot < 0) {
        mbedtls_platform_zeroize(share_bytes, sizeof(share_bytes));
        return -1;
    }

    size_t sector_offset = (free_slot * SHARE_SLOT_SIZE / SECTOR_SIZE) * SECTOR_SIZE;
    esp_err_t err = esp_partition_read(storage_partition, sector_offset, sector_buf, SECTOR_SIZE);
    if (err != ESP_OK) {
        mbedtls_platform_zeroize(share_bytes, sizeof(share_bytes));
        return -1;
    }

    memset(&work_slot, 0, sizeof(work_slot));
    strncpy(work_slot.group, group, STORAGE_GROUP_LEN);
    work_slot.group[STORAGE_GROUP_LEN] = '\0';
    work_slot.share_len = (uint16_t)share_len;
    memcpy(work_slot.share_data, share_bytes, share_len);
    mbedtls_platform_zeroize(share_bytes, sizeof(share_bytes));

    size_t slot_offset_in_sector = (free_slot * SHARE_SLOT_SIZE) % SECTOR_SIZE;
    memcpy(sector_buf + slot_offset_in_sector, &work_slot, sizeof(work_slot));
    mbedtls_platform_zeroize(&work_slot, sizeof(work_slot));

    err = esp_partition_erase_range(storage_partition, sector_offset, SECTOR_SIZE);
    if (err != ESP_OK) {
        mbedtls_platform_zeroize(sector_buf, SECTOR_SIZE);
        return -1;
    }

    err = esp_partition_write(storage_partition, sector_offset, sector_buf, SECTOR_SIZE);
    mbedtls_platform_zeroize(sector_buf, SECTOR_SIZE);
    return (err == ESP_OK) ? 0 : -1;
}

int storage_load_share(const char *group, char *share_hex, size_t len) {
    if (!initialized) return -1;

    for (int i = 0; i < MAX_SHARES; i++) {
        share_slot_t slot;
        esp_err_t err = esp_partition_read(storage_partition, i * SHARE_SLOT_SIZE, &slot, sizeof(slot));
        if (err != ESP_OK || slot.share_len == 0 || slot.share_len == 0xFFFF) continue;

        if (strcmp(slot.group, group) == 0) {
            if (slot.share_len * 2 + 1 > len) {
                ESP_LOGE(TAG, "Output buffer too small");
                return -1;
            }
            bytes_to_hex(slot.share_data, slot.share_len, share_hex);
            return 0;
        }
    }

    return -1;
}

int storage_delete_share(const char *group) {
    if (!initialized) return -1;

    for (int i = 0; i < MAX_SHARES; i++) {
        share_slot_t slot;
        esp_err_t err = esp_partition_read(storage_partition, i * SHARE_SLOT_SIZE, &slot, sizeof(slot));
        if (err != ESP_OK || slot.share_len == 0 || slot.share_len == 0xFFFF) continue;

        if (strcmp(slot.group, group) == 0) {
            size_t sector_offset = (i * SHARE_SLOT_SIZE / SECTOR_SIZE) * SECTOR_SIZE;
            err = esp_partition_read(storage_partition, sector_offset, sector_buf, SECTOR_SIZE);
            if (err != ESP_OK) return -1;

            size_t slot_offset_in_sector = (i * SHARE_SLOT_SIZE) % SECTOR_SIZE;
            memset(sector_buf + slot_offset_in_sector, 0xFF, sizeof(share_slot_t));

            err = esp_partition_erase_range(storage_partition, sector_offset, SECTOR_SIZE);
            if (err != ESP_OK) return -1;

            err = esp_partition_write(storage_partition, sector_offset, sector_buf, SECTOR_SIZE);
            if (err == ESP_OK) {
                ESP_LOGI(TAG, "Deleted share for group %.16s...", group);
                return 0;
            }
            return -1;
        }
    }

    return -1;
}

_Static_assert(sizeof(share_slot_t) == SHARE_SLOT_SIZE, "share_slot_t must equal SHARE_SLOT_SIZE");

int storage_list_shares(char groups[][STORAGE_GROUP_LEN + 1], int max_groups) {
    if (!initialized) return -1;

    int count = 0;
    for (int i = 0; i < MAX_SHARES && count < max_groups; i++) {
        share_slot_t slot;
        esp_err_t err = esp_partition_read(storage_partition, i * SHARE_SLOT_SIZE, &slot, sizeof(slot));
        if (err != ESP_OK || slot.share_len == 0 || slot.share_len == 0xFFFF || (unsigned char)slot.group[0] == 0xFF) continue;

        strncpy(groups[count], slot.group, STORAGE_GROUP_LEN);
        groups[count][STORAGE_GROUP_LEN] = '\0';
        count++;
    }

    return count;
}

bool storage_has_share(const char *group) {
    if (!initialized) return false;

    for (int i = 0; i < MAX_SHARES; i++) {
        share_slot_t slot;
        esp_err_t err = esp_partition_read(storage_partition, i * SHARE_SLOT_SIZE, &slot, sizeof(slot));
        if (err != ESP_OK || slot.share_len == 0 || slot.share_len == 0xFFFF) continue;

        if (strcmp(slot.group, group) == 0) {
            return true;
        }
    }

    return false;
}
