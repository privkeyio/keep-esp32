#include "storage.h"
#include "storage_crypto.h"
#include "hex_utils.h"
#include "esp_partition.h"
#include "esp_log.h"
#include "crypto_asm.h"
#include <string.h>
#include <ctype.h>

#define TAG "storage"
#define PARTITION_NAME "storage"
#define MAX_SHARES 8
#define SHARE_SLOT_SIZE 512
#define SECTOR_SIZE 4096
#define ENCRYPTED_FLAG 0x8000

typedef struct {
    char group[STORAGE_GROUP_LEN + 1];
    uint16_t share_len;
    uint8_t share_data[STORAGE_SHARE_LEN];
    uint8_t nonce[STORAGE_CRYPTO_NONCE_SIZE];
    uint8_t tag[STORAGE_CRYPTO_TAG_SIZE];
    uint8_t reserved[161];
} __attribute__((packed)) share_slot_t;

static const esp_partition_t *storage_partition = NULL;
static bool initialized = false;
static uint8_t sector_buf[SECTOR_SIZE];
static share_slot_t work_slot;

static uint16_t slot_data_len(const share_slot_t *slot) {
    return slot->share_len & ~ENCRYPTED_FLAG;
}

static bool slot_is_empty(const share_slot_t *slot) {
    return slot->share_len == 0xFFFF ||
           (unsigned char)slot->group[0] == 0xFF ||
           slot_data_len(slot) == 0;
}

static bool slot_is_valid(const share_slot_t *slot) {
    return !slot_is_empty(slot) && slot_data_len(slot) <= STORAGE_SHARE_LEN;
}

static bool validate_group_name(const char *group) {
    size_t len = strnlen(group, STORAGE_GROUP_LEN + 1);
    if (len == 0 || len > STORAGE_GROUP_LEN) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)group[i];
        if (!isalnum(c) && c != '_' && c != '-') {
            return false;
        }
    }
    return true;
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

static void null_terminate_group(share_slot_t *slot) {
    slot->group[STORAGE_GROUP_LEN] = '\0';
}

static void pad_group_name(char padded[STORAGE_GROUP_LEN + 1], const char *group) {
    memset(padded, 0, STORAGE_GROUP_LEN + 1);
    strncpy(padded, group, STORAGE_GROUP_LEN);
}

int storage_save_share(const char *group, const char *share_hex) {
    if (!initialized) {
        return STORAGE_ERR_NOT_INIT;
    }
    if (!validate_group_name(group)) {
        return STORAGE_ERR_INVALID_GROUP;
    }
    if (!share_hex) {
        return STORAGE_ERR_INVALID_DATA;
    }
    if (!storage_crypto_is_initialized()) {
        return STORAGE_ERR_CRYPTO_NOT_INIT;
    }

    unsigned char share_bytes[STORAGE_SHARE_LEN];
    int share_len = hex_to_bytes(share_hex, share_bytes, sizeof(share_bytes));
    if (share_len < 0) {
        secure_memzero(share_bytes, sizeof(share_bytes));
        return STORAGE_ERR_INVALID_DATA;
    }

    char padded_group[STORAGE_GROUP_LEN + 1];
    pad_group_name(padded_group, group);

    int target_slot = -1;
    for (int i = 0; i < MAX_SHARES; i++) {
        share_slot_t slot;
        esp_err_t err = esp_partition_read(storage_partition, i * SHARE_SLOT_SIZE, &slot, sizeof(slot));
        if (err != ESP_OK) {
            continue;
        }
        null_terminate_group(&slot);
        if (slot_is_valid(&slot) && ct_compare(slot.group, padded_group, STORAGE_GROUP_LEN + 1) == 0) {
            target_slot = i;
            break;
        }
        if (target_slot < 0 && slot_is_empty(&slot)) {
            target_slot = i;
        }
    }

    if (target_slot < 0) {
        secure_memzero(share_bytes, sizeof(share_bytes));
        return STORAGE_ERR_NO_SLOT;
    }

    size_t sector_offset = (target_slot * SHARE_SLOT_SIZE / SECTOR_SIZE) * SECTOR_SIZE;
    esp_err_t err = esp_partition_read(storage_partition, sector_offset, sector_buf, SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(share_bytes, sizeof(share_bytes));
        return STORAGE_ERR_IO;
    }

    memset(&work_slot, 0, sizeof(work_slot));
    strncpy(work_slot.group, group, STORAGE_GROUP_LEN);
    work_slot.group[STORAGE_GROUP_LEN] = '\0';

    uint8_t encrypted[STORAGE_SHARE_LEN];
    if (storage_crypto_encrypt(share_bytes, share_len, work_slot.nonce, encrypted, work_slot.tag) != 0) {
        secure_memzero(share_bytes, sizeof(share_bytes));
        secure_memzero(&work_slot, sizeof(work_slot));
        return STORAGE_ERR_IO;
    }
    secure_memzero(share_bytes, sizeof(share_bytes));

    work_slot.share_len = (uint16_t)share_len | ENCRYPTED_FLAG;
    memcpy(work_slot.share_data, encrypted, share_len);
    secure_memzero(encrypted, sizeof(encrypted));

    size_t slot_offset_in_sector = (target_slot * SHARE_SLOT_SIZE) % SECTOR_SIZE;
    memcpy(sector_buf + slot_offset_in_sector, &work_slot, sizeof(work_slot));
    secure_memzero(&work_slot, sizeof(work_slot));

    err = esp_partition_erase_range(storage_partition, sector_offset, SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(sector_buf, SECTOR_SIZE);
        return STORAGE_ERR_IO;
    }

    err = esp_partition_write(storage_partition, sector_offset, sector_buf, SECTOR_SIZE);
    secure_memzero(sector_buf, SECTOR_SIZE);
    return (err == ESP_OK) ? STORAGE_OK : STORAGE_ERR_IO;
}

int storage_load_share(const char *group, char *share_hex, size_t len) {
    if (!initialized) {
        return STORAGE_ERR_NOT_INIT;
    }
    if (!storage_crypto_is_initialized()) {
        return STORAGE_ERR_CRYPTO_NOT_INIT;
    }

    char padded_group[STORAGE_GROUP_LEN + 1];
    pad_group_name(padded_group, group);

    for (int i = 0; i < MAX_SHARES; i++) {
        share_slot_t slot;
        esp_err_t err = esp_partition_read(storage_partition, i * SHARE_SLOT_SIZE, &slot, sizeof(slot));
        if (err != ESP_OK || !slot_is_valid(&slot)) {
            continue;
        }

        null_terminate_group(&slot);
        if (ct_compare(slot.group, padded_group, STORAGE_GROUP_LEN + 1) != 0) {
            continue;
        }

        uint16_t actual_len = slot_data_len(&slot);
        if (actual_len * 2 + 1 > len) {
            ESP_LOGE(TAG, "Output buffer too small");
            secure_memzero(&slot, sizeof(slot));
            return STORAGE_ERR_INVALID_DATA;
        }

        if (slot.share_len & ENCRYPTED_FLAG) {
            uint8_t decrypted[STORAGE_SHARE_LEN];
            if (storage_crypto_decrypt(slot.share_data, actual_len, slot.nonce, slot.tag, decrypted) != 0) {
                ESP_LOGE(TAG, "Share decryption failed - tampered or wrong PIN");
                secure_memzero(&slot, sizeof(slot));
                return STORAGE_ERR_DECRYPT;
            }
            bytes_to_hex(decrypted, actual_len, share_hex, len);
            secure_memzero(decrypted, sizeof(decrypted));
        } else {
            bytes_to_hex(slot.share_data, actual_len, share_hex, len);
        }
        secure_memzero(&slot, sizeof(slot));
        return STORAGE_OK;
    }

    return STORAGE_ERR_NOT_FOUND;
}

int storage_delete_share(const char *group) {
    if (!initialized) {
        return STORAGE_ERR_NOT_INIT;
    }

    char padded_group[STORAGE_GROUP_LEN + 1];
    pad_group_name(padded_group, group);

    for (int i = 0; i < MAX_SHARES; i++) {
        share_slot_t slot;
        esp_err_t err = esp_partition_read(storage_partition, i * SHARE_SLOT_SIZE, &slot, sizeof(slot));
        if (err != ESP_OK || !slot_is_valid(&slot)) {
            continue;
        }

        null_terminate_group(&slot);
        if (ct_compare(slot.group, padded_group, STORAGE_GROUP_LEN + 1) != 0) {
            continue;
        }

        size_t sector_offset = (i * SHARE_SLOT_SIZE / SECTOR_SIZE) * SECTOR_SIZE;
        err = esp_partition_read(storage_partition, sector_offset, sector_buf, SECTOR_SIZE);
        if (err != ESP_OK) {
            secure_memzero(sector_buf, SECTOR_SIZE);
            return STORAGE_ERR_IO;
        }

        size_t slot_offset_in_sector = (i * SHARE_SLOT_SIZE) % SECTOR_SIZE;
        memset(sector_buf + slot_offset_in_sector, 0xFF, sizeof(share_slot_t));

        err = esp_partition_erase_range(storage_partition, sector_offset, SECTOR_SIZE);
        if (err != ESP_OK) {
            secure_memzero(sector_buf, SECTOR_SIZE);
            return STORAGE_ERR_IO;
        }

        err = esp_partition_write(storage_partition, sector_offset, sector_buf, SECTOR_SIZE);
        secure_memzero(sector_buf, SECTOR_SIZE);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "Deleted share for group %.16s...", group);
        }
        return err == ESP_OK ? STORAGE_OK : STORAGE_ERR_IO;
    }

    return STORAGE_ERR_NOT_FOUND;
}

_Static_assert(sizeof(share_slot_t) == SHARE_SLOT_SIZE, "share_slot_t must equal SHARE_SLOT_SIZE");

int storage_list_shares(char groups[][STORAGE_GROUP_LEN + 1], int max_groups) {
    if (!initialized) {
        return -1;
    }

    int count = 0;
    for (int i = 0; i < MAX_SHARES && count < max_groups; i++) {
        share_slot_t slot;
        esp_err_t err = esp_partition_read(storage_partition, i * SHARE_SLOT_SIZE, &slot, sizeof(slot));
        if (err != ESP_OK || !slot_is_valid(&slot)) {
            continue;
        }
        null_terminate_group(&slot);
        strncpy(groups[count], slot.group, STORAGE_GROUP_LEN);
        groups[count][STORAGE_GROUP_LEN] = '\0';
        count++;
    }

    return count;
}

bool storage_has_share(const char *group) {
    if (!initialized) {
        return false;
    }

    char padded_group[STORAGE_GROUP_LEN + 1];
    pad_group_name(padded_group, group);

    for (int i = 0; i < MAX_SHARES; i++) {
        share_slot_t slot;
        esp_err_t err = esp_partition_read(storage_partition, i * SHARE_SLOT_SIZE, &slot, sizeof(slot));
        if (err != ESP_OK || !slot_is_valid(&slot)) {
            continue;
        }
        null_terminate_group(&slot);
        if (ct_compare(slot.group, padded_group, STORAGE_GROUP_LEN + 1) == 0) {
            return true;
        }
    }

    return false;
}

void storage_cleanup(void) {
    secure_memzero(sector_buf, sizeof(sector_buf));
    secure_memzero(&work_slot, sizeof(work_slot));
    initialized = false;
    storage_partition = NULL;
}
