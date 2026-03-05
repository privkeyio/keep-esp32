// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include "storage.h"
#include "storage_internal.h"
#include "storage_crypto.h"
#include "hex_utils.h"
#include "crypto_asm.h"
#include "esp_partition.h"
#include "esp_log.h"
#include <string.h>
#include <ctype.h>

#define TAG            "storage"
#define PARTITION_NAME "storage"
#define MAX_SHARES     8
#define ENCRYPTED_FLAG 0x8000

#define MIGRATION_MARKER_MAGIC  0x4D494752
#define MIGRATION_MARKER_OFFSET (STORAGE_SECTOR_SIZE - sizeof(migration_marker_t))

typedef struct {
    uint32_t magic;
    uint8_t slot_idx;
    uint8_t reserved[3];
} __attribute__((packed)) migration_marker_t;

typedef struct {
    char group[STORAGE_GROUP_LEN + 1];
    uint16_t share_len;
    uint8_t format_version;
    uint8_t flags;
    uint8_t share_data[STORAGE_SHARE_LEN];
    uint8_t nonce[STORAGE_CRYPTO_NONCE_SIZE];
    uint8_t tag[STORAGE_CRYPTO_TAG_SIZE];
    uint8_t reserved[159];
} __attribute__((packed)) share_slot_t;

static const esp_partition_t *storage_partition = NULL;
static bool initialized = false;
static uint8_t sector_buf[STORAGE_SECTOR_SIZE];
static share_slot_t work_slot;

bool storage_is_initialized(void) {
    return initialized;
}

const esp_partition_t *storage_get_partition(void) {
    return storage_partition;
}

uint8_t *storage_get_sector_buf(void) {
    return sector_buf;
}

bool storage_validate_group_name(const char *group) {
    if (group == NULL) {
        return false;
    }
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

void storage_pad_group_name(char padded[STORAGE_GROUP_LEN + 1], const char *group) {
    memset(padded, 0, STORAGE_GROUP_LEN + 1);
    strncpy(padded, group, STORAGE_GROUP_LEN);
}

static uint16_t slot_data_len(const share_slot_t *slot) {
    return slot->share_len & ~ENCRYPTED_FLAG;
}

static bool slot_is_empty(const share_slot_t *slot) {
    return slot->share_len == 0xFFFF || (unsigned char)slot->group[0] == 0xFF ||
           slot_data_len(slot) == 0;
}

static bool slot_is_v1(const share_slot_t *slot) {
    return slot->format_version == 0xFF || slot->format_version == STORAGE_FORMAT_V1;
}

static bool slot_is_corrupt(const share_slot_t *slot) {
    uint8_t version = slot->format_version;
    return version != 0xFF && version != STORAGE_FORMAT_V1 && version != STORAGE_FORMAT_V2 &&
           version != STORAGE_FORMAT_V3;
}

static bool slot_is_valid(const share_slot_t *slot) {
    return !slot_is_empty(slot) && slot_data_len(slot) <= STORAGE_SHARE_LEN &&
           !slot_is_corrupt(slot);
}

static void null_terminate_group(share_slot_t *slot) {
    slot->group[STORAGE_GROUP_LEN] = '\0';
}

int storage_init(void) {
    if (initialized)
        return 0;

    storage_partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY,
                                                 PARTITION_NAME);
    if (!storage_partition) {
        ESP_LOGE(TAG, "Storage partition '%s' not found", PARTITION_NAME);
        return -1;
    }

    ESP_LOGI(TAG, "Storage initialized: %s at 0x%lx (%lu bytes)", storage_partition->label,
             storage_partition->address, storage_partition->size);
    initialized = true;
    return 0;
}

static int write_migration_marker(uint8_t slot_idx) {
    migration_marker_t marker;
    marker.magic = MIGRATION_MARKER_MAGIC;
    marker.slot_idx = slot_idx;
    memset(marker.reserved, 0, sizeof(marker.reserved));

    esp_err_t err = esp_partition_read(storage_partition, 0, sector_buf, STORAGE_SECTOR_SIZE);
    if (err != ESP_OK) {
        return STORAGE_ERR_IO;
    }

    memcpy(sector_buf + MIGRATION_MARKER_OFFSET, &marker, sizeof(marker));

    err = esp_partition_erase_range(storage_partition, 0, STORAGE_SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(sector_buf, STORAGE_SECTOR_SIZE);
        return STORAGE_ERR_IO;
    }

    err = esp_partition_write(storage_partition, 0, sector_buf, STORAGE_SECTOR_SIZE);
    secure_memzero(sector_buf, STORAGE_SECTOR_SIZE);
    return (err == ESP_OK) ? STORAGE_OK : STORAGE_ERR_IO;
}

static int clear_migration_marker(void) {
    esp_err_t err = esp_partition_read(storage_partition, 0, sector_buf, STORAGE_SECTOR_SIZE);
    if (err != ESP_OK) {
        return STORAGE_ERR_IO;
    }

    memset(sector_buf + MIGRATION_MARKER_OFFSET, 0xFF, sizeof(migration_marker_t));

    err = esp_partition_erase_range(storage_partition, 0, STORAGE_SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(sector_buf, STORAGE_SECTOR_SIZE);
        return STORAGE_ERR_IO;
    }

    err = esp_partition_write(storage_partition, 0, sector_buf, STORAGE_SECTOR_SIZE);
    secure_memzero(sector_buf, STORAGE_SECTOR_SIZE);
    return (err == ESP_OK) ? STORAGE_OK : STORAGE_ERR_IO;
}

static bool check_migration_marker(uint8_t *slot_idx_out) {
    migration_marker_t marker;
    if (esp_partition_read(storage_partition, MIGRATION_MARKER_OFFSET, &marker, sizeof(marker)) !=
        ESP_OK) {
        return false;
    }
    if (marker.magic != MIGRATION_MARKER_MAGIC) {
        return false;
    }
    if (slot_idx_out) {
        *slot_idx_out = marker.slot_idx;
    }
    return true;
}

static int migrate_slot_v1_to_v2(int slot_idx, share_slot_t *slot) {
    if (!storage_crypto_is_initialized()) {
        return STORAGE_ERR_CRYPTO_NOT_INIT;
    }

    uint16_t actual_len = slot_data_len(slot);
    uint8_t plaintext[STORAGE_SHARE_LEN];
    int ret;

    if (!(slot->share_len & ENCRYPTED_FLAG)) {
        return STORAGE_ERR_INVALID_DATA;
    }

    ret = storage_crypto_decrypt(slot->share_data, actual_len, NULL, 0, slot->nonce, slot->tag,
                                 plaintext);
    if (ret != 0) {
        secure_memzero(plaintext, sizeof(plaintext));
        return STORAGE_ERR_DECRYPT;
    }

    null_terminate_group(slot);
    if (!storage_validate_group_name(slot->group)) {
        secure_memzero(plaintext, sizeof(plaintext));
        return STORAGE_ERR_INVALID_GROUP;
    }

    ret = write_migration_marker((uint8_t)slot_idx);
    if (ret != STORAGE_OK) {
        secure_memzero(plaintext, sizeof(plaintext));
        return ret;
    }

    size_t sector_offset =
        (slot_idx * STORAGE_SHARE_SLOT_SIZE / STORAGE_SECTOR_SIZE) * STORAGE_SECTOR_SIZE;
    esp_err_t err =
        esp_partition_read(storage_partition, sector_offset, sector_buf, STORAGE_SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(plaintext, sizeof(plaintext));
        secure_memzero(sector_buf, STORAGE_SECTOR_SIZE);
        return STORAGE_ERR_IO;
    }

    memset(&work_slot, 0, sizeof(work_slot));
    memcpy(work_slot.group, slot->group, STORAGE_GROUP_LEN + 1);
    work_slot.format_version = STORAGE_FORMAT_CURRENT;
    work_slot.flags = 0;

    uint8_t encrypted[STORAGE_SHARE_LEN];
    ret = storage_crypto_encrypt(plaintext, actual_len, (const uint8_t *)work_slot.group,
                                 STORAGE_GROUP_LEN + 1, work_slot.nonce, encrypted, work_slot.tag);
    secure_memzero(plaintext, sizeof(plaintext));
    if (ret != 0) {
        secure_memzero(&work_slot, sizeof(work_slot));
        secure_memzero(sector_buf, STORAGE_SECTOR_SIZE);
        return STORAGE_ERR_ENCRYPT;
    }

    work_slot.share_len = actual_len | ENCRYPTED_FLAG;
    memcpy(work_slot.share_data, encrypted, actual_len);
    secure_memzero(encrypted, sizeof(encrypted));

    size_t slot_offset_in_sector = (slot_idx * STORAGE_SHARE_SLOT_SIZE) % STORAGE_SECTOR_SIZE;
    memcpy(sector_buf + slot_offset_in_sector, &work_slot, sizeof(work_slot));
    memset(sector_buf + MIGRATION_MARKER_OFFSET, 0xFF, sizeof(migration_marker_t));
    secure_memzero(&work_slot, sizeof(work_slot));

    err = esp_partition_erase_range(storage_partition, sector_offset, STORAGE_SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(sector_buf, STORAGE_SECTOR_SIZE);
        return STORAGE_ERR_IO;
    }

    err = esp_partition_write(storage_partition, sector_offset, sector_buf, STORAGE_SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(sector_buf, STORAGE_SECTOR_SIZE);
        return STORAGE_ERR_IO;
    }

    share_slot_t verify_slot;
    err = esp_partition_read(storage_partition, slot_idx * STORAGE_SHARE_SLOT_SIZE, &verify_slot,
                             sizeof(verify_slot));
    secure_memzero(sector_buf, STORAGE_SECTOR_SIZE);
    if (err != ESP_OK) {
        return STORAGE_ERR_IO;
    }

    if (verify_slot.format_version != STORAGE_FORMAT_CURRENT ||
        verify_slot.share_len != (actual_len | ENCRYPTED_FLAG) ||
        ct_compare(verify_slot.group, slot->group, STORAGE_GROUP_LEN) != 0) {
        secure_memzero(&verify_slot, sizeof(verify_slot));
        return STORAGE_ERR_IO;
    }
    secure_memzero(&verify_slot, sizeof(verify_slot));

    return STORAGE_OK;
}

static int recover_interrupted_slot(int slot_idx) {
    share_slot_t slot;
    esp_err_t err = esp_partition_read(storage_partition, slot_idx * STORAGE_SHARE_SLOT_SIZE, &slot,
                                       sizeof(slot));
    if (err != ESP_OK) {
        return STORAGE_ERR_IO;
    }

    if (slot_is_empty(&slot)) {
        ESP_LOGW(TAG, "Interrupted slot %d is empty, nothing to recover", slot_idx);
        return STORAGE_OK;
    }

    null_terminate_group(&slot);
    if (!storage_validate_group_name(slot.group)) {
        ESP_LOGW(TAG, "Interrupted slot %d has invalid group, clearing", slot_idx);
        goto clear_slot;
    }

    uint16_t actual_len = slot_data_len(&slot);
    if (actual_len == 0 || actual_len > STORAGE_SHARE_LEN || !(slot.share_len & ENCRYPTED_FLAG)) {
        ESP_LOGW(TAG, "Interrupted slot %d has invalid data, clearing", slot_idx);
        goto clear_slot;
    }

    uint8_t plaintext[STORAGE_SHARE_LEN];

    if (slot.format_version == STORAGE_FORMAT_V2) {
        int ret = storage_crypto_decrypt(slot.share_data, actual_len, (const uint8_t *)slot.group,
                                         STORAGE_GROUP_LEN + 1, slot.nonce, slot.tag, plaintext);
        secure_memzero(plaintext, sizeof(plaintext));
        if (ret == 0) {
            ESP_LOGI(TAG, "Interrupted slot %d is valid V2, no recovery needed", slot_idx);
            return STORAGE_OK;
        }
    }

    int ret = storage_crypto_decrypt(slot.share_data, actual_len, NULL, 0, slot.nonce, slot.tag,
                                     plaintext);
    secure_memzero(plaintext, sizeof(plaintext));
    if (ret == 0) {
        ESP_LOGI(TAG, "Interrupted slot %d recoverable as V1, will re-migrate", slot_idx);
        slot.format_version = STORAGE_FORMAT_V1;
        return STORAGE_OK;
    }

    ESP_LOGW(TAG, "Interrupted slot %d unrecoverable, clearing", slot_idx);

clear_slot:;
    size_t sector_offset =
        (slot_idx * STORAGE_SHARE_SLOT_SIZE / STORAGE_SECTOR_SIZE) * STORAGE_SECTOR_SIZE;
    err = esp_partition_read(storage_partition, sector_offset, sector_buf, STORAGE_SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(sector_buf, STORAGE_SECTOR_SIZE);
        return STORAGE_ERR_IO;
    }

    size_t slot_offset_in_sector = (slot_idx * STORAGE_SHARE_SLOT_SIZE) % STORAGE_SECTOR_SIZE;
    memset(sector_buf + slot_offset_in_sector, 0xFF, sizeof(share_slot_t));

    err = esp_partition_erase_range(storage_partition, sector_offset, STORAGE_SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(sector_buf, STORAGE_SECTOR_SIZE);
        return STORAGE_ERR_IO;
    }

    err = esp_partition_write(storage_partition, sector_offset, sector_buf, STORAGE_SECTOR_SIZE);
    secure_memzero(sector_buf, STORAGE_SECTOR_SIZE);
    return (err == ESP_OK) ? STORAGE_OK : STORAGE_ERR_IO;
}

int storage_migrate_if_needed(void) {
    if (!initialized) {
        return STORAGE_ERR_NOT_INIT;
    }
    if (!storage_crypto_is_initialized()) {
        return STORAGE_ERR_CRYPTO_NOT_INIT;
    }

    uint8_t interrupted_slot;
    if (check_migration_marker(&interrupted_slot)) {
        ESP_LOGW(TAG, "Detected interrupted migration for slot %d, attempting recovery",
                 interrupted_slot);
        if (interrupted_slot < MAX_SHARES) {
            int recover_ret = recover_interrupted_slot(interrupted_slot);
            if (recover_ret != STORAGE_OK) {
                ESP_LOGE(TAG, "Failed to recover interrupted slot %d: %d", interrupted_slot,
                         recover_ret);
            }
        }
        int clear_ret = clear_migration_marker();
        if (clear_ret != STORAGE_OK) {
            ESP_LOGE(TAG, "Failed to clear migration marker");
            return clear_ret;
        }
    }

    int migrated = 0;
    for (int i = 0; i < MAX_SHARES; i++) {
        share_slot_t slot;
        esp_err_t err =
            esp_partition_read(storage_partition, i * STORAGE_SHARE_SLOT_SIZE, &slot, sizeof(slot));
        if (err != ESP_OK || !slot_is_valid(&slot)) {
            continue;
        }
        null_terminate_group(&slot);

        if (slot_is_v1(&slot)) {
            ESP_LOGD(TAG, "Migrating slot %d from V1 to V2", i);
            int ret = migrate_slot_v1_to_v2(i, &slot);
            secure_memzero(&slot, sizeof(slot));
            if (ret != STORAGE_OK) {
                ESP_LOGE(TAG, "Migration failed for slot %d: %d", i, ret);
                return ret;
            }
            migrated++;
        } else {
            secure_memzero(&slot, sizeof(slot));
        }
    }

    if (migrated > 0) {
        ESP_LOGI(TAG, "Migrated %d slot(s) to V2 format", migrated);
    }
    return STORAGE_OK;
}

int storage_save_share(const char *group, const char *share_hex) {
    KEEP_ASSERT(group != NULL);
    KEEP_ASSERT(share_hex != NULL);

    if (!initialized) {
        return STORAGE_ERR_NOT_INIT;
    }
    if (!storage_validate_group_name(group)) {
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
    storage_pad_group_name(padded_group, group);

    int target_slot = -1;
    for (int i = 0; i < MAX_SHARES; i++) {
        share_slot_t slot;
        esp_err_t err = esp_partition_read(storage_partition, (size_t)i * STORAGE_SHARE_SLOT_SIZE,
                                           &slot, sizeof(slot));
        if (err != ESP_OK) {
            continue;
        }
        null_terminate_group(&slot);
        if (slot_is_valid(&slot) &&
            ct_compare(slot.group, padded_group, STORAGE_GROUP_LEN + 1) == 0) {
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

    size_t sector_offset =
        ((size_t)target_slot * STORAGE_SHARE_SLOT_SIZE / STORAGE_SECTOR_SIZE) * STORAGE_SECTOR_SIZE;
    esp_err_t err =
        esp_partition_read(storage_partition, sector_offset, sector_buf, STORAGE_SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(share_bytes, sizeof(share_bytes));
        return STORAGE_ERR_IO;
    }

    memset(&work_slot, 0, sizeof(work_slot));
    strncpy(work_slot.group, group, STORAGE_GROUP_LEN);
    work_slot.group[STORAGE_GROUP_LEN] = '\0';
    work_slot.format_version = STORAGE_FORMAT_CURRENT;
    work_slot.flags = 0;

    uint8_t encrypted[STORAGE_SHARE_LEN];
    if (storage_crypto_encrypt(share_bytes, share_len, (const uint8_t *)work_slot.group,
                               STORAGE_GROUP_LEN + 1, work_slot.nonce, encrypted,
                               work_slot.tag) != 0) {
        secure_memzero(share_bytes, sizeof(share_bytes));
        secure_memzero(&work_slot, sizeof(work_slot));
        return STORAGE_ERR_ENCRYPT;
    }
    secure_memzero(share_bytes, sizeof(share_bytes));

    work_slot.share_len = (uint16_t)share_len | ENCRYPTED_FLAG;
    memcpy(work_slot.share_data, encrypted, share_len);
    secure_memzero(encrypted, sizeof(encrypted));

    size_t slot_offset_in_sector =
        ((size_t)target_slot * STORAGE_SHARE_SLOT_SIZE) % STORAGE_SECTOR_SIZE;
    memcpy(sector_buf + slot_offset_in_sector, &work_slot, sizeof(work_slot));
    secure_memzero(&work_slot, sizeof(work_slot));

    err = esp_partition_erase_range(storage_partition, sector_offset, STORAGE_SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(sector_buf, STORAGE_SECTOR_SIZE);
        return STORAGE_ERR_IO;
    }

    err = esp_partition_write(storage_partition, sector_offset, sector_buf, STORAGE_SECTOR_SIZE);
    secure_memzero(sector_buf, STORAGE_SECTOR_SIZE);
    return (err == ESP_OK) ? STORAGE_OK : STORAGE_ERR_IO;
}

int storage_load_share(const char *group, char *share_hex, size_t len) {
    KEEP_ASSERT(group != NULL);
    KEEP_ASSERT(share_hex != NULL);
    KEEP_ASSERT(len > 0);

    if (!initialized) {
        return STORAGE_ERR_NOT_INIT;
    }
    if (!storage_crypto_is_initialized()) {
        return STORAGE_ERR_CRYPTO_NOT_INIT;
    }
    int rate_check = storage_crypto_check_rate_limit();
    if (rate_check != 0) {
        return rate_check;
    }

    char padded_group[STORAGE_GROUP_LEN + 1];
    storage_pad_group_name(padded_group, group);

    for (int i = 0; i < MAX_SHARES; i++) {
        share_slot_t slot;
        esp_err_t err = esp_partition_read(storage_partition, (size_t)i * STORAGE_SHARE_SLOT_SIZE,
                                           &slot, sizeof(slot));
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

        if (!(slot.share_len & ENCRYPTED_FLAG)) {
            secure_memzero(&slot, sizeof(slot));
            return STORAGE_ERR_INVALID_DATA;
        }

        uint8_t decrypted[STORAGE_SHARE_LEN];
        bool is_v1 = slot_is_v1(&slot);
        const uint8_t *aad = is_v1 ? NULL : (const uint8_t *)slot.group;
        size_t aad_len = is_v1 ? 0 : STORAGE_GROUP_LEN + 1;
        if (storage_crypto_decrypt(slot.share_data, actual_len, aad, aad_len, slot.nonce, slot.tag,
                                   decrypted) != 0) {
            ESP_LOGE(TAG, "Share decryption failed - tampered or wrong PIN");
            storage_crypto_record_attempt(false);
            secure_memzero(&slot, sizeof(slot));
            return STORAGE_ERR_DECRYPT;
        }
        bytes_to_hex(decrypted, actual_len, share_hex, len);
        secure_memzero(decrypted, sizeof(decrypted));
        secure_memzero(&slot, sizeof(slot));
        return STORAGE_OK;
    }

    return STORAGE_ERR_NOT_FOUND;
}

int storage_delete_share(const char *group) {
    KEEP_ASSERT(group != NULL);

    if (!initialized) {
        return STORAGE_ERR_NOT_INIT;
    }

    char padded_group[STORAGE_GROUP_LEN + 1];
    storage_pad_group_name(padded_group, group);

    for (int i = 0; i < MAX_SHARES; i++) {
        share_slot_t slot;
        esp_err_t err = esp_partition_read(storage_partition, (size_t)i * STORAGE_SHARE_SLOT_SIZE,
                                           &slot, sizeof(slot));
        if (err != ESP_OK || !slot_is_valid(&slot)) {
            continue;
        }

        null_terminate_group(&slot);
        if (ct_compare(slot.group, padded_group, STORAGE_GROUP_LEN + 1) != 0) {
            continue;
        }

        size_t sector_offset =
            ((size_t)i * STORAGE_SHARE_SLOT_SIZE / STORAGE_SECTOR_SIZE) * STORAGE_SECTOR_SIZE;
        err = esp_partition_read(storage_partition, sector_offset, sector_buf, STORAGE_SECTOR_SIZE);
        if (err != ESP_OK) {
            secure_memzero(sector_buf, STORAGE_SECTOR_SIZE);
            return STORAGE_ERR_IO;
        }

        size_t slot_offset_in_sector = ((size_t)i * STORAGE_SHARE_SLOT_SIZE) % STORAGE_SECTOR_SIZE;
        memset(sector_buf + slot_offset_in_sector, 0xFF, sizeof(share_slot_t));

        err = esp_partition_erase_range(storage_partition, sector_offset, STORAGE_SECTOR_SIZE);
        if (err != ESP_OK) {
            secure_memzero(sector_buf, STORAGE_SECTOR_SIZE);
            return STORAGE_ERR_IO;
        }

        err =
            esp_partition_write(storage_partition, sector_offset, sector_buf, STORAGE_SECTOR_SIZE);
        secure_memzero(sector_buf, STORAGE_SECTOR_SIZE);
        if (err == ESP_OK) {
            ESP_LOGD(TAG, "Deleted share");
        }
        return err == ESP_OK ? STORAGE_OK : STORAGE_ERR_IO;
    }

    return STORAGE_ERR_NOT_FOUND;
}

_Static_assert(sizeof(share_slot_t) == STORAGE_SHARE_SLOT_SIZE,
               "share_slot_t must equal STORAGE_SHARE_SLOT_SIZE");

int storage_list_shares(char groups[][STORAGE_GROUP_LEN + 1], int max_groups) {
    if (!initialized) {
        return -1;
    }

    int count = 0;
    for (int i = 0; i < MAX_SHARES && count < max_groups; i++) {
        share_slot_t slot;
        esp_err_t err = esp_partition_read(storage_partition, (size_t)i * STORAGE_SHARE_SLOT_SIZE,
                                           &slot, sizeof(slot));
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
    storage_pad_group_name(padded_group, group);

    for (int i = 0; i < MAX_SHARES; i++) {
        share_slot_t slot;
        esp_err_t err = esp_partition_read(storage_partition, (size_t)i * STORAGE_SHARE_SLOT_SIZE,
                                           &slot, sizeof(slot));
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
    storage_export_cleanup();
    storage_checkpoint_cleanup();
    initialized = false;
    storage_partition = NULL;
}
