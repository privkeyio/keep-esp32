// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "storage.h"
#include "storage_crypto.h"
#include "hex_utils.h"
#include "random_utils.h"
#include "frost.h"
#include "esp_partition.h"
#include "esp_log.h"
#include "crypto_asm.h"
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/sha256.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#define TAG                     "storage"
#define PARTITION_NAME          "storage"
#define MAX_SHARES              8
#define SHARE_SLOT_SIZE         512
#define METADATA_SLOT_SIZE      4096
#define SECTOR_SIZE             4096
#define ENCRYPTED_FLAG          0x8000
#define METADATA_FLAG           0x01
#define MIGRATION_MARKER_MAGIC  0x4D494752
#define MIGRATION_MARKER_OFFSET (SECTOR_SIZE - sizeof(migration_marker_t))
#define METADATA_SECTOR_OFFSET  SECTOR_SIZE

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

typedef struct {
    uint8_t npub[STORAGE_PUBKEY_LEN];
    uint8_t index;
    char relay_hint[STORAGE_RELAY_LEN];
} __attribute__((packed)) stored_participant_t;

typedef struct {
    char group[STORAGE_GROUP_LEN + 1];
    uint8_t format_version;
    uint8_t flags;
    uint8_t threshold;
    uint8_t participant_count;
    stored_participant_t participants[STORAGE_MAX_PARTICIPANTS];
    uint8_t group_pubkey[33];
    uint8_t coordinator_npub[STORAGE_PUBKEY_LEN];
    uint64_t created_at;
    uint8_t our_index;
    uint8_t nonce[STORAGE_CRYPTO_NONCE_SIZE];
    uint8_t tag[STORAGE_CRYPTO_TAG_SIZE];
    uint8_t reserved[32];
} __attribute__((packed)) metadata_slot_t;

static const esp_partition_t *storage_partition = NULL;
static bool initialized = false;
static uint8_t sector_buf[SECTOR_SIZE];
static share_slot_t work_slot;
static const esp_partition_t *checkpoint_partition = NULL;
static bool checkpoint_initialized = false;

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
    return slot->format_version == 0x00 ||
           (slot->format_version != 0xFF && slot->format_version != STORAGE_FORMAT_V1 &&
            slot->format_version != STORAGE_FORMAT_V2 && slot->format_version != STORAGE_FORMAT_V3);
}

static bool slot_is_valid(const share_slot_t *slot) {
    if (slot_is_empty(slot) || slot_data_len(slot) > STORAGE_SHARE_LEN) {
        return false;
    }
    return !slot_is_corrupt(slot);
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

    esp_err_t err = esp_partition_read(storage_partition, 0, sector_buf, SECTOR_SIZE);
    if (err != ESP_OK) {
        return STORAGE_ERR_IO;
    }

    memcpy(sector_buf + MIGRATION_MARKER_OFFSET, &marker, sizeof(marker));

    err = esp_partition_erase_range(storage_partition, 0, SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(sector_buf, SECTOR_SIZE);
        return STORAGE_ERR_IO;
    }

    err = esp_partition_write(storage_partition, 0, sector_buf, SECTOR_SIZE);
    secure_memzero(sector_buf, SECTOR_SIZE);
    return (err == ESP_OK) ? STORAGE_OK : STORAGE_ERR_IO;
}

static int clear_migration_marker(void) {
    esp_err_t err = esp_partition_read(storage_partition, 0, sector_buf, SECTOR_SIZE);
    if (err != ESP_OK) {
        return STORAGE_ERR_IO;
    }

    memset(sector_buf + MIGRATION_MARKER_OFFSET, 0xFF, sizeof(migration_marker_t));

    err = esp_partition_erase_range(storage_partition, 0, SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(sector_buf, SECTOR_SIZE);
        return STORAGE_ERR_IO;
    }

    err = esp_partition_write(storage_partition, 0, sector_buf, SECTOR_SIZE);
    secure_memzero(sector_buf, SECTOR_SIZE);
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

static void null_terminate_group(share_slot_t *slot) {
    slot->group[STORAGE_GROUP_LEN] = '\0';
}

static void pad_group_name(char padded[STORAGE_GROUP_LEN + 1], const char *group) {
    memset(padded, 0, STORAGE_GROUP_LEN + 1);
    strncpy(padded, group, STORAGE_GROUP_LEN);
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
    if (!validate_group_name(slot->group)) {
        secure_memzero(plaintext, sizeof(plaintext));
        return STORAGE_ERR_INVALID_GROUP;
    }

    ret = write_migration_marker((uint8_t)slot_idx);
    if (ret != STORAGE_OK) {
        secure_memzero(plaintext, sizeof(plaintext));
        return ret;
    }

    size_t sector_offset = (slot_idx * SHARE_SLOT_SIZE / SECTOR_SIZE) * SECTOR_SIZE;
    esp_err_t err = esp_partition_read(storage_partition, sector_offset, sector_buf, SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(plaintext, sizeof(plaintext));
        secure_memzero(sector_buf, SECTOR_SIZE);
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
        secure_memzero(sector_buf, SECTOR_SIZE);
        return STORAGE_ERR_ENCRYPT;
    }

    work_slot.share_len = actual_len | ENCRYPTED_FLAG;
    memcpy(work_slot.share_data, encrypted, actual_len);
    secure_memzero(encrypted, sizeof(encrypted));

    size_t slot_offset_in_sector = (slot_idx * SHARE_SLOT_SIZE) % SECTOR_SIZE;
    memcpy(sector_buf + slot_offset_in_sector, &work_slot, sizeof(work_slot));
    memset(sector_buf + MIGRATION_MARKER_OFFSET, 0xFF, sizeof(migration_marker_t));
    secure_memzero(&work_slot, sizeof(work_slot));

    err = esp_partition_erase_range(storage_partition, sector_offset, SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(sector_buf, SECTOR_SIZE);
        return STORAGE_ERR_IO;
    }

    err = esp_partition_write(storage_partition, sector_offset, sector_buf, SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(sector_buf, SECTOR_SIZE);
        return STORAGE_ERR_IO;
    }

    share_slot_t verify_slot;
    err = esp_partition_read(storage_partition, slot_idx * SHARE_SLOT_SIZE, &verify_slot,
                             sizeof(verify_slot));
    secure_memzero(sector_buf, SECTOR_SIZE);
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
    esp_err_t err =
        esp_partition_read(storage_partition, slot_idx * SHARE_SLOT_SIZE, &slot, sizeof(slot));
    if (err != ESP_OK) {
        return STORAGE_ERR_IO;
    }

    if (slot_is_empty(&slot)) {
        ESP_LOGW(TAG, "Interrupted slot %d is empty, nothing to recover", slot_idx);
        return STORAGE_OK;
    }

    null_terminate_group(&slot);
    if (!validate_group_name(slot.group)) {
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
    size_t sector_offset = (slot_idx * SHARE_SLOT_SIZE / SECTOR_SIZE) * SECTOR_SIZE;
    err = esp_partition_read(storage_partition, sector_offset, sector_buf, SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(sector_buf, SECTOR_SIZE);
        return STORAGE_ERR_IO;
    }

    size_t slot_offset_in_sector = (slot_idx * SHARE_SLOT_SIZE) % SECTOR_SIZE;
    memset(sector_buf + slot_offset_in_sector, 0xFF, sizeof(share_slot_t));

    err = esp_partition_erase_range(storage_partition, sector_offset, SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(sector_buf, SECTOR_SIZE);
        return STORAGE_ERR_IO;
    }

    err = esp_partition_write(storage_partition, sector_offset, sector_buf, SECTOR_SIZE);
    secure_memzero(sector_buf, SECTOR_SIZE);
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
            esp_partition_read(storage_partition, i * SHARE_SLOT_SIZE, &slot, sizeof(slot));
        if (err != ESP_OK || !slot_is_valid(&slot)) {
            continue;
        }
        null_terminate_group(&slot);

        if (slot_is_v1(&slot)) {
            ESP_LOGI(TAG, "Migrating slot %d (%.16s...) from V1 to V2", i, slot.group);
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
        esp_err_t err =
            esp_partition_read(storage_partition, (size_t)i * SHARE_SLOT_SIZE, &slot, sizeof(slot));
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

    size_t sector_offset = ((size_t)target_slot * SHARE_SLOT_SIZE / SECTOR_SIZE) * SECTOR_SIZE;
    esp_err_t err = esp_partition_read(storage_partition, sector_offset, sector_buf, SECTOR_SIZE);
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

    size_t slot_offset_in_sector = ((size_t)target_slot * SHARE_SLOT_SIZE) % SECTOR_SIZE;
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
        esp_err_t err =
            esp_partition_read(storage_partition, (size_t)i * SHARE_SLOT_SIZE, &slot, sizeof(slot));
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
    if (!initialized) {
        return STORAGE_ERR_NOT_INIT;
    }

    char padded_group[STORAGE_GROUP_LEN + 1];
    pad_group_name(padded_group, group);

    for (int i = 0; i < MAX_SHARES; i++) {
        share_slot_t slot;
        esp_err_t err =
            esp_partition_read(storage_partition, (size_t)i * SHARE_SLOT_SIZE, &slot, sizeof(slot));
        if (err != ESP_OK || !slot_is_valid(&slot)) {
            continue;
        }

        null_terminate_group(&slot);
        if (ct_compare(slot.group, padded_group, STORAGE_GROUP_LEN + 1) != 0) {
            continue;
        }

        size_t sector_offset = ((size_t)i * SHARE_SLOT_SIZE / SECTOR_SIZE) * SECTOR_SIZE;
        err = esp_partition_read(storage_partition, sector_offset, sector_buf, SECTOR_SIZE);
        if (err != ESP_OK) {
            secure_memzero(sector_buf, SECTOR_SIZE);
            return STORAGE_ERR_IO;
        }

        size_t slot_offset_in_sector = ((size_t)i * SHARE_SLOT_SIZE) % SECTOR_SIZE;
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
        esp_err_t err =
            esp_partition_read(storage_partition, (size_t)i * SHARE_SLOT_SIZE, &slot, sizeof(slot));
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
        esp_err_t err =
            esp_partition_read(storage_partition, (size_t)i * SHARE_SLOT_SIZE, &slot, sizeof(slot));
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

#define CHECKPOINT_PARTITION_NAME "checkpoint"
#define CHECKPOINT_MAGIC          0x434B5054
#define CHECKPOINT_SESSION_ID_LEN 32
#define CHECKPOINT_COUNTER_KEY    "dkg_cp_ctr"

static uint32_t checkpoint_counter = 0;
static bool checkpoint_counter_loaded = false;

#define EXPORT_RATE_LIMIT_WINDOW_MS 60000
#define EXPORT_RATE_LIMIT_MAX       3
#define EXPORT_LOCKOUT_MS           300000

static uint32_t export_attempt_times[EXPORT_RATE_LIMIT_MAX];
static uint8_t export_attempt_count = 0;
static uint32_t export_lockout_until = 0;
static uint8_t export_consecutive_failures = 0;

#ifdef ESP_PLATFORM
#include "esp_timer.h"
static uint32_t get_time_ms(void) {
    return (uint32_t)(esp_timer_get_time() / 1000);
}
#else
#include <time.h>
static uint32_t get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}
#endif

#define EXPORT_PBKDF2_ITERATIONS 100000

static const uint8_t EXPORT_HKDF_INFO[] = "share-export-encryption";

static int derive_export_key(const char *passphrase, size_t pass_len,
                             const uint8_t salt[STORAGE_EXPORT_SALT_LEN], uint8_t key_out[32]) {
    uint8_t stretched_key[32];
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);

    int ret = mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    if (ret != 0) {
        mbedtls_md_free(&md_ctx);
        return -1;
    }

    ret = mbedtls_pkcs5_pbkdf2_hmac(&md_ctx, (const unsigned char *)passphrase, pass_len, salt,
                                    STORAGE_EXPORT_SALT_LEN, EXPORT_PBKDF2_ITERATIONS, 32,
                                    stretched_key);
    mbedtls_md_free(&md_ctx);
    if (ret != 0) {
        secure_memzero(stretched_key, sizeof(stretched_key));
        return -1;
    }

    ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0, stretched_key, 32,
                       EXPORT_HKDF_INFO, sizeof(EXPORT_HKDF_INFO) - 1, key_out, 32);

    secure_memzero(stretched_key, sizeof(stretched_key));
    return ret == 0 ? 0 : -1;
}

int storage_export_check_rate_limit(void) {
    uint32_t now = get_time_ms();

    if (export_lockout_until > 0) {
        if ((int32_t)(now - export_lockout_until) < 0) {
            return STORAGE_ERR_RATE_LIMITED;
        }
        export_lockout_until = 0;
        export_consecutive_failures = 0;
    }

    int recent = 0;
    for (int i = 0; i < export_attempt_count && i < EXPORT_RATE_LIMIT_MAX; i++) {
        if ((int32_t)(now - export_attempt_times[i]) < (int32_t)EXPORT_RATE_LIMIT_WINDOW_MS) {
            recent++;
        }
    }

    if (recent >= EXPORT_RATE_LIMIT_MAX) {
        return STORAGE_ERR_RATE_LIMITED;
    }

    return STORAGE_OK;
}

void storage_export_record_attempt(bool success) {
    uint32_t now = get_time_ms();

    if (export_attempt_count < EXPORT_RATE_LIMIT_MAX) {
        export_attempt_times[export_attempt_count++] = now;
    } else {
        memmove(export_attempt_times, export_attempt_times + 1,
                (EXPORT_RATE_LIMIT_MAX - 1) * sizeof(export_attempt_times[0]));
        export_attempt_times[EXPORT_RATE_LIMIT_MAX - 1] = now;
    }

    if (!success) {
        export_consecutive_failures++;
        if (export_consecutive_failures >= 5) {
            export_lockout_until = now + EXPORT_LOCKOUT_MS;
            ESP_LOGW(TAG, "Export lockout activated for %d seconds", EXPORT_LOCKOUT_MS / 1000);
        }
    } else {
        export_consecutive_failures = 0;
    }
}

int storage_export_share(const char *group, const char *passphrase, share_export_t *export_out) {
    if (!initialized) {
        return STORAGE_ERR_NOT_INIT;
    }
    if (!storage_crypto_is_initialized()) {
        return STORAGE_ERR_CRYPTO_NOT_INIT;
    }
    if (!group || !passphrase || !export_out) {
        return STORAGE_ERR_INVALID_DATA;
    }
    if (!validate_group_name(group)) {
        return STORAGE_ERR_INVALID_GROUP;
    }

    size_t pass_len = strnlen(passphrase, 256);
    if (pass_len < 8 || pass_len > 255) {
        return STORAGE_ERR_INVALID_DATA;
    }

    char share_hex[STORAGE_SHARE_LEN * 2 + 1];
    int ret = storage_load_share(group, share_hex, sizeof(share_hex));
    if (ret != STORAGE_OK) {
        secure_memzero(share_hex, sizeof(share_hex));
        return ret;
    }

    uint8_t share_bytes[STORAGE_SHARE_LEN];
    int share_len = hex_to_bytes(share_hex, share_bytes, sizeof(share_bytes));
    secure_memzero(share_hex, sizeof(share_hex));
    if (share_len < 0) {
        secure_memzero(share_bytes, sizeof(share_bytes));
        return STORAGE_ERR_INVALID_DATA;
    }

    frost_state_t frost_state;
    if (frost_init(&frost_state, share_bytes, share_len) != 0) {
        secure_memzero(share_bytes, sizeof(share_bytes));
        return STORAGE_ERR_INVALID_DATA;
    }

    memset(export_out, 0, sizeof(share_export_t));
    export_out->version = STORAGE_EXPORT_VERSION;
    export_out->threshold = frost_state.threshold;
    export_out->participants = frost_state.participants;
    export_out->share_index = frost_state.share_index;
    memcpy(export_out->group_pubkey, frost_state.group_pubkey, sizeof(export_out->group_pubkey));
    frost_free(&frost_state);

    if (rng_fill_checked(export_out->salt, STORAGE_EXPORT_SALT_LEN) != 0 ||
        rng_fill_checked(export_out->nonce, sizeof(export_out->nonce)) != 0) {
        secure_memzero(share_bytes, sizeof(share_bytes));
        secure_memzero(export_out, sizeof(share_export_t));
        return STORAGE_ERR_EXPORT;
    }

    uint8_t export_key[32];
    if (derive_export_key(passphrase, pass_len, export_out->salt, export_key) != 0) {
        secure_memzero(share_bytes, sizeof(share_bytes));
        secure_memzero(export_out, sizeof(share_export_t));
        return STORAGE_ERR_EXPORT;
    }

    uint8_t aad[1 + 2 + 2 + 2 + 33];
    aad[0] = export_out->version;
    aad[1] = (uint8_t)(export_out->threshold >> 8);
    aad[2] = (uint8_t)(export_out->threshold & 0xFF);
    aad[3] = (uint8_t)(export_out->participants >> 8);
    aad[4] = (uint8_t)(export_out->participants & 0xFF);
    aad[5] = (uint8_t)(export_out->share_index >> 8);
    aad[6] = (uint8_t)(export_out->share_index & 0xFF);
    memcpy(aad + 7, export_out->group_pubkey, 33);

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, export_key, 256);
    secure_memzero(export_key, sizeof(export_key));
    if (ret != 0) {
        mbedtls_gcm_free(&gcm);
        secure_memzero(share_bytes, sizeof(share_bytes));
        secure_memzero(export_out, sizeof(share_export_t));
        return STORAGE_ERR_EXPORT;
    }

    uint8_t tag[16];
    ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, share_len, export_out->nonce,
                                    sizeof(export_out->nonce), aad, sizeof(aad), share_bytes,
                                    export_out->encrypted_share, sizeof(tag), tag);
    mbedtls_gcm_free(&gcm);
    secure_memzero(share_bytes, sizeof(share_bytes));
    if (ret != 0) {
        secure_memzero(export_out, sizeof(share_export_t));
        return STORAGE_ERR_EXPORT;
    }

    memcpy(export_out->encrypted_share + share_len, tag, sizeof(tag));
    export_out->encrypted_len = share_len + sizeof(tag);

    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0);
    mbedtls_sha256_update(&sha_ctx, aad, sizeof(aad));
    mbedtls_sha256_update(&sha_ctx, export_out->salt, sizeof(export_out->salt));
    mbedtls_sha256_update(&sha_ctx, export_out->nonce, sizeof(export_out->nonce));
    mbedtls_sha256_update(&sha_ctx, export_out->encrypted_share, export_out->encrypted_len);
    mbedtls_sha256_finish(&sha_ctx, export_out->checksum);
    mbedtls_sha256_free(&sha_ctx);

    return STORAGE_OK;
}

void storage_cleanup(void) {
    secure_memzero(sector_buf, sizeof(sector_buf));
    secure_memzero(&work_slot, sizeof(work_slot));
    export_attempt_count = 0;
    export_lockout_until = 0;
    export_consecutive_failures = 0;
    memset(export_attempt_times, 0, sizeof(export_attempt_times));
    initialized = false;
    storage_partition = NULL;
    checkpoint_initialized = false;
    checkpoint_partition = NULL;
    checkpoint_counter = 0;
    checkpoint_counter_loaded = false;
}

typedef struct {
    uint32_t magic;
    uint8_t session_id[CHECKPOINT_SESSION_ID_LEN];
    uint32_t counter;
    uint16_t data_len;
    uint8_t nonce[STORAGE_CRYPTO_NONCE_SIZE];
    uint8_t tag[STORAGE_CRYPTO_TAG_SIZE];
    uint8_t reserved[26];
} __attribute__((packed)) checkpoint_header_t;

_Static_assert(sizeof(checkpoint_header_t) == 96, "checkpoint_header_t must be 96 bytes");

static int checkpoint_init(void) {
    if (checkpoint_initialized)
        return 0;

    checkpoint_partition = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, CHECKPOINT_PARTITION_NAME);
    if (!checkpoint_partition) {
        ESP_LOGE(TAG, "Checkpoint partition '%s' not found", CHECKPOINT_PARTITION_NAME);
        return -1;
    }

    checkpoint_initialized = true;
    return 0;
}

static uint32_t checkpoint_get_counter(void) {
    if (!checkpoint_counter_loaded) {
        checkpoint_header_t header;
        if (checkpoint_partition &&
            esp_partition_read(checkpoint_partition, 0, &header, sizeof(header)) == ESP_OK &&
            header.magic == CHECKPOINT_MAGIC) {
            checkpoint_counter = header.counter;
        }
        checkpoint_counter_loaded = true;
    }
    return checkpoint_counter;
}

static void checkpoint_increment_counter(void) {
    checkpoint_counter++;
    checkpoint_counter_loaded = true;
}

static void pad_session_id(uint8_t padded[CHECKPOINT_SESSION_ID_LEN], const char *session_id) {
    memset(padded, 0, CHECKPOINT_SESSION_ID_LEN);
    size_t len = strlen(session_id);
    if (len > CHECKPOINT_SESSION_ID_LEN) {
        len = CHECKPOINT_SESSION_ID_LEN;
    }
    memcpy(padded, session_id, len);
}

int storage_checkpoint_save(const char *session_id, const uint8_t *data, size_t len) {
    if (!session_id || !data)
        return STORAGE_ERR_INVALID_DATA;
    if (len == 0 || len > STORAGE_CHECKPOINT_MAX_SIZE - sizeof(checkpoint_header_t))
        return STORAGE_ERR_INVALID_DATA;
    if (!storage_crypto_is_initialized())
        return STORAGE_ERR_CRYPTO_NOT_INIT;

    if (checkpoint_init() != 0)
        return STORAGE_ERR_NOT_INIT;

    checkpoint_header_t existing;
    esp_err_t err = esp_partition_read(checkpoint_partition, 0, &existing, sizeof(existing));
    if (err == ESP_OK && existing.magic == CHECKPOINT_MAGIC) {
        return STORAGE_ERR_CHECKPOINT_EXISTS;
    }

    checkpoint_header_t header;
    memset(&header, 0, sizeof(header));
    header.magic = CHECKPOINT_MAGIC;
    pad_session_id(header.session_id, session_id);
    header.counter = checkpoint_get_counter();
    header.data_len = (uint16_t)len;

    uint8_t *encrypted = malloc(len);
    if (!encrypted)
        return STORAGE_ERR_IO;

    int ret = storage_crypto_encrypt(data, len, header.session_id, CHECKPOINT_SESSION_ID_LEN,
                                     header.nonce, encrypted, header.tag);
    if (ret != 0) {
        free(encrypted);
        return STORAGE_ERR_ENCRYPT;
    }

    size_t total_size = sizeof(header) + len;
    size_t erase_size = ((total_size + SECTOR_SIZE - 1) / SECTOR_SIZE) * SECTOR_SIZE;

    err = esp_partition_erase_range(checkpoint_partition, 0, erase_size);
    if (err != ESP_OK) {
        secure_memzero(encrypted, len);
        free(encrypted);
        return STORAGE_ERR_IO;
    }

    err = esp_partition_write(checkpoint_partition, 0, &header, sizeof(header));
    if (err != ESP_OK) {
        secure_memzero(encrypted, len);
        free(encrypted);
        return STORAGE_ERR_IO;
    }

    err = esp_partition_write(checkpoint_partition, sizeof(header), encrypted, len);
    secure_memzero(encrypted, len);
    free(encrypted);

    if (err != ESP_OK)
        return STORAGE_ERR_IO;

    ESP_LOGI(TAG, "Saved checkpoint for session %.16s...", session_id);
    return STORAGE_OK;
}

int storage_checkpoint_load(const char *session_id, uint8_t *data, size_t max_len,
                            size_t *out_len) {
    if (!session_id || !data || !out_len)
        return STORAGE_ERR_INVALID_DATA;
    if (!storage_crypto_is_initialized())
        return STORAGE_ERR_CRYPTO_NOT_INIT;

    if (checkpoint_init() != 0)
        return STORAGE_ERR_NOT_INIT;

    checkpoint_header_t header;
    esp_err_t err = esp_partition_read(checkpoint_partition, 0, &header, sizeof(header));
    if (err != ESP_OK)
        return STORAGE_ERR_IO;

    if (header.magic != CHECKPOINT_MAGIC)
        return STORAGE_ERR_NOT_FOUND;

    uint8_t expected_id[CHECKPOINT_SESSION_ID_LEN];
    pad_session_id(expected_id, session_id);

    if (ct_compare(header.session_id, expected_id, CHECKPOINT_SESSION_ID_LEN) != 0)
        return STORAGE_ERR_NOT_FOUND;

    uint32_t current_counter = checkpoint_get_counter();
    if (header.counter != current_counter)
        return STORAGE_ERR_CHECKPOINT_EXPIRED;

    if (header.data_len > max_len || header.data_len > STORAGE_CHECKPOINT_MAX_SIZE - sizeof(header))
        return STORAGE_ERR_INVALID_DATA;

    uint8_t *encrypted = malloc(header.data_len);
    if (!encrypted)
        return STORAGE_ERR_IO;

    err = esp_partition_read(checkpoint_partition, sizeof(header), encrypted, header.data_len);
    if (err != ESP_OK) {
        free(encrypted);
        return STORAGE_ERR_IO;
    }

    int ret = storage_crypto_decrypt(encrypted, header.data_len, header.session_id,
                                     CHECKPOINT_SESSION_ID_LEN, header.nonce, header.tag, data);
    secure_memzero(encrypted, header.data_len);
    free(encrypted);

    if (ret != 0)
        return STORAGE_ERR_DECRYPT;

    *out_len = header.data_len;
    ESP_LOGI(TAG, "Loaded checkpoint for session %.16s...", session_id);
    return STORAGE_OK;
}

int storage_checkpoint_clear(const char *session_id) {
    if (!session_id)
        return STORAGE_ERR_INVALID_DATA;

    if (checkpoint_init() != 0)
        return STORAGE_ERR_NOT_INIT;

    checkpoint_header_t header;
    esp_err_t err = esp_partition_read(checkpoint_partition, 0, &header, sizeof(header));
    if (err != ESP_OK)
        return STORAGE_ERR_IO;

    if (header.magic != CHECKPOINT_MAGIC)
        return STORAGE_ERR_NOT_FOUND;

    uint8_t expected_id[CHECKPOINT_SESSION_ID_LEN];
    pad_session_id(expected_id, session_id);

    if (ct_compare(header.session_id, expected_id, CHECKPOINT_SESSION_ID_LEN) != 0)
        return STORAGE_ERR_NOT_FOUND;

    checkpoint_increment_counter();

    err = esp_partition_erase_range(checkpoint_partition, 0, SECTOR_SIZE);
    if (err != ESP_OK)
        return STORAGE_ERR_IO;

    ESP_LOGI(TAG, "Cleared checkpoint for session %.16s...", session_id);
    return STORAGE_OK;
}

bool storage_checkpoint_exists(const char *session_id) {
    if (!session_id)
        return false;

    if (checkpoint_init() != 0)
        return false;

    checkpoint_header_t header;
    esp_err_t err = esp_partition_read(checkpoint_partition, 0, &header, sizeof(header));
    if (err != ESP_OK || header.magic != CHECKPOINT_MAGIC)
        return false;

    uint8_t expected_id[CHECKPOINT_SESSION_ID_LEN];
    pad_session_id(expected_id, session_id);

    if (ct_compare(header.session_id, expected_id, CHECKPOINT_SESSION_ID_LEN) != 0)
        return false;

    return header.counter == checkpoint_get_counter();
}

static bool metadata_slot_is_empty(const metadata_slot_t *slot) {
    return slot->format_version == 0xFF || (unsigned char)slot->group[0] == 0xFF;
}

static bool metadata_slot_is_valid(const metadata_slot_t *slot) {
    return !metadata_slot_is_empty(slot) && slot->format_version == STORAGE_FORMAT_V3 &&
           slot->participant_count <= STORAGE_MAX_PARTICIPANTS;
}

static void null_terminate_metadata_group(metadata_slot_t *slot) {
    slot->group[STORAGE_GROUP_LEN] = '\0';
}

static int find_metadata_slot(const char *group) {
    char padded_group[STORAGE_GROUP_LEN + 1];
    pad_group_name(padded_group, group);

    for (int i = 0; i < MAX_SHARES; i++) {
        metadata_slot_t slot;
        size_t offset = METADATA_SECTOR_OFFSET + (size_t)i * METADATA_SLOT_SIZE;
        esp_err_t err = esp_partition_read(storage_partition, offset, &slot, sizeof(slot));
        if (err != ESP_OK) {
            continue;
        }
        null_terminate_metadata_group(&slot);
        if (metadata_slot_is_valid(&slot) &&
            ct_compare(slot.group, padded_group, STORAGE_GROUP_LEN + 1) == 0) {
            return i;
        }
    }
    return -1;
}

static int find_free_metadata_slot(void) {
    for (int i = 0; i < MAX_SHARES; i++) {
        metadata_slot_t slot;
        size_t offset = METADATA_SECTOR_OFFSET + (size_t)i * METADATA_SLOT_SIZE;
        esp_err_t err = esp_partition_read(storage_partition, offset, &slot, sizeof(slot));
        if (err != ESP_OK || metadata_slot_is_empty(&slot)) {
            return i;
        }
    }
    return -1;
}

int storage_save_metadata(const char *group, const group_metadata_t *metadata) {
    if (!initialized) {
        return STORAGE_ERR_NOT_INIT;
    }
    if (!validate_group_name(group)) {
        return STORAGE_ERR_INVALID_GROUP;
    }
    if (!metadata) {
        return STORAGE_ERR_INVALID_DATA;
    }
    if (!storage_crypto_is_initialized()) {
        return STORAGE_ERR_CRYPTO_NOT_INIT;
    }

    int target_slot = find_metadata_slot(group);
    if (target_slot < 0) {
        target_slot = find_free_metadata_slot();
    }
    if (target_slot < 0) {
        return STORAGE_ERR_NO_SLOT;
    }

    metadata_slot_t slot;
    memset(&slot, 0, sizeof(slot));
    strncpy(slot.group, group, STORAGE_GROUP_LEN);
    slot.group[STORAGE_GROUP_LEN] = '\0';
    slot.format_version = STORAGE_FORMAT_V3;
    slot.flags = METADATA_FLAG;
    slot.threshold = metadata->threshold;
    slot.participant_count = metadata->participant_count;
    slot.created_at = metadata->created_at;
    slot.our_index = metadata->our_index;

    for (uint8_t i = 0; i < metadata->participant_count && i < STORAGE_MAX_PARTICIPANTS; i++) {
        memcpy(slot.participants[i].npub, metadata->participants[i].npub, STORAGE_PUBKEY_LEN);
        slot.participants[i].index = metadata->participants[i].index;
        strncpy(slot.participants[i].relay_hint, metadata->participants[i].relay_hint,
                STORAGE_RELAY_LEN - 1);
        slot.participants[i].relay_hint[STORAGE_RELAY_LEN - 1] = '\0';
    }

    memcpy(slot.group_pubkey, metadata->group_pubkey, 33);
    if (metadata->has_coordinator) {
        memcpy(slot.coordinator_npub, metadata->coordinator_npub, STORAGE_PUBKEY_LEN);
        slot.flags |= 0x02;
    }

    uint8_t plaintext[sizeof(metadata_slot_t) - STORAGE_GROUP_LEN - 1 - 2 -
                      STORAGE_CRYPTO_NONCE_SIZE - STORAGE_CRYPTO_TAG_SIZE - 32];
    size_t plaintext_len = sizeof(plaintext);
    memcpy(plaintext, &slot.threshold, plaintext_len);

    uint8_t encrypted[sizeof(plaintext)];
    if (storage_crypto_encrypt(plaintext, plaintext_len, (const uint8_t *)slot.group,
                               STORAGE_GROUP_LEN + 1, slot.nonce, encrypted, slot.tag) != 0) {
        secure_memzero(&slot, sizeof(slot));
        secure_memzero(plaintext, sizeof(plaintext));
        return STORAGE_ERR_ENCRYPT;
    }
    memcpy(&slot.threshold, encrypted, plaintext_len);
    secure_memzero(plaintext, sizeof(plaintext));
    secure_memzero(encrypted, sizeof(encrypted));

    size_t slot_offset = METADATA_SECTOR_OFFSET + (size_t)target_slot * METADATA_SLOT_SIZE;
    size_t sector_offset = (slot_offset / SECTOR_SIZE) * SECTOR_SIZE;
    esp_err_t err = esp_partition_read(storage_partition, sector_offset, sector_buf, SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(&slot, sizeof(slot));
        return STORAGE_ERR_IO;
    }

    size_t slot_offset_in_sector = slot_offset % SECTOR_SIZE;
    memcpy(sector_buf + slot_offset_in_sector, &slot, sizeof(slot));
    secure_memzero(&slot, sizeof(slot));

    err = esp_partition_erase_range(storage_partition, sector_offset, SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(sector_buf, SECTOR_SIZE);
        return STORAGE_ERR_IO;
    }

    err = esp_partition_write(storage_partition, sector_offset, sector_buf, SECTOR_SIZE);
    secure_memzero(sector_buf, SECTOR_SIZE);
    return (err == ESP_OK) ? STORAGE_OK : STORAGE_ERR_IO;
}

int storage_load_metadata(const char *group, group_metadata_t *metadata) {
    if (!initialized) {
        return STORAGE_ERR_NOT_INIT;
    }
    if (!storage_crypto_is_initialized()) {
        return STORAGE_ERR_CRYPTO_NOT_INIT;
    }
    if (!metadata) {
        return STORAGE_ERR_INVALID_DATA;
    }
    if (!validate_group_name(group)) {
        return STORAGE_ERR_INVALID_GROUP;
    }

    int slot_idx = find_metadata_slot(group);
    if (slot_idx < 0) {
        return STORAGE_ERR_NOT_FOUND;
    }

    metadata_slot_t slot;
    size_t offset = METADATA_SECTOR_OFFSET + (size_t)slot_idx * METADATA_SLOT_SIZE;
    esp_err_t err = esp_partition_read(storage_partition, offset, &slot, sizeof(slot));
    if (err != ESP_OK) {
        return STORAGE_ERR_IO;
    }

    uint8_t encrypted[sizeof(metadata_slot_t) - STORAGE_GROUP_LEN - 1 - 2 -
                      STORAGE_CRYPTO_NONCE_SIZE - STORAGE_CRYPTO_TAG_SIZE - 32];
    size_t encrypted_len = sizeof(encrypted);
    memcpy(encrypted, &slot.threshold, encrypted_len);

    uint8_t decrypted[sizeof(encrypted)];
    null_terminate_metadata_group(&slot);
    if (storage_crypto_decrypt(encrypted, encrypted_len, (const uint8_t *)slot.group,
                               STORAGE_GROUP_LEN + 1, slot.nonce, slot.tag, decrypted) != 0) {
        secure_memzero(&slot, sizeof(slot));
        secure_memzero(encrypted, sizeof(encrypted));
        return STORAGE_ERR_DECRYPT;
    }
    memcpy(&slot.threshold, decrypted, encrypted_len);
    secure_memzero(encrypted, sizeof(encrypted));
    secure_memzero(decrypted, sizeof(decrypted));

    memset(metadata, 0, sizeof(*metadata));
    metadata->threshold = slot.threshold;
    uint8_t count = slot.participant_count;
    if (count > STORAGE_MAX_PARTICIPANTS) {
        count = STORAGE_MAX_PARTICIPANTS;
    }
    metadata->participant_count = count;
    metadata->created_at = slot.created_at;
    metadata->our_index = slot.our_index;
    memcpy(metadata->group_pubkey, slot.group_pubkey, 33);

    for (uint8_t i = 0; i < count; i++) {
        memcpy(metadata->participants[i].npub, slot.participants[i].npub, STORAGE_PUBKEY_LEN);
        metadata->participants[i].index = slot.participants[i].index;
        strncpy(metadata->participants[i].relay_hint, slot.participants[i].relay_hint,
                STORAGE_RELAY_LEN - 1);
        metadata->participants[i].relay_hint[STORAGE_RELAY_LEN - 1] = '\0';
    }

    if (slot.flags & 0x02) {
        memcpy(metadata->coordinator_npub, slot.coordinator_npub, STORAGE_PUBKEY_LEN);
        metadata->has_coordinator = true;
    }

    secure_memzero(&slot, sizeof(slot));
    return STORAGE_OK;
}

bool storage_has_metadata(const char *group) {
    if (!initialized) {
        return false;
    }
    return find_metadata_slot(group) >= 0;
}

_Static_assert(sizeof(metadata_slot_t) <= METADATA_SLOT_SIZE,
               "metadata_slot_t must fit in METADATA_SLOT_SIZE");

#define SESSION_CHECKPOINT_SLOT_SIZE 4096
#define SESSION_CHECKPOINT_OFFSET    (METADATA_SECTOR_OFFSET + METADATA_SLOT_SIZE * MAX_SHARES)
#define SESSION_CHECKPOINT_MAGIC     0x53455343

typedef struct {
    uint32_t magic;
    uint8_t session_id[STORAGE_SESSION_ID_LEN];
    uint16_t data_len;
    uint8_t flags;
    uint8_t reserved;
    uint8_t nonce[STORAGE_CRYPTO_NONCE_SIZE];
    uint8_t tag[STORAGE_CRYPTO_TAG_SIZE];
    uint8_t data[SESSION_CHECKPOINT_SLOT_SIZE - 32 - 4 - 4 - STORAGE_CRYPTO_NONCE_SIZE -
                 STORAGE_CRYPTO_TAG_SIZE];
} __attribute__((packed)) session_checkpoint_slot_t;

static bool checkpoint_slot_is_empty(const session_checkpoint_slot_t *slot) {
    return slot->magic != SESSION_CHECKPOINT_MAGIC;
}

static int find_checkpoint_slot(const uint8_t *session_id) {
    for (int i = 0; i < STORAGE_MAX_SESSION_CHECKPOINTS; i++) {
        session_checkpoint_slot_t slot;
        size_t offset = SESSION_CHECKPOINT_OFFSET + (size_t)i * SESSION_CHECKPOINT_SLOT_SIZE;
        esp_err_t err = esp_partition_read(storage_partition, offset, &slot, sizeof(slot));
        if (err != ESP_OK) {
            continue;
        }
        if (!checkpoint_slot_is_empty(&slot) &&
            ct_compare(slot.session_id, session_id, STORAGE_SESSION_ID_LEN) == 0) {
            return i;
        }
    }
    return -1;
}

static int find_free_checkpoint_slot(void) {
    for (int i = 0; i < STORAGE_MAX_SESSION_CHECKPOINTS; i++) {
        session_checkpoint_slot_t slot;
        size_t offset = SESSION_CHECKPOINT_OFFSET + (size_t)i * SESSION_CHECKPOINT_SLOT_SIZE;
        esp_err_t err = esp_partition_read(storage_partition, offset, &slot, sizeof(slot));
        if (err != ESP_OK || checkpoint_slot_is_empty(&slot)) {
            return i;
        }
    }
    return -1;
}

int storage_save_session_checkpoint(const uint8_t *session_id, const void *data, size_t len) {
    if (!initialized) {
        return STORAGE_ERR_NOT_INIT;
    }
    if (!session_id || !data) {
        return STORAGE_ERR_INVALID_DATA;
    }
    if (!storage_crypto_is_initialized()) {
        return STORAGE_ERR_CRYPTO_NOT_INIT;
    }
    if (len > sizeof(((session_checkpoint_slot_t *)0)->data)) {
        return STORAGE_ERR_INVALID_DATA;
    }

    int target_slot = find_checkpoint_slot(session_id);
    if (target_slot < 0) {
        target_slot = find_free_checkpoint_slot();
    }
    if (target_slot < 0) {
        return STORAGE_ERR_NO_SLOT;
    }

    session_checkpoint_slot_t slot;
    memset(&slot, 0, sizeof(slot));
    slot.magic = SESSION_CHECKPOINT_MAGIC;
    memcpy(slot.session_id, session_id, STORAGE_SESSION_ID_LEN);
    slot.data_len = (uint16_t)len;
    slot.flags = 0x01;

    uint8_t encrypted[sizeof(slot.data)];
    if (storage_crypto_encrypt(data, len, session_id, STORAGE_SESSION_ID_LEN, slot.nonce, encrypted,
                               slot.tag) != 0) {
        secure_memzero(&slot, sizeof(slot));
        return STORAGE_ERR_ENCRYPT;
    }
    memcpy(slot.data, encrypted, len);
    secure_memzero(encrypted, sizeof(encrypted));

    size_t slot_offset =
        SESSION_CHECKPOINT_OFFSET + (size_t)target_slot * SESSION_CHECKPOINT_SLOT_SIZE;
    size_t sector_offset = (slot_offset / SECTOR_SIZE) * SECTOR_SIZE;
    esp_err_t err = esp_partition_read(storage_partition, sector_offset, sector_buf, SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(&slot, sizeof(slot));
        return STORAGE_ERR_IO;
    }

    size_t slot_offset_in_sector = slot_offset % SECTOR_SIZE;
    memcpy(sector_buf + slot_offset_in_sector, &slot, sizeof(slot));
    secure_memzero(&slot, sizeof(slot));

    err = esp_partition_erase_range(storage_partition, sector_offset, SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(sector_buf, SECTOR_SIZE);
        return STORAGE_ERR_IO;
    }

    err = esp_partition_write(storage_partition, sector_offset, sector_buf, SECTOR_SIZE);
    secure_memzero(sector_buf, SECTOR_SIZE);
    return (err == ESP_OK) ? STORAGE_OK : STORAGE_ERR_IO;
}

int storage_load_session_checkpoint(const uint8_t *session_id, void *data, size_t len) {
    if (!initialized) {
        return STORAGE_ERR_NOT_INIT;
    }
    if (!storage_crypto_is_initialized()) {
        return STORAGE_ERR_CRYPTO_NOT_INIT;
    }
    if (!session_id || !data) {
        return STORAGE_ERR_INVALID_DATA;
    }

    int slot_idx = find_checkpoint_slot(session_id);
    if (slot_idx < 0) {
        return STORAGE_ERR_NOT_FOUND;
    }

    session_checkpoint_slot_t slot;
    size_t offset = SESSION_CHECKPOINT_OFFSET + (size_t)slot_idx * SESSION_CHECKPOINT_SLOT_SIZE;
    esp_err_t err = esp_partition_read(storage_partition, offset, &slot, sizeof(slot));
    if (err != ESP_OK) {
        return STORAGE_ERR_IO;
    }

    if (slot.data_len > len || slot.data_len > sizeof(slot.data)) {
        secure_memzero(&slot, sizeof(slot));
        return STORAGE_ERR_INVALID_DATA;
    }

    uint8_t decrypted[sizeof(slot.data)];
    if (storage_crypto_decrypt(slot.data, slot.data_len, session_id, STORAGE_SESSION_ID_LEN,
                               slot.nonce, slot.tag, decrypted) != 0) {
        secure_memzero(&slot, sizeof(slot));
        return STORAGE_ERR_DECRYPT;
    }

    memcpy(data, decrypted, slot.data_len);
    secure_memzero(decrypted, sizeof(decrypted));
    secure_memzero(&slot, sizeof(slot));
    return STORAGE_OK;
}

int storage_delete_session_checkpoint(const uint8_t *session_id) {
    if (!initialized) {
        return STORAGE_ERR_NOT_INIT;
    }
    if (!session_id) {
        return STORAGE_ERR_INVALID_DATA;
    }

    int slot_idx = find_checkpoint_slot(session_id);
    if (slot_idx < 0) {
        return STORAGE_ERR_NOT_FOUND;
    }

    size_t slot_offset =
        SESSION_CHECKPOINT_OFFSET + (size_t)slot_idx * SESSION_CHECKPOINT_SLOT_SIZE;
    size_t sector_offset = (slot_offset / SECTOR_SIZE) * SECTOR_SIZE;
    esp_err_t err = esp_partition_read(storage_partition, sector_offset, sector_buf, SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(sector_buf, SECTOR_SIZE);
        return STORAGE_ERR_IO;
    }

    size_t slot_offset_in_sector = slot_offset % SECTOR_SIZE;
    memset(sector_buf + slot_offset_in_sector, 0xFF, sizeof(session_checkpoint_slot_t));

    err = esp_partition_erase_range(storage_partition, sector_offset, SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(sector_buf, SECTOR_SIZE);
        return STORAGE_ERR_IO;
    }

    err = esp_partition_write(storage_partition, sector_offset, sector_buf, SECTOR_SIZE);
    secure_memzero(sector_buf, SECTOR_SIZE);
    return (err == ESP_OK) ? STORAGE_OK : STORAGE_ERR_IO;
}

int storage_list_session_checkpoints(uint8_t session_ids[][STORAGE_SESSION_ID_LEN], int max_count) {
    if (!initialized) {
        return -1;
    }

    int count = 0;
    for (int i = 0; i < STORAGE_MAX_SESSION_CHECKPOINTS && count < max_count; i++) {
        session_checkpoint_slot_t slot;
        size_t offset = SESSION_CHECKPOINT_OFFSET + (size_t)i * SESSION_CHECKPOINT_SLOT_SIZE;
        esp_err_t err = esp_partition_read(storage_partition, offset, &slot, sizeof(slot));
        if (err != ESP_OK || checkpoint_slot_is_empty(&slot)) {
            continue;
        }
        memcpy(session_ids[count], slot.session_id, STORAGE_SESSION_ID_LEN);
        count++;
    }
    return count;
}

int storage_count_session_checkpoints(void) {
    if (!initialized) {
        return 0;
    }

    int count = 0;
    for (int i = 0; i < STORAGE_MAX_SESSION_CHECKPOINTS; i++) {
        session_checkpoint_slot_t slot;
        size_t offset = SESSION_CHECKPOINT_OFFSET + (size_t)i * SESSION_CHECKPOINT_SLOT_SIZE;
        esp_err_t err = esp_partition_read(storage_partition, offset, &slot, sizeof(slot));
        if (err == ESP_OK && !checkpoint_slot_is_empty(&slot)) {
            count++;
        }
    }
    return count;
}

bool storage_has_session_checkpoint(const uint8_t *session_id) {
    if (!initialized || !session_id) {
        return false;
    }
    return find_checkpoint_slot(session_id) >= 0;
}
