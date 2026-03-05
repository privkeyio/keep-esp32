// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include "storage.h"
#include "storage_crypto.h"
#include "storage_internal.h"
#include "crypto_asm.h"
#include "esp_partition.h"
#include "esp_log.h"
#include <string.h>

#define TAG "storage_metadata"

#define METADATA_FLAG 0x01

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
    const esp_partition_t *partition = storage_get_partition();
    if (!partition)
        return -1;

    char padded_group[STORAGE_GROUP_LEN + 1];
    storage_pad_group_name(padded_group, group);

    for (int i = 0; i < STORAGE_MAX_SHARES; i++) {
        metadata_slot_t slot;
        size_t offset = STORAGE_METADATA_SECTOR_OFFSET + (size_t)i * STORAGE_METADATA_SLOT_SIZE;
        esp_err_t err = esp_partition_read(partition, offset, &slot, sizeof(slot));
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
    const esp_partition_t *partition = storage_get_partition();
    if (!partition)
        return -1;

    for (int i = 0; i < STORAGE_MAX_SHARES; i++) {
        metadata_slot_t slot;
        size_t offset = STORAGE_METADATA_SECTOR_OFFSET + (size_t)i * STORAGE_METADATA_SLOT_SIZE;
        esp_err_t err = esp_partition_read(partition, offset, &slot, sizeof(slot));
        if (err != ESP_OK || metadata_slot_is_empty(&slot)) {
            return i;
        }
    }
    return -1;
}

int storage_save_metadata(const char *group, const group_metadata_t *metadata) {
    KEEP_ASSERT(group != NULL);
    KEEP_ASSERT(metadata != NULL);

    if (!storage_is_initialized()) {
        return STORAGE_ERR_NOT_INIT;
    }
    if (!storage_validate_group_name(group)) {
        return STORAGE_ERR_INVALID_GROUP;
    }
    if (!metadata) {
        return STORAGE_ERR_INVALID_DATA;
    }
    if (metadata->participant_count == 0 ||
        metadata->participant_count > STORAGE_MAX_PARTICIPANTS) {
        return STORAGE_ERR_INVALID_DATA;
    }
    if (metadata->our_index >= metadata->participant_count) {
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

    const esp_partition_t *partition = storage_get_partition();
    uint8_t *sector_buf = storage_get_sector_buf();

    size_t slot_offset =
        STORAGE_METADATA_SECTOR_OFFSET + (size_t)target_slot * STORAGE_METADATA_SLOT_SIZE;
    size_t sector_offset = (slot_offset / STORAGE_SECTOR_SIZE) * STORAGE_SECTOR_SIZE;
    esp_err_t err = esp_partition_read(partition, sector_offset, sector_buf, STORAGE_SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(&slot, sizeof(slot));
        return STORAGE_ERR_IO;
    }

    size_t slot_offset_in_sector = slot_offset % STORAGE_SECTOR_SIZE;
    memcpy(sector_buf + slot_offset_in_sector, &slot, sizeof(slot));
    secure_memzero(&slot, sizeof(slot));

    err = esp_partition_erase_range(partition, sector_offset, STORAGE_SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(sector_buf, STORAGE_SECTOR_SIZE);
        return STORAGE_ERR_IO;
    }

    err = esp_partition_write(partition, sector_offset, sector_buf, STORAGE_SECTOR_SIZE);
    secure_memzero(sector_buf, STORAGE_SECTOR_SIZE);
    return (err == ESP_OK) ? STORAGE_OK : STORAGE_ERR_IO;
}

int storage_load_metadata(const char *group, group_metadata_t *metadata) {
    KEEP_ASSERT(group != NULL);
    KEEP_ASSERT(metadata != NULL);

    if (!storage_is_initialized()) {
        return STORAGE_ERR_NOT_INIT;
    }
    if (!storage_crypto_is_initialized()) {
        return STORAGE_ERR_CRYPTO_NOT_INIT;
    }
    if (!metadata) {
        return STORAGE_ERR_INVALID_DATA;
    }
    if (!storage_validate_group_name(group)) {
        return STORAGE_ERR_INVALID_GROUP;
    }

    int slot_idx = find_metadata_slot(group);
    if (slot_idx < 0) {
        return STORAGE_ERR_NOT_FOUND;
    }

    const esp_partition_t *partition = storage_get_partition();
    metadata_slot_t slot;
    size_t offset = STORAGE_METADATA_SECTOR_OFFSET + (size_t)slot_idx * STORAGE_METADATA_SLOT_SIZE;
    esp_err_t err = esp_partition_read(partition, offset, &slot, sizeof(slot));
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
    if (!storage_is_initialized()) {
        return false;
    }
    if (group == NULL) {
        return false;
    }
    return find_metadata_slot(group) >= 0;
}

_Static_assert(sizeof(metadata_slot_t) <= STORAGE_METADATA_SLOT_SIZE,
               "metadata_slot_t must fit in STORAGE_METADATA_SLOT_SIZE");
