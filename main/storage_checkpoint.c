// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "storage.h"
#include "storage_crypto.h"
#include "storage_internal.h"
#include "crypto_asm.h"
#include "esp_partition.h"
#include "esp_log.h"
#include <string.h>
#include <stdlib.h>

#define TAG "storage_checkpoint"

#define CHECKPOINT_PARTITION_NAME "checkpoint"
#define CHECKPOINT_MAGIC          0x434B5054
#define CHECKPOINT_SESSION_ID_LEN 32
#define SESSION_CHECKPOINT_SLOT_SIZE 4096
#define SESSION_CHECKPOINT_MAGIC     0x53455343

static const esp_partition_t *checkpoint_partition = NULL;
static bool checkpoint_initialized = false;
static uint32_t checkpoint_counter = 0;
static bool checkpoint_counter_loaded = false;

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
    size_t erase_size = ((total_size + STORAGE_SECTOR_SIZE - 1) / STORAGE_SECTOR_SIZE) * STORAGE_SECTOR_SIZE;

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

    err = esp_partition_erase_range(checkpoint_partition, 0, STORAGE_SECTOR_SIZE);
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

static bool checkpoint_slot_is_empty(const session_checkpoint_slot_t *slot) {
    return slot->magic != SESSION_CHECKPOINT_MAGIC;
}

static int find_checkpoint_slot(const uint8_t *session_id) {
    const esp_partition_t *partition = storage_get_partition();
    if (!partition)
        return -1;

    for (int i = 0; i < STORAGE_MAX_SESSION_CHECKPOINTS; i++) {
        session_checkpoint_slot_t slot;
        size_t offset = STORAGE_SESSION_CHECKPOINT_OFFSET + (size_t)i * SESSION_CHECKPOINT_SLOT_SIZE;
        esp_err_t err = esp_partition_read(partition, offset, &slot, sizeof(slot));
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
    const esp_partition_t *partition = storage_get_partition();
    if (!partition)
        return -1;

    for (int i = 0; i < STORAGE_MAX_SESSION_CHECKPOINTS; i++) {
        session_checkpoint_slot_t slot;
        size_t offset = STORAGE_SESSION_CHECKPOINT_OFFSET + (size_t)i * SESSION_CHECKPOINT_SLOT_SIZE;
        esp_err_t err = esp_partition_read(partition, offset, &slot, sizeof(slot));
        if (err != ESP_OK || checkpoint_slot_is_empty(&slot)) {
            return i;
        }
    }
    return -1;
}

int storage_save_session_checkpoint(const uint8_t *session_id, const void *data, size_t len) {
    if (!storage_is_initialized()) {
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

    const esp_partition_t *partition = storage_get_partition();
    uint8_t *sector_buf = storage_get_sector_buf();

    size_t slot_offset =
        STORAGE_SESSION_CHECKPOINT_OFFSET + (size_t)target_slot * SESSION_CHECKPOINT_SLOT_SIZE;
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

int storage_load_session_checkpoint(const uint8_t *session_id, void *data, size_t len) {
    if (!storage_is_initialized()) {
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

    const esp_partition_t *partition = storage_get_partition();
    session_checkpoint_slot_t slot;
    size_t offset = STORAGE_SESSION_CHECKPOINT_OFFSET + (size_t)slot_idx * SESSION_CHECKPOINT_SLOT_SIZE;
    esp_err_t err = esp_partition_read(partition, offset, &slot, sizeof(slot));
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
    if (!storage_is_initialized()) {
        return STORAGE_ERR_NOT_INIT;
    }
    if (!session_id) {
        return STORAGE_ERR_INVALID_DATA;
    }

    int slot_idx = find_checkpoint_slot(session_id);
    if (slot_idx < 0) {
        return STORAGE_ERR_NOT_FOUND;
    }

    const esp_partition_t *partition = storage_get_partition();
    uint8_t *sector_buf = storage_get_sector_buf();

    size_t slot_offset =
        STORAGE_SESSION_CHECKPOINT_OFFSET + (size_t)slot_idx * SESSION_CHECKPOINT_SLOT_SIZE;
    size_t sector_offset = (slot_offset / STORAGE_SECTOR_SIZE) * STORAGE_SECTOR_SIZE;
    esp_err_t err = esp_partition_read(partition, sector_offset, sector_buf, STORAGE_SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(sector_buf, STORAGE_SECTOR_SIZE);
        return STORAGE_ERR_IO;
    }

    size_t slot_offset_in_sector = slot_offset % STORAGE_SECTOR_SIZE;
    memset(sector_buf + slot_offset_in_sector, 0xFF, sizeof(session_checkpoint_slot_t));

    err = esp_partition_erase_range(partition, sector_offset, STORAGE_SECTOR_SIZE);
    if (err != ESP_OK) {
        secure_memzero(sector_buf, STORAGE_SECTOR_SIZE);
        return STORAGE_ERR_IO;
    }

    err = esp_partition_write(partition, sector_offset, sector_buf, STORAGE_SECTOR_SIZE);
    secure_memzero(sector_buf, STORAGE_SECTOR_SIZE);
    return (err == ESP_OK) ? STORAGE_OK : STORAGE_ERR_IO;
}

int storage_list_session_checkpoints(uint8_t session_ids[][STORAGE_SESSION_ID_LEN], int max_count) {
    if (!storage_is_initialized()) {
        return -1;
    }

    const esp_partition_t *partition = storage_get_partition();
    int count = 0;
    for (int i = 0; i < STORAGE_MAX_SESSION_CHECKPOINTS && count < max_count; i++) {
        session_checkpoint_slot_t slot;
        size_t offset = STORAGE_SESSION_CHECKPOINT_OFFSET + (size_t)i * SESSION_CHECKPOINT_SLOT_SIZE;
        esp_err_t err = esp_partition_read(partition, offset, &slot, sizeof(slot));
        if (err != ESP_OK || checkpoint_slot_is_empty(&slot)) {
            continue;
        }
        memcpy(session_ids[count], slot.session_id, STORAGE_SESSION_ID_LEN);
        count++;
    }
    return count;
}

int storage_count_session_checkpoints(void) {
    if (!storage_is_initialized()) {
        return 0;
    }

    const esp_partition_t *partition = storage_get_partition();
    int count = 0;
    for (int i = 0; i < STORAGE_MAX_SESSION_CHECKPOINTS; i++) {
        session_checkpoint_slot_t slot;
        size_t offset = STORAGE_SESSION_CHECKPOINT_OFFSET + (size_t)i * SESSION_CHECKPOINT_SLOT_SIZE;
        esp_err_t err = esp_partition_read(partition, offset, &slot, sizeof(slot));
        if (err == ESP_OK && !checkpoint_slot_is_empty(&slot)) {
            count++;
        }
    }
    return count;
}

bool storage_has_session_checkpoint(const uint8_t *session_id) {
    if (!storage_is_initialized() || !session_id) {
        return false;
    }
    return find_checkpoint_slot(session_id) >= 0;
}

void storage_checkpoint_cleanup(void) {
    checkpoint_initialized = false;
    checkpoint_partition = NULL;
    checkpoint_counter = 0;
    checkpoint_counter_loaded = false;
}
