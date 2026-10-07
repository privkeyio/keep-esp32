// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include "storage.h"
#include "storage_crypto.h"
#include "storage_internal.h"
#include "crypto_asm.h"
#include "esp_partition.h"
#include "esp_log.h"
#ifdef ESP_PLATFORM
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#endif
#include <stdlib.h>
#include <string.h>

#define TAG "storage_checkpoint"

#define CHECKPOINT_PARTITION_NAME "checkpoint"
#define CHECKPOINT_MAGIC          0x434B5054
#define CHECKPOINT_SESSION_ID_LEN 32

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

#define CHECKPOINT_MAX_DATA_SIZE (STORAGE_CHECKPOINT_MAX_SIZE - sizeof(checkpoint_header_t))

#ifdef ESP_PLATFORM
static SemaphoreHandle_t checkpoint_mutex = NULL;

static void checkpoint_lock(void) {
    if (checkpoint_mutex)
        xSemaphoreTake(checkpoint_mutex, portMAX_DELAY);
}

static void checkpoint_unlock(void) {
    if (checkpoint_mutex)
        xSemaphoreGive(checkpoint_mutex);
}
#else
static void checkpoint_lock(void) {
}
static void checkpoint_unlock(void) {
}
#endif

static int checkpoint_init(void) {
    if (checkpoint_initialized)
        return 0;

    checkpoint_partition = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, CHECKPOINT_PARTITION_NAME);
    if (!checkpoint_partition) {
        ESP_LOGE(TAG, "Checkpoint partition '%s' not found", CHECKPOINT_PARTITION_NAME);
        return -1;
    }

#ifdef ESP_PLATFORM
    if (!checkpoint_mutex) {
        checkpoint_mutex = xSemaphoreCreateMutex();
        if (!checkpoint_mutex)
            return -1;
    }
#endif

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
    if (len == 0 || len > CHECKPOINT_MAX_DATA_SIZE)
        return STORAGE_ERR_INVALID_DATA;
    if (!storage_crypto_is_initialized())
        return STORAGE_ERR_CRYPTO_NOT_INIT;

    if (checkpoint_init() != 0)
        return STORAGE_ERR_NOT_INIT;

    checkpoint_lock();

    checkpoint_header_t existing;
    esp_err_t err = esp_partition_read(checkpoint_partition, 0, &existing, sizeof(existing));
    if (err != ESP_OK) {
        checkpoint_unlock();
        return STORAGE_ERR_IO;
    }
    if (existing.magic == CHECKPOINT_MAGIC) {
        checkpoint_unlock();
        return STORAGE_ERR_CHECKPOINT_EXISTS;
    }

    checkpoint_header_t header;
    memset(&header, 0, sizeof(header));
    header.magic = CHECKPOINT_MAGIC;
    pad_session_id(header.session_id, session_id);
    header.counter = checkpoint_get_counter();
    header.data_len = (uint16_t)len;

    uint8_t *encrypted = malloc(len);
    if (!encrypted) {
        checkpoint_unlock();
        return STORAGE_ERR_IO;
    }

    int ret = storage_crypto_encrypt(data, len, header.session_id, CHECKPOINT_SESSION_ID_LEN,
                                     header.nonce, encrypted, header.tag);
    if (ret != 0) {
        free(encrypted);
        checkpoint_unlock();
        return STORAGE_ERR_ENCRYPT;
    }

    size_t total_size = sizeof(header) + len;
    size_t erase_size =
        ((total_size + STORAGE_SECTOR_SIZE - 1) / STORAGE_SECTOR_SIZE) * STORAGE_SECTOR_SIZE;

    err = esp_partition_erase_range(checkpoint_partition, 0, erase_size);
    if (err != ESP_OK) {
        secure_memzero(encrypted, len);
        free(encrypted);
        checkpoint_unlock();
        return STORAGE_ERR_IO;
    }

    err = esp_partition_write(checkpoint_partition, 0, &header, sizeof(header));
    if (err != ESP_OK) {
        secure_memzero(encrypted, len);
        free(encrypted);
        checkpoint_unlock();
        return STORAGE_ERR_IO;
    }

    err = esp_partition_write(checkpoint_partition, sizeof(header), encrypted, len);
    secure_memzero(encrypted, len);
    free(encrypted);
    checkpoint_unlock();

    if (err != ESP_OK)
        return STORAGE_ERR_IO;

    ESP_LOGD(TAG, "Saved checkpoint");
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

    if (header.data_len > max_len || header.data_len > CHECKPOINT_MAX_DATA_SIZE)
        return STORAGE_ERR_INVALID_DATA;

    uint32_t current_counter = checkpoint_get_counter();
    if (header.counter != current_counter)
        return STORAGE_ERR_CHECKPOINT_EXPIRED;

    checkpoint_lock();

    uint8_t *encrypted = malloc(header.data_len);
    if (!encrypted) {
        checkpoint_unlock();
        return STORAGE_ERR_IO;
    }

    err = esp_partition_read(checkpoint_partition, sizeof(header), encrypted, header.data_len);
    if (err != ESP_OK) {
        free(encrypted);
        checkpoint_unlock();
        return STORAGE_ERR_IO;
    }

    int ret = storage_crypto_decrypt(encrypted, header.data_len, header.session_id,
                                     CHECKPOINT_SESSION_ID_LEN, header.nonce, header.tag, data);
    secure_memzero(encrypted, header.data_len);
    free(encrypted);
    checkpoint_unlock();

    if (ret != 0)
        return STORAGE_ERR_DECRYPT;

    *out_len = header.data_len;
    ESP_LOGD(TAG, "Loaded checkpoint");
    return STORAGE_OK;
}

int storage_checkpoint_clear(const char *session_id) {
    if (!session_id)
        return STORAGE_ERR_INVALID_DATA;

    if (checkpoint_init() != 0)
        return STORAGE_ERR_NOT_INIT;

    checkpoint_lock();

    checkpoint_header_t header;
    esp_err_t err = esp_partition_read(checkpoint_partition, 0, &header, sizeof(header));
    if (err != ESP_OK) {
        checkpoint_unlock();
        return STORAGE_ERR_IO;
    }

    if (header.magic != CHECKPOINT_MAGIC) {
        checkpoint_unlock();
        return STORAGE_ERR_NOT_FOUND;
    }

    uint8_t expected_id[CHECKPOINT_SESSION_ID_LEN];
    pad_session_id(expected_id, session_id);

    if (ct_compare(header.session_id, expected_id, CHECKPOINT_SESSION_ID_LEN) != 0) {
        checkpoint_unlock();
        return STORAGE_ERR_NOT_FOUND;
    }

    checkpoint_increment_counter();

    size_t total_size = sizeof(checkpoint_header_t) + header.data_len;
    size_t erase_size =
        ((total_size + STORAGE_SECTOR_SIZE - 1) / STORAGE_SECTOR_SIZE) * STORAGE_SECTOR_SIZE;
    if (erase_size > checkpoint_partition->size)
        erase_size = checkpoint_partition->size;

    err = esp_partition_erase_range(checkpoint_partition, 0, erase_size);
    checkpoint_unlock();

    if (err != ESP_OK)
        return STORAGE_ERR_IO;

    ESP_LOGD(TAG, "Cleared checkpoint");
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

void storage_checkpoint_cleanup(void) {
#ifdef ESP_PLATFORM
    if (checkpoint_mutex) {
        vSemaphoreDelete(checkpoint_mutex);
        checkpoint_mutex = NULL;
    }
#endif
    checkpoint_initialized = false;
    checkpoint_partition = NULL;
    checkpoint_counter = 0;
    checkpoint_counter_loaded = false;
}
