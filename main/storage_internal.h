// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#ifndef STORAGE_INTERNAL_H
#define STORAGE_INTERNAL_H

#include "storage.h"
#include "storage_crypto.h"
#include "esp_partition.h"

#define STORAGE_SECTOR_SIZE            4096
#define STORAGE_SHARE_SLOT_SIZE        512
#define STORAGE_METADATA_SLOT_SIZE     4096
#define STORAGE_METADATA_SECTOR_OFFSET STORAGE_SECTOR_SIZE
#define STORAGE_SESSION_CHECKPOINT_OFFSET \
    (STORAGE_METADATA_SECTOR_OFFSET + STORAGE_METADATA_SLOT_SIZE * STORAGE_MAX_SHARES)

bool storage_is_initialized(void);
const esp_partition_t *storage_get_partition(void);
uint8_t *storage_get_sector_buf(void);
bool storage_validate_group_name(const char *group);
void storage_pad_group_name(char padded[STORAGE_GROUP_LEN + 1], const char *group);

void storage_checkpoint_cleanup(void);
void storage_export_cleanup(void);

#endif
