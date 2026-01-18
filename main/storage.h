// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef STORAGE_H
#define STORAGE_H

#include <stddef.h>
#include <stdbool.h>
#include "error_codes.h"

#define STORAGE_MAX_SHARES 8
#define STORAGE_GROUP_LEN  64
#define STORAGE_SHARE_LEN  256

#define STORAGE_FORMAT_V1      1
#define STORAGE_FORMAT_V2      2
#define STORAGE_FORMAT_CURRENT STORAGE_FORMAT_V2

/**
 * @brief Initialize storage subsystem.
 * @return 0 on success, negative on error
 * @note Call before other storage functions.
 */
int storage_init(void);

int storage_migrate_if_needed(void);

void storage_cleanup(void);

/**
 * @brief Save FROST share.
 * @param group Group ID (max STORAGE_GROUP_LEN)
 * @param share_hex Hex-encoded share
 * @return 0 on success, negative on error
 * @warning Overwrites existing share for same group.
 */
int storage_save_share(const char *group, const char *share_hex);

/**
 * @brief Load FROST share.
 * @param group Group ID
 * @param share_hex Output buffer
 * @param len Buffer size
 * @return 0 on success, negative if not found
 */
int storage_load_share(const char *group, char *share_hex, size_t len);

/**
 * @brief Delete share.
 * @param group Group ID
 * @return 0 on success, negative on error
 */
int storage_delete_share(const char *group);

/**
 * @brief List stored group IDs.
 * @param groups Output array
 * @param max_groups Array size
 * @return Count found, negative on error
 */
int storage_list_shares(char groups[][STORAGE_GROUP_LEN + 1], int max_groups);

/**
 * @brief Check if share exists.
 * @param group Group ID
 * @return true if exists
 */
bool storage_has_share(const char *group);

#endif
