// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef STORAGE_H
#define STORAGE_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include "error_codes.h"

#define STORAGE_MAX_SHARES       8
#define STORAGE_GROUP_LEN        64
#define STORAGE_SHARE_LEN        256
#define STORAGE_MAX_PARTICIPANTS 16
#define STORAGE_RELAY_LEN        128
#define STORAGE_PUBKEY_LEN       32

#define STORAGE_FORMAT_V1      1
#define STORAGE_FORMAT_V2      2
#define STORAGE_FORMAT_V3      3
#define STORAGE_FORMAT_CURRENT STORAGE_FORMAT_V3

typedef struct {
    uint8_t npub[STORAGE_PUBKEY_LEN];
    uint8_t index;
    char relay_hint[STORAGE_RELAY_LEN];
} storage_participant_t;

typedef struct {
    uint8_t threshold;
    uint8_t participant_count;
    storage_participant_t participants[STORAGE_MAX_PARTICIPANTS];
    uint8_t group_pubkey[33];
    uint8_t coordinator_npub[STORAGE_PUBKEY_LEN];
    uint64_t created_at;
    uint8_t our_index;
    bool has_coordinator;
} group_metadata_t;

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

/**
 * @brief Save group metadata.
 * @param group Group ID
 * @param metadata Metadata to save
 * @return 0 on success, negative on error
 */
int storage_save_metadata(const char *group, const group_metadata_t *metadata);

/**
 * @brief Load group metadata.
 * @param group Group ID
 * @param metadata Output metadata
 * @return 0 on success, negative on error
 */
int storage_load_metadata(const char *group, group_metadata_t *metadata);

/**
 * @brief Check if metadata exists for a group.
 * @param group Group ID
 * @return true if metadata exists
 */
bool storage_has_metadata(const char *group);

#define STORAGE_MAX_SESSION_CHECKPOINTS 4
#define STORAGE_SESSION_ID_LEN          32

int storage_save_session_checkpoint(const uint8_t *session_id, const void *data, size_t len);
int storage_load_session_checkpoint(const uint8_t *session_id, void *data, size_t len);
int storage_delete_session_checkpoint(const uint8_t *session_id);
int storage_list_session_checkpoints(uint8_t session_ids[][STORAGE_SESSION_ID_LEN], int max_count);
int storage_count_session_checkpoints(void);
bool storage_has_session_checkpoint(const uint8_t *session_id);

#define STORAGE_CHECKPOINT_MAX_SIZE    24576
#define STORAGE_ERR_CHECKPOINT_EXISTS  -11
#define STORAGE_ERR_CHECKPOINT_EXPIRED -12

int storage_checkpoint_save(const char *session_id, const uint8_t *data, size_t len);
int storage_checkpoint_load(const char *session_id, uint8_t *data, size_t max_len, size_t *out_len);
int storage_checkpoint_clear(const char *session_id);
bool storage_checkpoint_exists(const char *session_id);

#endif
