// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#ifndef FROST_SIGNER_STORAGE_H
#define FROST_SIGNER_STORAGE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "frost.h"
#include "storage.h"

#define SHARE_STORE_OK            0
#define SHARE_STORE_ERR_NOT_FOUND -1
#define SHARE_STORE_ERR_DECODE    -2
#define SHARE_STORE_ERR_INIT      -3
#define SHARE_STORE_ERR_SAVE      -4
#define SHARE_STORE_ERR_DELETE    -5

/**
 * @brief Function pointer type for loading share hex from storage.
 * @param group Group identifier
 * @param share_hex Output buffer for hex-encoded share
 * @param len Buffer size
 * @return 0 on success, negative on error
 */
typedef int (*share_load_fn)(const char *group, char *share_hex, size_t len);

/**
 * @brief Function pointer type for saving share hex to storage.
 * @param group Group identifier
 * @param share_hex Hex-encoded share
 * @return 0 on success, negative on error
 */
typedef int (*share_save_fn)(const char *group, const char *share_hex);

/**
 * @brief Function pointer type for deleting a share.
 * @param group Group identifier
 * @return 0 on success, negative on error
 */
typedef int (*share_delete_fn)(const char *group);

/**
 * @brief Function pointer type for checking share existence.
 * @param group Group identifier
 * @return true if share exists
 */
typedef bool (*share_exists_fn)(const char *group);

/**
 * @brief Storage adapter with pluggable backends.
 *
 * Use share_store_default() for production or provide custom
 * callbacks for testing.
 */
typedef struct {
    share_load_fn load;
    share_save_fn save;
    share_delete_fn delete_share;
    share_exists_fn exists;
} share_store_t;

/**
 * @brief Get default storage adapter using NVS backend.
 * @return Pointer to static default store
 */
const share_store_t *share_store_default(void);

/**
 * @brief Create a custom storage adapter.
 * @param load Load callback (must not be NULL)
 * @param save Save callback (must not be NULL)
 * @param delete_share Delete callback (must not be NULL)
 * @param exists Exists callback (must not be NULL)
 * @param valid Output: set to true if all pointers valid, false otherwise
 * @return Initialized store struct (check valid before use)
 */
share_store_t share_store_create(share_load_fn load, share_save_fn save,
                                 share_delete_fn delete_share, share_exists_fn exists, bool *valid);

/**
 * @brief Load and initialize FROST state from storage.
 * @param store Storage adapter
 * @param group Group identifier
 * @param state Output FROST state
 * @return 0 on success, negative on error
 * @note Caller must call frost_free() when done.
 */
int share_store_load_frost_state(const share_store_t *store, const char *group,
                                 frost_state_t *state);

/**
 * @brief Load raw share bytes from storage.
 * @param store Storage adapter
 * @param group Group identifier
 * @param share_bytes Output buffer
 * @param max_len Buffer size
 * @param out_len Output: actual share length
 * @return 0 on success, negative on error
 */
int share_store_load_share_bytes(const share_store_t *store, const char *group,
                                 uint8_t *share_bytes, size_t max_len, size_t *out_len);

#endif
