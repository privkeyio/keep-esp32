/**
 * @file storage.h
 * @brief Persistent storage for FROST key shares.
 *
 * Uses ESP32 NVS. Shares stored as hex strings.
 *
 * @warning Shares contain secret material. Enable NVS encryption in production.
 */

#ifndef STORAGE_H
#define STORAGE_H

#include <stddef.h>
#include <stdbool.h>

#define STORAGE_MAX_SHARES 8   /**< Max stored shares */
#define STORAGE_GROUP_LEN  64  /**< Max group ID length */
#define STORAGE_SHARE_LEN  256 /**< Max share hex length */

/** @name Storage Error Codes */
/** @{ */
#define STORAGE_OK                  0
#define STORAGE_ERR_NOT_INIT        -1
#define STORAGE_ERR_CRYPTO_NOT_INIT -2
#define STORAGE_ERR_INVALID_GROUP   -3
#define STORAGE_ERR_INVALID_DATA    -4
#define STORAGE_ERR_NO_SLOT         -5
#define STORAGE_ERR_IO              -6
#define STORAGE_ERR_NOT_FOUND       -7
#define STORAGE_ERR_DECRYPT         -8
/** @} */

/**
 * @brief Initialize storage subsystem.
 * @return 0 on success, negative on error
 * @note Call before other storage functions.
 */
int storage_init(void);

/**
 * @brief Cleanup storage subsystem.
 */
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
