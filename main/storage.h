// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

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

#define STORAGE_EXPORT_VERSION  2
#define STORAGE_EXPORT_SALT_LEN 32
#define STORAGE_EXPORT_MAX_LEN  1024

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

int storage_init(void);

/* Run after unlock: upgrades share slots from older formats and erases the regions older
 * firmware used for signing and DKG checkpoints, which protocol 2 never reads. */
int storage_migrate_if_needed(void);

void storage_cleanup(void);

int storage_save_share(const char *group, const char *share_hex);

/* Derives the storage key from the PIN and proves it before any other decrypt can run,
 * as a counted attempt. Returns 0, ERR_PIN_* or STORAGE_ERR_*; the key is cleared on any
 * failure. */
int storage_unlock(const char *pin);
int storage_load_share(const char *group, char *share_hex, size_t len);

int storage_delete_share(const char *group);

int storage_list_shares(char groups[][STORAGE_GROUP_LEN + 1], int max_groups);

bool storage_has_share(const char *group);

int storage_save_metadata(const char *group, const group_metadata_t *metadata);

int storage_load_metadata(const char *group, group_metadata_t *metadata);

bool storage_has_metadata(const char *group);

typedef struct {
    uint8_t version;
    uint16_t threshold;
    uint16_t participants;
    uint16_t share_index;
    uint8_t group_pubkey[33];
    uint8_t encrypted_share[STORAGE_SHARE_LEN + 16];
    size_t encrypted_len;
    uint8_t nonce[12];
    uint8_t salt[STORAGE_EXPORT_SALT_LEN];
    uint8_t checksum[32];
} share_export_t;

/* What the export records in the clear (and authenticates) about the share, taken from
 * the validated key package by the caller. */
typedef struct {
    uint16_t threshold;
    uint16_t participants;
    uint16_t share_index;
    uint8_t group_pubkey[33];
} share_export_meta_t;

int storage_export_share(const char *group, const char *passphrase, const share_export_meta_t *meta,
                         share_export_t *export_out);

int storage_export_check_rate_limit(void);
void storage_export_record_attempt(bool success);

#endif
