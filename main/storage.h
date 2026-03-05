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

#define STORAGE_EXPORT_VERSION  1
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

int storage_migrate_if_needed(void);

void storage_cleanup(void);

int storage_save_share(const char *group, const char *share_hex);

int storage_load_share(const char *group, char *share_hex, size_t len);

int storage_delete_share(const char *group);

int storage_list_shares(char groups[][STORAGE_GROUP_LEN + 1], int max_groups);

bool storage_has_share(const char *group);

int storage_save_metadata(const char *group, const group_metadata_t *metadata);

int storage_load_metadata(const char *group, group_metadata_t *metadata);

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

int storage_export_share(const char *group, const char *passphrase, share_export_t *export_out);

int storage_export_check_rate_limit(void);
void storage_export_record_attempt(bool success);

#endif
