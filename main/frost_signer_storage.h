// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#ifndef FROST_SIGNER_STORAGE_H
#define FROST_SIGNER_STORAGE_H

#include <stddef.h>
#include <stdint.h>
#include "frost_tr.h"
#include "storage.h"

#define SHARE_KEY_OK            0
#define SHARE_KEY_ERR_NOT_FOUND -1
#define SHARE_KEY_ERR_DECODE    -2
#define SHARE_KEY_ERR_LEGACY    -3
#define SHARE_KEY_ERR_SAVE      -4

/* Protocol 2 share payload, stored encrypted in the share slot:
 * version 0x02 | participants u16 BE | frost-core KeyPackage serialization.
 * Shares stored before protocol 2 are 102 or 104 bytes; no payload has those lengths. */
#define SHARE_PAYLOAD_VERSION 0x02
#define SHARE_PAYLOAD_HEADER  3
#define SHARE_KEY_PACKAGE_MAX (STORAGE_SHARE_LEN - SHARE_PAYLOAD_HEADER)

typedef struct {
    uint8_t key_package[SHARE_KEY_PACKAGE_MAX];
    size_t key_package_len;
    uint16_t participants;
} share_key_t;

int share_payload_encode(const share_key_t *key, uint8_t out[STORAGE_SHARE_LEN], size_t *out_len);
/* SHARE_KEY_ERR_LEGACY for a pre-protocol-2 share. Only framing is checked; the key
 * package itself is validated by frost_tr wherever it is used. */
int share_payload_decode(const uint8_t *payload, size_t len, share_key_t *out);

int share_key_load(const char *group, share_key_t *out);
int share_key_save(const char *group, const share_key_t *key);
/* The stored bytes as they are, for migrating a pre-protocol-2 share. */
int share_raw_load(const char *group, uint8_t out[STORAGE_SHARE_LEN], size_t *out_len);

#endif
