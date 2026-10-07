// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#ifndef FROST_SIGNER_H
#define FROST_SIGNER_H

#include <stdint.h>
#include "protocol.h"
#include "storage.h"

int frost_signer_init(void);
void frost_signer_cleanup(void);
void frost_signer_cleanup_stale(void);
/* Drops every signing session, so none started under an older policy can continue under
 * a new one. */
void frost_signer_discard_sessions(void);
/* Rewrites every share stored before protocol 2 in the protocol 2 format. One that cannot
 * be rebuilt into a valid key package is left in place and counted, never deleted. Run
 * after each unlock. */
int frost_signer_migrate_shares(int *migrated, int *unmigratable);
/* The validated metadata storage_export_share() records for `group`'s share. */
int frost_signer_export_meta(const char *group, share_export_meta_t *meta);
void frost_import_share(const char *group, const char *key_package_hex, uint16_t participants,
                        rpc_response_t *resp);
void frost_get_pubkey(const char *group, rpc_response_t *resp);
void frost_get_share_info(const char *group, rpc_response_t *resp);
void frost_commit(const char *group, const char *session_id_hex, const char *message_hex,
                  const uint32_t *path, size_t path_len, rpc_response_t *resp);
void frost_sign(const char *group, const char *session_id_hex, const char *signing_package_hex,
                rpc_response_t *resp);

#endif
