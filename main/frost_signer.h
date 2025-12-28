#ifndef FROST_SIGNER_H
#define FROST_SIGNER_H

#include "protocol.h"

int frost_signer_init(void);
void frost_signer_cleanup(void);
void frost_signer_cleanup_stale(void);
void frost_get_pubkey(const char *group, rpc_response_t *resp);
void frost_commit(const char *group, const char *session_id_hex, const char *message_hex, rpc_response_t *resp);
void frost_sign(const char *group, const char *session_id_hex, const char *commitments_hex, rpc_response_t *resp);
void frost_add_share(const char *session_id_hex, const char *sig_share_hex, uint16_t share_index, rpc_response_t *resp);
void frost_aggregate_shares(const char *session_id_hex, rpc_response_t *resp);

#endif
