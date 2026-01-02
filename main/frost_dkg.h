#ifndef FROST_DKG_H
#define FROST_DKG_H

#include "protocol.h"
#include <stdint.h>

#define DKG_MAX_PARTICIPANTS 16
#define DKG_MAX_THRESHOLD 16

void dkg_init(const rpc_request_t *req, rpc_response_t *resp);
void dkg_round1(const rpc_request_t *req, rpc_response_t *resp);
void dkg_round1_peer(const rpc_request_t *req, rpc_response_t *resp);
void dkg_round2(const rpc_request_t *req, rpc_response_t *resp);
void dkg_receive_share(const rpc_request_t *req, rpc_response_t *resp);
void dkg_finalize(const rpc_request_t *req, rpc_response_t *resp);

#endif
