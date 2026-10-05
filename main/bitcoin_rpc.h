// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#ifndef BITCOIN_RPC_H
#define BITCOIN_RPC_H

#include "protocol.h"

int bitcoin_rpc_init(void);
void bitcoin_rpc_parse(const rpc_request_t *req, rpc_response_t *resp);
void bitcoin_rpc_sign(const rpc_request_t *req, rpc_response_t *resp);

#endif
