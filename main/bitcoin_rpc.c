// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include "bitcoin_rpc.h"
#include "psbt.h"
#include "policy.h"
#include "secresult.h"
#include "hex_utils.h"
#include <stdbool.h>
#include <stdio.h>

static bool psbt_initialized = false;

int bitcoin_rpc_init(void) {
    int ret = psbt_init();
    psbt_initialized = ret == 0;
    return ret;
}

void bitcoin_rpc_parse(const rpc_request_t *req, rpc_response_t *resp) {
    if (!psbt_initialized) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_INTERNAL, "PSBT not initialized");
        return;
    }
    if (!req->psbt[0]) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_PARAMS, "Missing psbt");
        return;
    }

    psbt_summary_t summary;
    int ret = psbt_parse(req->psbt, &summary);
    if (ret != 0) {
        char err_msg[64];
        snprintf(err_msg, sizeof(err_msg), "PSBT parse error: %d", ret);
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_PARAMS, err_msg);
        return;
    }

    char result[256];
    snprintf(result, sizeof(result),
             "{\"inputs\":%zu,\"outputs\":%zu,\"total_in_sats\":%llu,\"total_out_sats\":%llu,\"fee_"
             "sats\":%llu}",
             summary.input_count, summary.output_count, (unsigned long long)summary.total_in_sats,
             (unsigned long long)summary.total_out_sats, (unsigned long long)summary.fee_sats);
    protocol_success(resp, req->id, result);
}

void bitcoin_rpc_sign(const rpc_request_t *req, rpc_response_t *resp) {
    if (!psbt_initialized) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_INTERNAL, "PSBT not initialized");
        return;
    }
    if (!req->psbt[0]) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_PARAMS, "Missing psbt");
        return;
    }

    psbt_summary_t summary;
    if (psbt_parse(req->psbt, &summary) != 0) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_PARAMS, "Failed to parse PSBT");
        return;
    }

    secresult_t policy_ret = policy_evaluate_secure(summary.total_out_sats, summary.fee_sats);
    if (!SECRESULT_IS_TRUE(policy_ret)) {
        if (policy_ret == SECRESULT_ERR_POLICY_DENIED) {
            PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_SIGN, "Policy denied");
        } else {
            PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_SIGN, "Policy evaluation failed");
        }
        return;
    }

    uint8_t sighash[32];
    uint8_t sighash_type;
    int ret = psbt_get_sighash(req->psbt, req->input_idx, sighash, &sighash_type);
    if (ret == PSBT_ERR_SIGHASH_TYPE) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_SIGN, "Unsupported sighash type");
        return;
    }
    if (ret != 0) {
        PROTOCOL_ERROR(resp, req->id, PROTOCOL_ERR_SIGN, "Failed to get sighash");
        return;
    }

    char hex[65];
    bytes_to_hex(sighash, 32, hex, sizeof(hex));

    char result[160];
    snprintf(result, sizeof(result), "{\"input_idx\":%zu,\"sighash\":\"%s\",\"sighash_type\":%u}",
             req->input_idx, hex, (unsigned)sighash_type);
    protocol_success(resp, req->id, result);
}
