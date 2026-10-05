// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#ifndef PSBT_H
#define PSBT_H

#include <stdint.h>
#include <stddef.h>

#define PSBT_MAX_BASE64_LEN 8192

#define PSBT_SIGHASH_ALL_UNIFIED 0x21

#define PSBT_ERR_INVALID      -1
#define PSBT_ERR_SIGHASH_TYPE -2

struct wally_tx;
struct wally_tx_output;

typedef struct {
    size_t input_count;
    size_t output_count;
    uint64_t total_in_sats;
    uint64_t total_out_sats;
    uint64_t fee_sats;
} psbt_summary_t;

int psbt_init(void);
int psbt_parse(const char *base64, psbt_summary_t *summary);
int psbt_get_sighash(const char *base64, size_t input_idx, uint8_t sighash[32],
                     uint8_t *sighash_type);
int psbt_unified_sighash_taproot(const struct wally_tx *tx, size_t input_idx,
                                 const struct wally_tx_output *spent, uint8_t hash_type,
                                 uint8_t sighash[32]);
int psbt_add_taproot_signature(const char *base64_in, size_t input_idx, const uint8_t *sig,
                               size_t sig_len, char *base64_out, size_t out_len);

#endif
