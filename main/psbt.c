// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include "psbt.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_psbt.h>
#include <wally_psbt_members.h>
#include <wally_script.h>
#include <wally_transaction.h>
#include <string.h>

#define SIGHASH_ALL                 0x01
#define SIGHASH_SINGLE              0x03
#define SIGHASH_UNIFIED             0x20
#define SIGHASH_ANYONECANPAY        0x80
#define UNIFIED_SCRIPT_TYPE_TAPROOT 2
#define OUTPOINT_LEN                36

int psbt_init(void) {
    return wally_init(0);
}

int psbt_parse(const char *base64, psbt_summary_t *summary) {
    if (!base64 || !summary) {
        return WALLY_EINVAL;
    }

    struct wally_psbt *psbt = NULL;
    int ret = wally_psbt_from_base64(base64, 0, &psbt);
    if (ret != WALLY_OK) {
        return -ret;
    }
    if (!psbt) {
        return -200;
    }

    memset(summary, 0, sizeof(*summary));
    summary->input_count = psbt->num_inputs;
    summary->output_count = psbt->num_outputs;

    for (size_t i = 0; i < psbt->num_inputs; i++) {
        const struct wally_tx_output *utxo = NULL;
        if (wally_psbt_get_input_best_utxo(psbt, i, &utxo) == WALLY_OK && utxo) {
            summary->total_in_sats += utxo->satoshi;
        }
    }

    if (psbt->tx) {
        for (size_t i = 0; i < psbt->tx->num_outputs; i++) {
            summary->total_out_sats += psbt->tx->outputs[i].satoshi;
        }
    } else {
        for (size_t i = 0; i < psbt->num_outputs; i++) {
            if (psbt->outputs[i].has_amount) {
                summary->total_out_sats += psbt->outputs[i].amount;
            }
        }
    }

    if (summary->total_in_sats >= summary->total_out_sats) {
        summary->fee_sats = summary->total_in_sats - summary->total_out_sats;
    }

    wally_psbt_free(psbt);
    return 0;
}

static unsigned char *put_le(unsigned char *p, uint64_t v, size_t n) {
    for (size_t i = 0; i < n; i++) {
        p[i] = (unsigned char)(v >> (8 * i));
    }
    return p + n;
}

static size_t compact_size_len(size_t n) {
    return n < 0xfd ? 1 : n <= 0xffff ? 3 : n <= 0xffffffff ? 5 : 9;
}

static unsigned char *put_compact_size(unsigned char *p, size_t n) {
    if (n < 0xfd) {
        *p = (unsigned char)n;
        return p + 1;
    }
    if (n <= 0xffff) {
        *p = 0xfd;
        return put_le(p + 1, n, 2);
    }
    if (n <= 0xffffffff) {
        *p = 0xfe;
        return put_le(p + 1, n, 4);
    }
    *p = 0xff;
    return put_le(p + 1, n, 8);
}

static size_t output_len(const struct wally_tx_output *out) {
    return 8 + compact_size_len(out->script_len) + out->script_len;
}

static unsigned char *put_output(unsigned char *p, const struct wally_tx_output *out) {
    p = put_le(p, out->satoshi, 8);
    p = put_compact_size(p, out->script_len);
    if (out->script_len) {
        memcpy(p, out->script, out->script_len);
    }
    return p + out->script_len;
}

static unsigned char *put_outpoint(unsigned char *p, const struct wally_tx_input *in) {
    memcpy(p, in->txhash, WALLY_TXHASH_LEN);
    return put_le(p + WALLY_TXHASH_LEN, in->index, 4);
}

typedef enum { AGG_PREVOUTS, AGG_AMOUNTS, AGG_SCRIPTS, AGG_SEQUENCES, AGG_OUTPUTS } aggregate_t;

static int sha_aggregate(const struct wally_tx *tx, const struct wally_tx_output *spent,
                         aggregate_t which, unsigned char *p_out) {
    size_t n = which == AGG_OUTPUTS ? tx->num_outputs : tx->num_inputs;
    size_t len = 0;
    for (size_t i = 0; i < n; i++) {
        switch (which) {
        case AGG_PREVOUTS:
            len += OUTPOINT_LEN;
            break;
        case AGG_AMOUNTS:
            len += 8;
            break;
        case AGG_SCRIPTS:
            len += compact_size_len(spent[i].script_len) + spent[i].script_len;
            break;
        case AGG_SEQUENCES:
            len += 4;
            break;
        case AGG_OUTPUTS:
            len += output_len(&tx->outputs[i]);
            break;
        }
    }

    unsigned char *buf = malloc(len ? len : 1);
    if (!buf) {
        return -1;
    }
    unsigned char *p = buf;
    for (size_t i = 0; i < n; i++) {
        switch (which) {
        case AGG_PREVOUTS:
            p = put_outpoint(p, &tx->inputs[i]);
            break;
        case AGG_AMOUNTS:
            p = put_le(p, spent[i].satoshi, 8);
            break;
        case AGG_SCRIPTS:
            p = put_compact_size(p, spent[i].script_len);
            if (spent[i].script_len) {
                memcpy(p, spent[i].script, spent[i].script_len);
            }
            p += spent[i].script_len;
            break;
        case AGG_SEQUENCES:
            p = put_le(p, tx->inputs[i].sequence, 4);
            break;
        case AGG_OUTPUTS:
            p = put_output(p, &tx->outputs[i]);
            break;
        }
    }

    int ret = wally_sha256(buf, len, p_out, SHA256_LEN);
    free(buf);
    return ret == WALLY_OK ? 0 : -1;
}

int psbt_unified_sighash_taproot(const struct wally_tx *tx, size_t input_idx,
                                 const struct wally_tx_output *spent, uint8_t hash_type,
                                 uint8_t sighash[32]) {
    if (!tx || !spent || !sighash || input_idx >= tx->num_inputs) {
        return -1;
    }
    uint8_t base = hash_type & 0x1f;
    bool acp = (hash_type & SIGHASH_ANYONECANPAY) != 0;
    if (!(hash_type & SIGHASH_UNIFIED) || (hash_type & 0x40) || base < SIGHASH_ALL ||
        base > SIGHASH_SINGLE) {
        return -1;
    }
    if (base == SIGHASH_SINGLE && input_idx >= tx->num_outputs) {
        return -1;
    }

    const struct wally_tx_input *in = &tx->inputs[input_idx];
    const struct wally_tx_output *own = &spent[input_idx];
    size_t msg_len = 1 + 1 + 4 + 5 + (acp ? 0 : 4 * SHA256_LEN) +
                     (base == SIGHASH_ALL ? SHA256_LEN : 0) + 1 +
                     (acp ? OUTPOINT_LEN + output_len(own) + 4 : 4) + 1 +
                     (base == SIGHASH_SINGLE ? SHA256_LEN : 0);
    unsigned char *msg = malloc(msg_len);
    if (!msg) {
        return -1;
    }

    int ret = 0;
    unsigned char *p = msg;
    *p++ = 0;
    *p++ = hash_type;
    p = put_le(p, tx->version, 4);
    p = put_le(p, tx->locktime, 5);
    if (!acp) {
        static const aggregate_t aggs[] = {AGG_PREVOUTS, AGG_AMOUNTS, AGG_SCRIPTS, AGG_SEQUENCES};
        for (size_t i = 0; i < 4 && ret == 0; i++, p += SHA256_LEN) {
            ret = sha_aggregate(tx, spent, aggs[i], p);
        }
    }
    if (ret == 0 && base == SIGHASH_ALL) {
        ret = sha_aggregate(tx, spent, AGG_OUTPUTS, p);
        p += SHA256_LEN;
    }
    *p++ = UNIFIED_SCRIPT_TYPE_TAPROOT;
    if (acp) {
        p = put_outpoint(p, in);
        p = put_output(p, own);
        p = put_le(p, in->sequence, 4);
    } else {
        p = put_le(p, input_idx, 4);
    }
    *p++ = 0;
    if (ret == 0 && base == SIGHASH_SINGLE) {
        const struct wally_tx_output *out = &tx->outputs[input_idx];
        size_t single_len = output_len(out);
        unsigned char *buf = malloc(single_len);
        if (!buf) {
            ret = -1;
        } else {
            put_output(buf, out);
            ret = wally_sha256(buf, single_len, p, SHA256_LEN) == WALLY_OK ? 0 : -1;
            p += SHA256_LEN;
            free(buf);
        }
    }

    if (ret == 0 && (size_t)(p - msg) != msg_len) {
        ret = -1;
    }
    if (ret == 0 &&
        wally_bip340_tagged_hash(msg, msg_len, "UnifiedSighash", sighash, SHA256_LEN) != WALLY_OK) {
        ret = -1;
    }
    free(msg);
    if (ret != 0) {
        memset(sighash, 0, 32);
    }
    return ret;
}

static int unified_sighash_from_psbt(const struct wally_psbt *psbt, const struct wally_tx *tx,
                                     size_t input_idx, uint8_t sighash[32]) {
    struct wally_tx_output *spent = calloc(tx->num_inputs, sizeof(*spent));
    if (!spent) {
        return -1;
    }
    int ret = 0;
    for (size_t i = 0; i < tx->num_inputs && ret == 0; i++) {
        const struct wally_tx_output *out = NULL;
        if (wally_psbt_get_input_best_utxo(psbt, i, &out) != WALLY_OK || !out) {
            ret = -1;
        } else {
            spent[i].satoshi = out->satoshi;
            spent[i].script = out->script;
            spent[i].script_len = out->script_len;
        }
    }

    size_t script_type = 0;
    const struct wally_tx_output *own = ret == 0 ? &spent[input_idx] : NULL;
    if (ret == 0 &&
        (wally_scriptpubkey_get_type(own->script, own->script_len, &script_type) != WALLY_OK ||
         script_type != WALLY_SCRIPT_TYPE_P2TR)) {
        ret = -1;
    }
    if (ret == 0) {
        ret = psbt_unified_sighash_taproot(tx, input_idx, spent, PSBT_SIGHASH_ALL_UNIFIED, sighash);
    }
    free(spent);
    return ret;
}

int psbt_get_sighash(const char *base64, size_t input_idx, uint8_t sighash[32],
                     uint8_t *sighash_type) {
    if (!base64 || !sighash || !sighash_type) {
        return PSBT_ERR_INVALID;
    }
    memset(sighash, 0, 32);
    *sighash_type = 0;

    struct wally_psbt *psbt = NULL;
    int ret = wally_psbt_from_base64(base64, 0, &psbt);
    if (ret != WALLY_OK || !psbt) {
        return PSBT_ERR_INVALID;
    }

    if (input_idx >= psbt->num_inputs) {
        wally_psbt_free(psbt);
        return PSBT_ERR_INVALID;
    }

    uint32_t requested = psbt->inputs[input_idx].sighash;
    if (requested != 0 && requested != SIGHASH_ALL && requested != PSBT_SIGHASH_ALL_UNIFIED) {
        wally_psbt_free(psbt);
        return PSBT_ERR_SIGHASH_TYPE;
    }

    struct wally_tx *tx = NULL;
    ret = wally_psbt_extract(psbt, WALLY_PSBT_EXTRACT_NON_FINAL, &tx);
    if (ret != WALLY_OK || !tx) {
        wally_psbt_free(psbt);
        return PSBT_ERR_INVALID;
    }

    if (requested == PSBT_SIGHASH_ALL_UNIFIED) {
        ret = unified_sighash_from_psbt(psbt, tx, input_idx, sighash);
    } else {
        unsigned char script[256];
        size_t script_len = 0;
        ret = wally_psbt_get_input_signing_script(psbt, input_idx, script, sizeof(script),
                                                  &script_len);
        if (ret == WALLY_OK) {
            ret = wally_psbt_get_input_signature_hash(psbt, input_idx, tx, script, script_len, 0,
                                                      sighash, SHA256_LEN);
        }
        ret = ret == WALLY_OK ? 0 : -1;
    }
    wally_tx_free(tx);
    wally_psbt_free(psbt);
    if (ret != 0) {
        memset(sighash, 0, 32);
        return PSBT_ERR_INVALID;
    }
    *sighash_type = (uint8_t)requested;
    return 0;
}

int psbt_add_taproot_signature(const char *base64_in, size_t input_idx, const uint8_t *sig,
                               size_t sig_len, char *base64_out, size_t out_len) {
    if (!base64_in || !sig || !base64_out || out_len == 0) {
        return -1;
    }
    if (sig_len != 64 && sig_len != 65) {
        return -1;
    }

    struct wally_psbt *psbt = NULL;
    int ret = wally_psbt_from_base64(base64_in, 0, &psbt);
    if (ret != WALLY_OK || !psbt) {
        return -1;
    }

    if (input_idx >= psbt->num_inputs) {
        wally_psbt_free(psbt);
        return -1;
    }

    ret = wally_psbt_input_set_taproot_signature(&psbt->inputs[input_idx], sig, sig_len);
    if (ret != WALLY_OK) {
        wally_psbt_free(psbt);
        return -1;
    }

    char *result = NULL;
    ret = wally_psbt_to_base64(psbt, 0, &result);
    wally_psbt_free(psbt);

    if (ret != WALLY_OK || !result) {
        return -1;
    }

    size_t result_len = strlen(result);
    if (result_len >= out_len) {
        wally_free_string(result);
        return -1;
    }

    memcpy(base64_out, result, result_len + 1);
    wally_free_string(result);
    return 0;
}
