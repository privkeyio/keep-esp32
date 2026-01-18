#include "psbt.h"
#include <wally_core.h>
#include <wally_psbt.h>
#include <wally_transaction.h>
#include <string.h>

#define SHA256_LEN 32

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
        struct wally_psbt_input *inp = &psbt->inputs[i];
        if (inp->witness_utxo) {
            summary->total_in_sats += inp->witness_utxo->satoshi;
        } else if (inp->utxo && inp->utxo->outputs && inp->index < inp->utxo->num_outputs) {
            summary->total_in_sats += inp->utxo->outputs[inp->index].satoshi;
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

int psbt_get_sighash(const char *base64, size_t input_idx, uint8_t sighash[32]) {
    if (!base64 || !sighash) {
        return -1;
    }
    memset(sighash, 0, 32);

    struct wally_psbt *psbt = NULL;
    int ret = wally_psbt_from_base64(base64, 0, &psbt);
    if (ret != WALLY_OK || !psbt) {
        return -1;
    }

    if (input_idx >= psbt->num_inputs) {
        wally_psbt_free(psbt);
        return -1;
    }

    struct wally_tx *tx = NULL;
    ret = wally_psbt_extract(psbt, WALLY_PSBT_EXTRACT_NON_FINAL, &tx);
    if (ret != WALLY_OK || !tx) {
        wally_psbt_free(psbt);
        return -1;
    }

    unsigned char script[256];
    size_t script_len = 0;
    ret = wally_psbt_get_input_signing_script(psbt, input_idx, script, sizeof(script), &script_len);
    if (ret != WALLY_OK) {
        wally_tx_free(tx);
        wally_psbt_free(psbt);
        return -1;
    }

    ret = wally_psbt_get_input_signature_hash(psbt, input_idx, tx, script, script_len, 0, sighash,
                                              SHA256_LEN);
    wally_tx_free(tx);
    wally_psbt_free(psbt);
    return (ret == WALLY_OK) ? 0 : -1;
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
