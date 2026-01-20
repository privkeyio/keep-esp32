#include "psbt_fraud.h"
#include "crypto_asm.h"
#include <wally_psbt.h>
#include <wally_script.h>
#include <wally_transaction.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

static psbt_script_type_t wally_to_script_type(size_t wally_type) {
    switch (wally_type) {
    case WALLY_SCRIPT_TYPE_P2PKH:
        return SCRIPT_TYPE_P2PKH;
    case WALLY_SCRIPT_TYPE_P2SH:
        return SCRIPT_TYPE_P2SH;
    case WALLY_SCRIPT_TYPE_P2WPKH:
        return SCRIPT_TYPE_P2WPKH;
    case WALLY_SCRIPT_TYPE_P2WSH:
        return SCRIPT_TYPE_P2WSH;
    case WALLY_SCRIPT_TYPE_P2TR:
        return SCRIPT_TYPE_P2TR;
    case WALLY_SCRIPT_TYPE_OP_RETURN:
        return SCRIPT_TYPE_OP_RETURN;
    default:
        return SCRIPT_TYPE_UNKNOWN;
    }
}

const char *psbt_fraud_script_type_name(psbt_script_type_t type) {
    switch (type) {
    case SCRIPT_TYPE_P2PKH:
        return "P2PKH";
    case SCRIPT_TYPE_P2SH:
        return "P2SH";
    case SCRIPT_TYPE_P2WPKH:
        return "P2WPKH";
    case SCRIPT_TYPE_P2WSH:
        return "P2WSH";
    case SCRIPT_TYPE_P2TR:
        return "P2TR";
    case SCRIPT_TYPE_OP_RETURN:
        return "OP_RETURN";
    default:
        return "UNKNOWN";
    }
}

static uint64_t get_output_amount(const struct wally_psbt *psbt, size_t idx) {
    if (psbt->tx && idx < psbt->tx->num_outputs) {
        return psbt->tx->outputs[idx].satoshi;
    }
    if (idx < psbt->num_outputs && psbt->outputs[idx].has_amount) {
        return psbt->outputs[idx].amount;
    }
    return 0;
}

static int get_output_script(const struct wally_psbt *psbt, size_t idx,
                             const unsigned char **script, size_t *script_len) {
    if (psbt->tx && idx < psbt->tx->num_outputs) {
        *script = psbt->tx->outputs[idx].script;
        *script_len = psbt->tx->outputs[idx].script_len;
        return 0;
    }
    if (idx < psbt->num_outputs && psbt->outputs[idx].script) {
        *script = psbt->outputs[idx].script;
        *script_len = psbt->outputs[idx].script_len;
        return 0;
    }
    return -1;
}

static int analyze_fees_internal(const struct wally_psbt *psbt, uint64_t total_in_sats,
                                 psbt_fee_analysis_t *analysis) {
    memset(analysis, 0, sizeof(*analysis));

    uint64_t total_out = 0;
    for (size_t i = 0; i < psbt->num_outputs; i++) {
        uint64_t amount = get_output_amount(psbt, i);
        if (total_out > UINT64_MAX - amount) {
            return PSBT_FRAUD_ERR_OVERFLOW;
        }
        total_out += amount;
    }

    if (total_in_sats < total_out) {
        return PSBT_FRAUD_ERR_INVALID_FEE;
    }

    analysis->fee_sats = total_in_sats - total_out;
    analysis->send_amount_sats = total_out;

    if (analysis->send_amount_sats > 0) {
        uint64_t percent;
        if (analysis->fee_sats <= UINT64_MAX / 10000) {
            percent = (analysis->fee_sats * 10000) / analysis->send_amount_sats;
        } else {
            percent = (analysis->fee_sats / analysis->send_amount_sats) * 10000;
        }
        analysis->fee_percent_x100 = (percent > UINT32_MAX) ? UINT32_MAX : (uint32_t)percent;
    }

    if (analysis->fee_sats > PSBT_FRAUD_FEE_WARN_ABS_SATS) {
        analysis->fee_warning = true;
        int ret =
            snprintf(analysis->warning_msg, sizeof(analysis->warning_msg), "Fee exceeds %llu sats",
                     (unsigned long long)PSBT_FRAUD_FEE_WARN_ABS_SATS);
        if (ret < 0 || (size_t)ret >= sizeof(analysis->warning_msg)) {
            memcpy(analysis->warning_msg, "High fee", 9);
        }
    } else if (analysis->fee_percent_x100 > PSBT_FRAUD_FEE_WARN_PERCENT * 100) {
        analysis->fee_warning = true;
        int ret = snprintf(analysis->warning_msg, sizeof(analysis->warning_msg),
                           "Fee is %" PRIu32 ".%02" PRIu32 "%% of amount",
                           analysis->fee_percent_x100 / 100, analysis->fee_percent_x100 % 100);
        if (ret < 0 || (size_t)ret >= sizeof(analysis->warning_msg)) {
            memcpy(analysis->warning_msg, "High fee %", 11);
        }
    }

    return 0;
}

static int check_dust_internal(const struct wally_psbt *psbt, psbt_dust_analysis_t *analysis) {
    memset(analysis, 0, sizeof(*analysis));

    if (psbt->num_outputs > PSBT_FRAUD_MAX_OUTPUTS) {
        return PSBT_FRAUD_ERR_TOO_MANY_IO;
    }

    for (size_t i = 0; i < psbt->num_outputs; i++) {
        uint64_t amount = get_output_amount(psbt, i);

        const unsigned char *script = NULL;
        size_t script_len = 0;
        if (get_output_script(psbt, i, &script, &script_len) == 0 && script_len > 0) {
            size_t script_type = 0;
            wally_scriptpubkey_get_type(script, script_len, &script_type);
            if (script_type == WALLY_SCRIPT_TYPE_OP_RETURN) {
                continue;
            }
        }

        if (amount > 0 && amount < PSBT_FRAUD_DUST_LIMIT_SATS) {
            analysis->has_dust = true;
            if (analysis->dust_count < PSBT_FRAUD_MAX_OUTPUTS) {
                analysis->dust_indices[analysis->dust_count] = i;
                analysis->dust_amounts[analysis->dust_count] = amount;
                analysis->dust_count++;
            }
        }
    }

    return 0;
}

static int analyze_scripts_internal(const struct wally_psbt *psbt,
                                    psbt_script_analysis_t *analysis) {
    memset(analysis, 0, sizeof(*analysis));

    if (psbt->num_inputs > PSBT_FRAUD_MAX_INPUTS || psbt->num_outputs > PSBT_FRAUD_MAX_OUTPUTS) {
        return PSBT_FRAUD_ERR_TOO_MANY_IO;
    }

    analysis->input_count = psbt->num_inputs;
    analysis->output_count = psbt->num_outputs;

    if (!psbt->inputs) {
        return PSBT_FRAUD_ERR_PARSE;
    }

    for (size_t i = 0; i < psbt->num_inputs; i++) {
        const struct wally_psbt_input *inp = &psbt->inputs[i];
        const unsigned char *script = NULL;
        size_t script_len = 0;

        if (inp->witness_utxo) {
            script = inp->witness_utxo->script;
            script_len = inp->witness_utxo->script_len;
        } else if (inp->utxo && inp->index < inp->utxo->num_outputs) {
            script = inp->utxo->outputs[inp->index].script;
            script_len = inp->utxo->outputs[inp->index].script_len;
        }

        if (script && script_len > 0) {
            size_t wally_type = 0;
            wally_scriptpubkey_get_type(script, script_len, &wally_type);
            analysis->input_types[i] = wally_to_script_type(wally_type);
            if (analysis->input_types[i] == SCRIPT_TYPE_UNKNOWN) {
                analysis->has_unknown_script = true;
            }
        } else {
            analysis->input_types[i] = SCRIPT_TYPE_UNKNOWN;
            analysis->has_unknown_script = true;
        }
    }

    for (size_t i = 0; i < psbt->num_outputs; i++) {
        const unsigned char *script = NULL;
        size_t script_len = 0;

        if (get_output_script(psbt, i, &script, &script_len) == 0 && script_len > 0) {
            size_t wally_type = 0;
            wally_scriptpubkey_get_type(script, script_len, &wally_type);
            analysis->output_types[i] = wally_to_script_type(wally_type);
            if (analysis->output_types[i] == SCRIPT_TYPE_UNKNOWN) {
                analysis->has_unknown_script = true;
            }
            if (analysis->output_types[i] == SCRIPT_TYPE_OP_RETURN) {
                analysis->has_op_return = true;
            }
        } else {
            analysis->output_types[i] = SCRIPT_TYPE_UNKNOWN;
            analysis->has_unknown_script = true;
        }
    }

    return 0;
}

int psbt_fraud_analyze_fees(const char *base64, uint64_t total_in_sats,
                            psbt_fee_analysis_t *analysis) {
    if (!base64 || !analysis) {
        return PSBT_FRAUD_ERR_PARAMS;
    }

    struct wally_psbt *psbt = NULL;
    if (wally_psbt_from_base64(base64, 0, &psbt) != WALLY_OK || !psbt) {
        return PSBT_FRAUD_ERR_PARSE;
    }

    int ret = analyze_fees_internal(psbt, total_in_sats, analysis);
    wally_psbt_free(psbt);
    return ret;
}

int psbt_fraud_check_dust(const char *base64, psbt_dust_analysis_t *analysis) {
    if (!base64 || !analysis) {
        return PSBT_FRAUD_ERR_PARAMS;
    }

    struct wally_psbt *psbt = NULL;
    if (wally_psbt_from_base64(base64, 0, &psbt) != WALLY_OK || !psbt) {
        return PSBT_FRAUD_ERR_PARSE;
    }

    int ret = check_dust_internal(psbt, analysis);
    wally_psbt_free(psbt);
    return ret;
}

int psbt_fraud_analyze_scripts(const char *base64, psbt_script_analysis_t *analysis) {
    if (!base64 || !analysis) {
        return PSBT_FRAUD_ERR_PARAMS;
    }

    struct wally_psbt *psbt = NULL;
    if (wally_psbt_from_base64(base64, 0, &psbt) != WALLY_OK || !psbt) {
        return PSBT_FRAUD_ERR_PARSE;
    }

    int ret = analyze_scripts_internal(psbt, analysis);
    wally_psbt_free(psbt);
    return ret;
}

static bool extract_keypath_fingerprint(const struct wally_map *keypaths,
                                        uint8_t fingerprint[PSBT_FRAUD_FINGERPRINT_LEN],
                                        uint32_t *path, size_t *path_len) {
    if (!keypaths || keypaths->num_items == 0) {
        return false;
    }

    uint8_t temp_fp[PSBT_FRAUD_FINGERPRINT_LEN] = {0};
    uint32_t temp_path[5] = {0};
    size_t temp_path_len = 0;
    uint32_t found = 0;

    for (size_t i = 0; i < keypaths->num_items; i++) {
        const unsigned char *value = keypaths->items[i].value;
        size_t value_len = keypaths->items[i].value_len;

        uint32_t valid = (value != NULL && value_len >= PSBT_FRAUD_FINGERPRINT_LEN) ? 1 : 0;
        uint32_t use_this = valid & ~found;

        uint8_t candidate_fp[PSBT_FRAUD_FINGERPRINT_LEN] = {0};
        uint32_t candidate_path[5] = {0};
        size_t candidate_path_len = 0;

        if (valid) {
            memcpy(candidate_fp, value, PSBT_FRAUD_FINGERPRINT_LEN);
            size_t remaining = value_len - PSBT_FRAUD_FINGERPRINT_LEN;
            size_t num_elements = remaining / sizeof(uint32_t);
            if (num_elements > 5)
                num_elements = 5;
            for (size_t j = 0; j < num_elements; j++) {
                memcpy(&candidate_path[j],
                       value + PSBT_FRAUD_FINGERPRINT_LEN + (j * sizeof(uint32_t)),
                       sizeof(uint32_t));
            }
            candidate_path_len = num_elements;
        }

        ct_select_bytes(temp_fp, temp_fp, candidate_fp, PSBT_FRAUD_FINGERPRINT_LEN, use_this);
        for (size_t j = 0; j < 5; j++) {
            temp_path[j] = ct_select32(temp_path[j], candidate_path[j], use_this);
        }
        temp_path_len =
            ct_select32((uint32_t)temp_path_len, (uint32_t)candidate_path_len, use_this);
        found |= valid;
    }

    if (found) {
        memcpy(fingerprint, temp_fp, PSBT_FRAUD_FINGERPRINT_LEN);
        if (path && path_len) {
            memcpy(path, temp_path, sizeof(temp_path));
            *path_len = temp_path_len;
        }
    }
    return found != 0;
}

static int analyze_change_internal(const struct wally_psbt *psbt, const uint8_t *wallet_fingerprint,
                                   psbt_change_analysis_t *analysis) {
    memset(analysis, 0, sizeof(*analysis));

    if (psbt->num_outputs > PSBT_FRAUD_MAX_OUTPUTS) {
        return PSBT_FRAUD_ERR_TOO_MANY_IO;
    }

    analysis->output_count = psbt->num_outputs;

    for (size_t i = 0; i < psbt->num_outputs; i++) {
        psbt_output_analysis_t *out = &analysis->outputs[i];
        out->amount_sats = get_output_amount(psbt, i);

        const unsigned char *script = NULL;
        size_t script_len = 0;
        if (get_output_script(psbt, i, &script, &script_len) == 0 && script_len > 0) {
            size_t wally_type = 0;
            wally_scriptpubkey_get_type(script, script_len, &wally_type);
            out->script_type = wally_to_script_type(wally_type);
        }

        struct wally_psbt_output *psbt_out = &psbt->outputs[i];

        uint8_t fp[PSBT_FRAUD_FINGERPRINT_LEN];
        bool found = extract_keypath_fingerprint(&psbt_out->keypaths, fp, out->derivation_path,
                                                 &out->derivation_len) ||
                     extract_keypath_fingerprint(&psbt_out->taproot_leaf_paths, fp,
                                                 out->derivation_path, &out->derivation_len);

        if (found) {
            out->has_derivation = true;
            memcpy(out->fingerprint, fp, PSBT_FRAUD_FINGERPRINT_LEN);

            if (wallet_fingerprint &&
                ct_compare(fp, wallet_fingerprint, PSBT_FRAUD_FINGERPRINT_LEN) == 0) {
                out->is_change = true;
                analysis->change_count++;
            } else {
                analysis->external_count++;
            }
        } else {
            analysis->external_count++;
        }
    }

    return 0;
}

int psbt_fraud_analyze_change(const char *base64, const uint8_t *wallet_fingerprint,
                              psbt_change_analysis_t *analysis) {
    if (!base64 || !analysis) {
        return PSBT_FRAUD_ERR_PARAMS;
    }

    struct wally_psbt *psbt = NULL;
    if (wally_psbt_from_base64(base64, 0, &psbt) != WALLY_OK || !psbt) {
        return PSBT_FRAUD_ERR_PARSE;
    }

    int ret = analyze_change_internal(psbt, wallet_fingerprint, analysis);
    wally_psbt_free(psbt);
    return ret;
}

int psbt_fraud_analyze(const char *base64, uint64_t total_in_sats,
                       const uint8_t *wallet_fingerprint, psbt_fraud_analysis_t *analysis) {
    if (!base64 || !analysis) {
        return PSBT_FRAUD_ERR_PARAMS;
    }

    memset(analysis, 0, sizeof(*analysis));

    struct wally_psbt *psbt = NULL;
    if (wally_psbt_from_base64(base64, 0, &psbt) != WALLY_OK || !psbt) {
        return PSBT_FRAUD_ERR_PARSE;
    }

    int ret = analyze_fees_internal(psbt, total_in_sats, &analysis->fee);
    if (ret == 0) {
        ret = check_dust_internal(psbt, &analysis->dust);
    }
    if (ret == 0) {
        ret = analyze_scripts_internal(psbt, &analysis->scripts);
    }
    if (ret == 0) {
        ret = analyze_change_internal(psbt, wallet_fingerprint, &analysis->change);
    }

    wally_psbt_free(psbt);

    if (ret != 0) {
        return ret;
    }

    if (analysis->fee.fee_warning) {
        analysis->flags |= PSBT_FRAUD_FLAG_HIGH_FEE;
    }
    if (analysis->dust.has_dust) {
        analysis->flags |= PSBT_FRAUD_FLAG_DUST_OUTPUT;
    }
    if (analysis->scripts.has_unknown_script) {
        analysis->flags |= PSBT_FRAUD_FLAG_UNKNOWN_SCRIPT;
    }
    if (analysis->scripts.has_op_return) {
        analysis->flags |= PSBT_FRAUD_FLAG_OP_RETURN;
    }
    if (wallet_fingerprint && analysis->change.change_count == 0) {
        analysis->flags |= PSBT_FRAUD_FLAG_NO_CHANGE;
    }
    if (wallet_fingerprint && analysis->change.output_count > 0 &&
        analysis->change.external_count == analysis->change.output_count) {
        analysis->flags |= PSBT_FRAUD_FLAG_ALL_EXTERNAL;
    }

    uint64_t change_total = 0;
    for (size_t i = 0; i < analysis->change.output_count; i++) {
        if (analysis->change.outputs[i].is_change) {
            uint64_t amount = analysis->change.outputs[i].amount_sats;
            if (change_total > UINT64_MAX - amount) {
                secure_memzero(analysis, sizeof(*analysis));
                return PSBT_FRAUD_ERR_OVERFLOW;
            }
            change_total += amount;
        }
    }
    analysis->fee.change_amount_sats = change_total;

    if (analysis->fee.send_amount_sats >= change_total) {
        analysis->fee.send_amount_sats -= change_total;
    } else {
        analysis->fee.send_amount_sats = 0;
    }

    return 0;
}

secresult_t psbt_fraud_check_secure(const psbt_fraud_analysis_t *analysis, bool allow_high_fee,
                                    bool allow_dust, bool allow_unknown_scripts,
                                    bool allow_op_return, bool allow_no_change,
                                    bool allow_all_external) {
    if (!analysis) {
        return SECRESULT_ERR_POLICY_DENIED;
    }

    if ((analysis->flags & PSBT_FRAUD_FLAG_HIGH_FEE) && !allow_high_fee) {
        return SECRESULT_ERR_HIGH_FEE;
    }

    if ((analysis->flags & PSBT_FRAUD_FLAG_DUST_OUTPUT) && !allow_dust) {
        return SECRESULT_ERR_DUST_OUTPUT;
    }

    if ((analysis->flags & PSBT_FRAUD_FLAG_UNKNOWN_SCRIPT) && !allow_unknown_scripts) {
        return SECRESULT_ERR_UNKNOWN_SCRIPT;
    }

    if ((analysis->flags & PSBT_FRAUD_FLAG_OP_RETURN) && !allow_op_return) {
        return SECRESULT_ERR_OP_RETURN;
    }

    if ((analysis->flags & PSBT_FRAUD_FLAG_NO_CHANGE) && !allow_no_change) {
        return SECRESULT_ERR_NO_CHANGE;
    }

    if ((analysis->flags & PSBT_FRAUD_FLAG_ALL_EXTERNAL) && !allow_all_external) {
        return SECRESULT_ERR_ALL_EXTERNAL;
    }

    return SECRESULT_TRUE;
}
