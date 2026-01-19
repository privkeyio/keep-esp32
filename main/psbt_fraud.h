#ifndef PSBT_FRAUD_H
#define PSBT_FRAUD_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "secresult.h"

#define PSBT_FRAUD_MAX_OUTPUTS       16
#define PSBT_FRAUD_MAX_INPUTS        16
#define PSBT_FRAUD_WARNING_MSG_LEN   64
#define PSBT_FRAUD_DERIVATION_LEN    20
#define PSBT_FRAUD_FINGERPRINT_LEN   4

#define PSBT_FRAUD_FEE_WARN_PERCENT  10
#define PSBT_FRAUD_FEE_WARN_ABS_SATS 100000
#define PSBT_FRAUD_DUST_LIMIT_SATS   546

#define PSBT_FRAUD_ERR_PARSE         -1
#define PSBT_FRAUD_ERR_PARAMS        -2
#define PSBT_FRAUD_ERR_TOO_MANY_IO   -3
#define PSBT_FRAUD_ERR_OVERFLOW      -4
#define PSBT_FRAUD_ERR_INVALID_FEE   -5

typedef enum {
    SCRIPT_TYPE_UNKNOWN = 0,
    SCRIPT_TYPE_P2PKH,
    SCRIPT_TYPE_P2SH,
    SCRIPT_TYPE_P2WPKH,
    SCRIPT_TYPE_P2WSH,
    SCRIPT_TYPE_P2TR,
    SCRIPT_TYPE_OP_RETURN
} psbt_script_type_t;

typedef struct {
    bool is_change;
    bool has_derivation;
    uint8_t fingerprint[PSBT_FRAUD_FINGERPRINT_LEN];
    uint32_t derivation_path[5];
    size_t derivation_len;
    uint64_t amount_sats;
    psbt_script_type_t script_type;
} psbt_output_analysis_t;

typedef struct {
    uint64_t fee_sats;
    uint64_t send_amount_sats;
    uint64_t change_amount_sats;
    uint32_t fee_percent_x100;
    bool fee_warning;
    char warning_msg[PSBT_FRAUD_WARNING_MSG_LEN];
} psbt_fee_analysis_t;

typedef struct {
    bool has_dust;
    size_t dust_count;
    size_t dust_indices[PSBT_FRAUD_MAX_OUTPUTS];
    uint64_t dust_amounts[PSBT_FRAUD_MAX_OUTPUTS];
} psbt_dust_analysis_t;

typedef struct {
    psbt_script_type_t input_types[PSBT_FRAUD_MAX_INPUTS];
    psbt_script_type_t output_types[PSBT_FRAUD_MAX_OUTPUTS];
    size_t input_count;
    size_t output_count;
    bool has_unknown_script;
    bool has_op_return;
} psbt_script_analysis_t;

typedef struct {
    psbt_output_analysis_t outputs[PSBT_FRAUD_MAX_OUTPUTS];
    size_t output_count;
    size_t change_count;
    size_t external_count;
} psbt_change_analysis_t;

typedef enum {
    PSBT_FRAUD_FLAG_NONE          = 0,
    PSBT_FRAUD_FLAG_HIGH_FEE      = (1 << 0),
    PSBT_FRAUD_FLAG_DUST_OUTPUT   = (1 << 1),
    PSBT_FRAUD_FLAG_UNKNOWN_SCRIPT= (1 << 2),
    PSBT_FRAUD_FLAG_NO_CHANGE     = (1 << 3),
    PSBT_FRAUD_FLAG_OP_RETURN     = (1 << 4),
    PSBT_FRAUD_FLAG_ALL_EXTERNAL  = (1 << 5)
} psbt_fraud_flags_t;

typedef struct {
    uint32_t flags;
    psbt_fee_analysis_t fee;
    psbt_dust_analysis_t dust;
    psbt_script_analysis_t scripts;
    psbt_change_analysis_t change;
} psbt_fraud_analysis_t;

int psbt_fraud_analyze_fees(const char *base64,
                            uint64_t total_in_sats,
                            psbt_fee_analysis_t *analysis);

int psbt_fraud_check_dust(const char *base64,
                          psbt_dust_analysis_t *analysis);

int psbt_fraud_analyze_scripts(const char *base64,
                               psbt_script_analysis_t *analysis);

int psbt_fraud_analyze_change(const char *base64,
                              const uint8_t *wallet_fingerprint,
                              psbt_change_analysis_t *analysis);

int psbt_fraud_analyze(const char *base64,
                       uint64_t total_in_sats,
                       const uint8_t *wallet_fingerprint,
                       psbt_fraud_analysis_t *analysis);

secresult_t psbt_fraud_check_secure(const psbt_fraud_analysis_t *analysis,
                                    bool allow_high_fee,
                                    bool allow_dust,
                                    bool allow_unknown_scripts,
                                    bool allow_op_return,
                                    bool allow_no_change,
                                    bool allow_all_external);

const char *psbt_fraud_script_type_name(psbt_script_type_t type);

#endif
