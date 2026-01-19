#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "psbt_fraud.h"
#include <wally_core.h>
#include <wally_psbt.h>
#include <wally_transaction.h>
#include <wally_script.h>

#define TEST(name) printf("  TEST: %s\n", name)
#define PASS()     printf("    PASS\n")
#define FAIL(msg)                      \
    do {                               \
        printf("    FAIL: %s\n", msg); \
        return 1;                      \
    } while (0)

static const char *PSBT_BIP174_P2PKH =
    "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+"
    "////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF"
    "5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQDMAQAAAAKJo8ceq00g4Dcbu6TMaY+ilclG"
    "OvouOX+FM8y2L5Vn5QEAAAAXFgAUvhjRUqmwEgOdrz2n3k9TNJ7suYX/////hviqQ6cd"
    "/xRIiTpTCnI372tGCLuy3S0BceY67GpIkLQBAAAAFxYAFP4+nvGnRel02QLENVlDq8s0"
    "vVNT/////wIAwusLAAAAABl2qRSFz/EJf9ngCLs0r3CcYhl7OJeKSIiscv74TiwAAAAX"
    "qRQzlyW6Ie/WKsdTqbzQZ9bHpqOdBYcAAAAAAAAA";

static const char *PSBT_BIP174_SIGNED =
    "cHNidP8BAKACAAAAAqsJSaCMWvfEm4IS9Bfi8Vqz9cM9zxU4IagTn4d6W3vkAAAAAA"
    "D+////qwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QBAAAAAP7///8CYDvq"
    "CwAAAAAZdqkUdopAu9dAy+gdmI5x3ipNXHE5ax2IrI4kAAAAAAAAGXapFG9GILVT+g"
    "lechue4O/p+gOcykWXiKwAAAAAAAEHakcwRAIgR1lmF5fAGwNrJZKJSGhiGDR9iYZL"
    "cZ4ff89X0eURZYcCIFMJ6r9Wqk2Ikf/REf3xM286KdqGbX+EhtdVRs7tr5MZASEDXNxh"
    "/HupccC1AaZGoqg7ECy0OIEhfKaC3Ibi1z+ogpIAAQEgAOH1BQAAAAAXqRQ1RebjO4Ms"
    "RwUPJNPuuTycA5SLx4cBBBYAFIXRNTfy4mVAWjTbr6nj3aAfuCMIAAAA";

static const char *PSBT_P2TR =
    "cHNidP8BAFICAAAAASd0Srq/MCf+DWzyOpbu4u+xiO9SMBlUWFiD5ptmJLJCAAAAAAD/"
    "////AUjmBSoBAAAAFgAUdo4e60z0IIZgM/gKzv8PlyB0SWkAAAAAAAEBKwDyBSoBAAAA"
    "IlEgWiws9bUs8x+DrS6Npj/wMYPs2PYJx1EK6KSOA5EKB1cBE0C7U+yRe62dkGrxuocY"
    "HEi4as5aritTYFpyXKdGJWMUdvxvW67a9PLuD0d/NvWPOXDVuCc7fkl7l68uPxJcl680"
    "IRb+NJBkyY1uKoU/o8mxK9izBKGcGVxg76fuI5MEbT+iMhkAdystp1YAAIABAACAAAAAgAEA"
    "AAAAAAAAARcg/jSQZMmNbiqFP6PJsSvYswShnBlcYO+n7iOTBG0/ojIAIgIDa3cqbbdNh1PJ"
    "ioJ5WN5seKszEhCfN9PgMESEJC7Oc9gYdystp1QAAIABAACAAAAAgAAAAAAAAAAAAA==";

static const char *PSBT_2_INPUTS_2_OUTPUTS =
    "cHNidP8BAKACAAAAAqsJSaCMWvfEm4IS9Bfi8Vqz9cM9zxU4IagTn4d6W3vkAAAAAA"
    "D+////qwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QBAAAAAP7///8CYDvq"
    "CwAAAAAZdqkUdopAu9dAy+gdmI5x3ipNXHE5ax2IrI4kAAAAAAAAGXapFG9GILVT+g"
    "lechue4O/p+gOcykWXiKwAAAAAAAEA3wIAAAABJoFxNx7f8oXpN63upLN7eAAMBWbLs"
    "61kZBcTykIXG/YAAAAAakcwRAIgcLIkUSPmv0dNYMW1DAQ9TGkaXSQ18Jo0p2YqncJR"
    "eQoCIAEynKnazygL3zB0DsA5BCJCLIHLRYOUV663b8Eu3ZWzASECZX0RjTNXuOD0ws1G"
    "23s59tnDjZpwq8ubLeXcjb/kzjH+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9Uh"
    "pGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQEgAOH1"
    "BQAAAAAXqRQ1RebjO4MsRwUPJNPuuTycA5SLx4cBBBYAFIXRNTfy4mVAWjTbr6nj3aAf"
    "uCMIAAAA";

static const char *PSBT_P2SH_P2WSH_MULTISIG =
    "cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/"
    "pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+"
    "uHIgIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUZGMEMCIAQktY7/"
    "qqaU4VWepck7v9SokGQiQFXN8HC2dxRpRC0HAh9cjrD+plFtYLisszrWTt5g6Hhb+zqpS5m9+GFR25qaAQEEIgAgdx/"
    "RitRZZm3Unz1WTj28QvTIR3TjYK2haBao7UiNVoEBBUdSIQOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/"
    "HkjUdUGEQ1W9RiED3lXR4drIBeP4pYwfv5uUwC89uq/hJ/"
    "78pJlfJvggg71SriIGA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb1GELSmumcAAACAAAAAgAQAAIAiBgPeVdHh"
    "2sgF4/iljB+/m5TALz26r+En/vykmV8m+CCDvRC0prpnAAAAgAAAAIAFAACAAAA=";

static const char *PSBT_P2WSH_2OF2 =
    "cHNidP8BAFICAAAAAZ38ZijCbFiZ/hvT3DOGZb/VXXraEPYiCXPfLTht7BJ2AQAAAAD/////"
    "AfA9zR0AAAAAFgAUezoAv9wU0neVwrdJAdCdpu8TNXkAAAAATwEENYfPAto/"
    "0AiAAAAAlwSLGtBEWx7IJ1UXcnyHtOTrwYogP/"
    "oPlMAVZr046QADUbdDiH7h1A3DKmBDck8tZFmztaTXPa7I+64EcvO8Q+IM2QxqT64AAIAAAACATwEENYfPAto/"
    "0AiAAAABuQRSQnE5zXjCz/"
    "JES+NTzVhgXj5RMoXlKLQH+uP2FzUD0wpel8itvFV9rCrZp+"
    "OcFyLrrGnmaLbyZnzB1nHIPKsM2QxqT64AAIABAACAAAEBKwBlzR0AAAAAIgAgLFSGEmxJeAeagU4TcV1l82RZ5NbMre0m"
    "bQUIZFuvpjIBBUdSIQKdoSzbWyNWkrkVNq/"
    "v5ckcOrlHPY5DtTODarRWKZyIcSEDNys0I07Xz5wf6l0F1EFVeSe+"
    "lUKxYusC4ass6AIkwAtSriIGAp2hLNtbI1aSuRU2r+/"
    "lyRw6uUc9jkO1M4NqtFYpnIhxENkMak+uAACAAAAAgAAAAAAiBgM3KzQjTtfPnB/"
    "qXQXUQVV5J76VQrFi6wLhqyzoAiTACxDZDGpPrgAAgAEAAIAAAAAAACICA57/"
    "H1R6HV+S36K6evaslxpL0DukpzSwMVaiVritOh75EO3kXMUAAACAAAAAgAEAAIAA";

static int test_analyze_fees_basic(void) {
    TEST("psbt_fraud_analyze_fees - basic calculation");

    psbt_fee_analysis_t analysis;
    int ret = psbt_fraud_analyze_fees(PSBT_BIP174_P2PKH, 200000000, &analysis);
    if (ret != 0)
        FAIL("parse failed");

    uint64_t expected_out = 99999699 + 100000000;
    if (analysis.send_amount_sats != expected_out)
        FAIL("wrong send amount");

    uint64_t expected_fee = 200000000 - expected_out;
    if (analysis.fee_sats != expected_fee)
        FAIL("wrong fee");

    PASS();
    return 0;
}

static int test_analyze_fees_high(void) {
    TEST("psbt_fraud_analyze_fees - high fee warning");

    psbt_fee_analysis_t analysis;
    int ret = psbt_fraud_analyze_fees(PSBT_BIP174_P2PKH, 500000000, &analysis);
    if (ret != 0)
        FAIL("parse failed");

    if (!analysis.fee_warning)
        FAIL("expected fee warning for high fee");

    PASS();
    return 0;
}

static int test_analyze_fees_overflow(void) {
    TEST("psbt_fraud_analyze_fees - input less than output");

    psbt_fee_analysis_t analysis;
    int ret = psbt_fraud_analyze_fees(PSBT_BIP174_P2PKH, 100, &analysis);
    if (ret != PSBT_FRAUD_ERR_INVALID_FEE)
        FAIL("expected invalid fee error");

    PASS();
    return 0;
}

static int test_analyze_fees_null(void) {
    TEST("psbt_fraud_analyze_fees - null parameters");

    psbt_fee_analysis_t analysis;
    if (psbt_fraud_analyze_fees(NULL, 100000, &analysis) != PSBT_FRAUD_ERR_PARAMS)
        FAIL("expected params error for null base64");

    if (psbt_fraud_analyze_fees(PSBT_BIP174_P2PKH, 100000, NULL) != PSBT_FRAUD_ERR_PARAMS)
        FAIL("expected params error for null analysis");

    PASS();
    return 0;
}

static int test_analyze_fees_invalid_psbt(void) {
    TEST("psbt_fraud_analyze_fees - invalid PSBT");

    psbt_fee_analysis_t analysis;
    if (psbt_fraud_analyze_fees("not_valid_base64", 100000, &analysis) != PSBT_FRAUD_ERR_PARSE)
        FAIL("expected parse error");

    if (psbt_fraud_analyze_fees("cHNidP8=", 100000, &analysis) != PSBT_FRAUD_ERR_PARSE)
        FAIL("expected parse error for truncated PSBT");

    PASS();
    return 0;
}

static int test_check_dust_none(void) {
    TEST("psbt_fraud_check_dust - no dust outputs");

    psbt_dust_analysis_t analysis;
    int ret = psbt_fraud_check_dust(PSBT_BIP174_P2PKH, &analysis);
    if (ret != 0)
        FAIL("parse failed");

    if (analysis.has_dust)
        FAIL("should have no dust");

    if (analysis.dust_count != 0)
        FAIL("dust count should be 0");

    PASS();
    return 0;
}

static int test_check_dust_null(void) {
    TEST("psbt_fraud_check_dust - null parameters");

    psbt_dust_analysis_t analysis;
    if (psbt_fraud_check_dust(NULL, &analysis) != PSBT_FRAUD_ERR_PARAMS)
        FAIL("expected params error for null base64");

    if (psbt_fraud_check_dust(PSBT_BIP174_P2PKH, NULL) != PSBT_FRAUD_ERR_PARAMS)
        FAIL("expected params error for null analysis");

    PASS();
    return 0;
}

static int test_analyze_scripts_p2pkh_p2sh(void) {
    TEST("psbt_fraud_analyze_scripts - P2PKH and P2SH outputs");

    psbt_script_analysis_t analysis;
    int ret = psbt_fraud_analyze_scripts(PSBT_BIP174_P2PKH, &analysis);
    if (ret != 0)
        FAIL("parse failed");

    if (analysis.output_count != 2)
        FAIL("expected 2 outputs");

    if (analysis.output_types[0] != SCRIPT_TYPE_P2PKH)
        FAIL("expected P2PKH for output 0");

    if (analysis.output_types[1] != SCRIPT_TYPE_P2SH)
        FAIL("expected P2SH for output 1");

    if (analysis.has_unknown_script)
        FAIL("should not have unknown scripts");

    if (analysis.has_op_return)
        FAIL("should not have OP_RETURN");

    PASS();
    return 0;
}

static int test_analyze_scripts_p2tr(void) {
    TEST("psbt_fraud_analyze_scripts - P2TR input and P2WPKH output");

    psbt_script_analysis_t analysis;
    int ret = psbt_fraud_analyze_scripts(PSBT_P2TR, &analysis);
    if (ret != 0)
        FAIL("parse failed");

    if (analysis.output_count != 1)
        FAIL("expected 1 output");

    if (analysis.output_types[0] != SCRIPT_TYPE_P2WPKH)
        FAIL("expected P2WPKH for output 0");

    if (analysis.input_count != 1)
        FAIL("expected 1 input");

    if (analysis.input_types[0] != SCRIPT_TYPE_P2TR)
        FAIL("expected P2TR for input 0");

    PASS();
    return 0;
}

static int test_analyze_scripts_null(void) {
    TEST("psbt_fraud_analyze_scripts - null parameters");

    psbt_script_analysis_t analysis;
    if (psbt_fraud_analyze_scripts(NULL, &analysis) != PSBT_FRAUD_ERR_PARAMS)
        FAIL("expected params error for null base64");

    if (psbt_fraud_analyze_scripts(PSBT_BIP174_P2PKH, NULL) != PSBT_FRAUD_ERR_PARAMS)
        FAIL("expected params error for null analysis");

    PASS();
    return 0;
}

static int test_analyze_change_with_fingerprint(void) {
    TEST("psbt_fraud_analyze_change - with matching fingerprint");

    uint8_t wallet_fp[4] = {0xed, 0xe4, 0x5c, 0xc5};

    psbt_change_analysis_t analysis;
    int ret = psbt_fraud_analyze_change(PSBT_P2WSH_2OF2, wallet_fp, &analysis);
    if (ret != 0)
        FAIL("parse failed");

    if (analysis.output_count != 1)
        FAIL("expected 1 output");

    if (analysis.change_count != 1)
        FAIL("expected 1 change output");

    if (!analysis.outputs[0].has_derivation)
        FAIL("output should have derivation");

    if (!analysis.outputs[0].is_change)
        FAIL("output should be marked as change");

    PASS();
    return 0;
}

static int test_analyze_change_no_fingerprint(void) {
    TEST("psbt_fraud_analyze_change - no fingerprint provided");

    psbt_change_analysis_t analysis;
    int ret = psbt_fraud_analyze_change(PSBT_BIP174_P2PKH, NULL, &analysis);
    if (ret != 0)
        FAIL("parse failed");

    if (analysis.change_count != 0)
        FAIL("should have 0 change without fingerprint match");

    PASS();
    return 0;
}

static int test_analyze_change_wrong_fingerprint(void) {
    TEST("psbt_fraud_analyze_change - non-matching fingerprint");

    uint8_t wrong_fp[4] = {0xde, 0xad, 0xbe, 0xef};

    psbt_change_analysis_t analysis;
    int ret = psbt_fraud_analyze_change(PSBT_BIP174_P2PKH, wrong_fp, &analysis);
    if (ret != 0)
        FAIL("parse failed");

    if (analysis.change_count != 0)
        FAIL("should have 0 change with wrong fingerprint");

    PASS();
    return 0;
}

static int test_analyze_change_null(void) {
    TEST("psbt_fraud_analyze_change - null parameters");

    psbt_change_analysis_t analysis;
    if (psbt_fraud_analyze_change(NULL, NULL, &analysis) != PSBT_FRAUD_ERR_PARAMS)
        FAIL("expected params error for null base64");

    if (psbt_fraud_analyze_change(PSBT_BIP174_P2PKH, NULL, NULL) != PSBT_FRAUD_ERR_PARAMS)
        FAIL("expected params error for null analysis");

    PASS();
    return 0;
}

static int test_full_analyze_clean(void) {
    TEST("psbt_fraud_analyze - clean transaction");

    psbt_fraud_analysis_t analysis;
    int ret = psbt_fraud_analyze(PSBT_BIP174_P2PKH, 200000000, NULL, &analysis);
    if (ret != 0)
        FAIL("parse failed");

    if (analysis.flags & PSBT_FRAUD_FLAG_DUST_OUTPUT)
        FAIL("should not have dust flag");

    if (analysis.flags & PSBT_FRAUD_FLAG_UNKNOWN_SCRIPT)
        FAIL("should not have unknown script flag");

    if (analysis.flags & PSBT_FRAUD_FLAG_OP_RETURN)
        FAIL("should not have OP_RETURN flag");

    PASS();
    return 0;
}

static int test_full_analyze_all_external(void) {
    TEST("psbt_fraud_analyze - all external outputs");

    uint8_t wrong_fp[4] = {0xde, 0xad, 0xbe, 0xef};

    psbt_fraud_analysis_t analysis;
    int ret = psbt_fraud_analyze(PSBT_BIP174_P2PKH, 200000000, wrong_fp, &analysis);
    if (ret != 0)
        FAIL("parse failed");

    if (!(analysis.flags & PSBT_FRAUD_FLAG_ALL_EXTERNAL))
        FAIL("should have all_external flag");

    if (!(analysis.flags & PSBT_FRAUD_FLAG_NO_CHANGE))
        FAIL("should have no_change flag");

    PASS();
    return 0;
}

static int test_full_analyze_null(void) {
    TEST("psbt_fraud_analyze - null parameters");

    psbt_fraud_analysis_t analysis;
    if (psbt_fraud_analyze(NULL, 100000, NULL, &analysis) != PSBT_FRAUD_ERR_PARAMS)
        FAIL("expected params error for null base64");

    if (psbt_fraud_analyze(PSBT_BIP174_P2PKH, 100000, NULL, NULL) != PSBT_FRAUD_ERR_PARAMS)
        FAIL("expected params error for null analysis");

    PASS();
    return 0;
}

static int test_script_type_name(void) {
    TEST("psbt_fraud_script_type_name");

    if (strcmp(psbt_fraud_script_type_name(SCRIPT_TYPE_P2PKH), "P2PKH") != 0)
        FAIL("P2PKH name wrong");

    if (strcmp(psbt_fraud_script_type_name(SCRIPT_TYPE_P2WPKH), "P2WPKH") != 0)
        FAIL("P2WPKH name wrong");

    if (strcmp(psbt_fraud_script_type_name(SCRIPT_TYPE_P2TR), "P2TR") != 0)
        FAIL("P2TR name wrong");

    if (strcmp(psbt_fraud_script_type_name(SCRIPT_TYPE_OP_RETURN), "OP_RETURN") != 0)
        FAIL("OP_RETURN name wrong");

    if (strcmp(psbt_fraud_script_type_name(SCRIPT_TYPE_UNKNOWN), "UNKNOWN") != 0)
        FAIL("UNKNOWN name wrong");

    PASS();
    return 0;
}

static int test_fraud_check_secure_clean(void) {
    TEST("psbt_fraud_check_secure - clean transaction");

    psbt_fraud_analysis_t analysis;
    int ret = psbt_fraud_analyze(PSBT_BIP174_P2PKH, 200000000, NULL, &analysis);
    if (ret != 0)
        FAIL("parse failed");

    secresult_t result = psbt_fraud_check_secure(&analysis, false, false, false, false, true, true);
    if (!SECRESULT_IS_TRUE(result))
        FAIL("should pass for clean transaction");

    PASS();
    return 0;
}

static int test_fraud_check_secure_high_fee(void) {
    TEST("psbt_fraud_check_secure - high fee rejection");

    psbt_fraud_analysis_t analysis;
    int ret = psbt_fraud_analyze(PSBT_BIP174_P2PKH, 500000000, NULL, &analysis);
    if (ret != 0)
        FAIL("parse failed");

    secresult_t result = psbt_fraud_check_secure(&analysis, false, true, true, true, true, true);
    if (result != SECRESULT_ERR_HIGH_FEE)
        FAIL("should reject high fee when not allowed");

    result = psbt_fraud_check_secure(&analysis, true, true, true, true, true, true);
    if (!SECRESULT_IS_TRUE(result))
        FAIL("should pass when high fee allowed");

    PASS();
    return 0;
}

static int test_multiple_inputs_outputs(void) {
    TEST("psbt_fraud_analyze - multiple inputs and outputs");

    psbt_script_analysis_t analysis;
    int ret = psbt_fraud_analyze_scripts(PSBT_2_INPUTS_2_OUTPUTS, &analysis);
    if (ret != 0)
        FAIL("parse failed");

    if (analysis.input_count != 2)
        FAIL("expected 2 inputs");

    if (analysis.output_count != 2)
        FAIL("expected 2 outputs");

    PASS();
    return 0;
}

static int test_psbt_p2wsh_multisig(void) {
    TEST("psbt_fraud_analyze - P2WSH 2-of-2 multisig");

    psbt_script_analysis_t analysis;
    int ret = psbt_fraud_analyze_scripts(PSBT_P2WSH_2OF2, &analysis);
    if (ret != 0)
        FAIL("parse failed");

    if (analysis.input_count != 1)
        FAIL("expected 1 input");

    if (analysis.input_types[0] != SCRIPT_TYPE_P2WSH)
        FAIL("expected P2WSH input");

    if (analysis.output_count != 1)
        FAIL("expected 1 output");

    if (analysis.output_types[0] != SCRIPT_TYPE_P2WPKH)
        FAIL("expected P2WPKH output");

    PASS();
    return 0;
}

static char *create_psbt_with_dust_output(void) {
    struct wally_psbt *psbt = NULL;
    struct wally_tx *tx = NULL;
    int ret;

    unsigned char prev_txid[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                   0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                                   0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

    ret = wally_tx_init_alloc(2, 0, 1, 2, &tx);
    if (ret != WALLY_OK)
        return NULL;

    ret = wally_tx_add_raw_input(tx, prev_txid, sizeof(prev_txid), 0, 0xffffffff, NULL, 0, NULL, 0);
    if (ret != WALLY_OK) {
        wally_tx_free(tx);
        return NULL;
    }

    unsigned char p2pkh_script[25];
    p2pkh_script[0] = 0x76;
    p2pkh_script[1] = 0xa9;
    p2pkh_script[2] = 0x14;
    memset(&p2pkh_script[3], 0xaa, 20);
    p2pkh_script[23] = 0x88;
    p2pkh_script[24] = 0xac;

    ret = wally_tx_add_raw_output(tx, 100, p2pkh_script, sizeof(p2pkh_script), 0);
    if (ret != WALLY_OK) {
        wally_tx_free(tx);
        return NULL;
    }

    ret = wally_tx_add_raw_output(tx, 100000000, p2pkh_script, sizeof(p2pkh_script), 0);
    if (ret != WALLY_OK) {
        wally_tx_free(tx);
        return NULL;
    }

    ret = wally_psbt_from_tx(tx, 0, 0, &psbt);
    wally_tx_free(tx);
    if (ret != WALLY_OK)
        return NULL;

    char *base64 = NULL;
    ret = wally_psbt_to_base64(psbt, 0, &base64);
    wally_psbt_free(psbt);
    if (ret != WALLY_OK)
        return NULL;

    return base64;
}

static int test_check_dust_present(void) {
    TEST("psbt_fraud_check_dust - dust output present");

    char *psbt_base64 = create_psbt_with_dust_output();
    if (!psbt_base64)
        FAIL("failed to create test PSBT");

    psbt_dust_analysis_t analysis;
    int ret = psbt_fraud_check_dust(psbt_base64, &analysis);
    wally_free_string(psbt_base64);

    if (ret != 0)
        FAIL("parse failed");

    if (!analysis.has_dust)
        FAIL("expected has_dust == true");

    if (analysis.dust_count < 1)
        FAIL("expected dust_count >= 1");

    if (analysis.dust_amounts[0] >= PSBT_FRAUD_DUST_LIMIT_SATS)
        FAIL("expected dust amount < 546");

    PASS();
    return 0;
}

static char *create_psbt_with_op_return(void) {
    struct wally_psbt *psbt = NULL;
    struct wally_tx *tx = NULL;
    int ret;

    unsigned char prev_txid[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                   0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                                   0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

    ret = wally_tx_init_alloc(2, 0, 1, 2, &tx);
    if (ret != WALLY_OK)
        return NULL;

    ret = wally_tx_add_raw_input(tx, prev_txid, sizeof(prev_txid), 0, 0xffffffff, NULL, 0, NULL, 0);
    if (ret != WALLY_OK) {
        wally_tx_free(tx);
        return NULL;
    }

    unsigned char op_return_script[6];
    op_return_script[0] = 0x6a;
    op_return_script[1] = 0x04;
    op_return_script[2] = 't';
    op_return_script[3] = 'e';
    op_return_script[4] = 's';
    op_return_script[5] = 't';

    ret = wally_tx_add_raw_output(tx, 0, op_return_script, sizeof(op_return_script), 0);
    if (ret != WALLY_OK) {
        wally_tx_free(tx);
        return NULL;
    }

    unsigned char p2pkh_script[25];
    p2pkh_script[0] = 0x76;
    p2pkh_script[1] = 0xa9;
    p2pkh_script[2] = 0x14;
    memset(&p2pkh_script[3], 0xaa, 20);
    p2pkh_script[23] = 0x88;
    p2pkh_script[24] = 0xac;

    ret = wally_tx_add_raw_output(tx, 100000000, p2pkh_script, sizeof(p2pkh_script), 0);
    if (ret != WALLY_OK) {
        wally_tx_free(tx);
        return NULL;
    }

    ret = wally_psbt_from_tx(tx, 0, 0, &psbt);
    wally_tx_free(tx);
    if (ret != WALLY_OK)
        return NULL;

    char *base64 = NULL;
    ret = wally_psbt_to_base64(psbt, 0, &base64);
    wally_psbt_free(psbt);
    if (ret != WALLY_OK)
        return NULL;

    return base64;
}

static int test_analyze_scripts_op_return(void) {
    TEST("psbt_fraud_analyze_scripts - OP_RETURN output");

    char *psbt_base64 = create_psbt_with_op_return();
    if (!psbt_base64)
        FAIL("failed to create test PSBT");

    psbt_script_analysis_t analysis;
    int ret = psbt_fraud_analyze_scripts(psbt_base64, &analysis);
    wally_free_string(psbt_base64);

    if (ret != 0)
        FAIL("parse failed");

    if (!analysis.has_op_return)
        FAIL("expected has_op_return == true");

    bool found_op_return = false;
    for (size_t i = 0; i < analysis.output_count; i++) {
        if (analysis.output_types[i] == SCRIPT_TYPE_OP_RETURN) {
            found_op_return = true;
            break;
        }
    }

    if (!found_op_return)
        FAIL("expected at least one output with SCRIPT_TYPE_OP_RETURN");

    PASS();
    return 0;
}

int main(void) {
    printf("\n=== PSBT Fraud Detection Integration Tests ===\n\n");

    wally_init(0);

    int failures = 0;

    printf("Fee Analysis:\n");
    failures += test_analyze_fees_basic();
    failures += test_analyze_fees_high();
    failures += test_analyze_fees_overflow();
    failures += test_analyze_fees_null();
    failures += test_analyze_fees_invalid_psbt();

    printf("\nDust Detection:\n");
    failures += test_check_dust_none();
    failures += test_check_dust_present();
    failures += test_check_dust_null();

    printf("\nScript Analysis:\n");
    failures += test_analyze_scripts_p2pkh_p2sh();
    failures += test_analyze_scripts_p2tr();
    failures += test_analyze_scripts_op_return();
    failures += test_analyze_scripts_null();

    printf("\nChange Detection:\n");
    failures += test_analyze_change_with_fingerprint();
    failures += test_analyze_change_no_fingerprint();
    failures += test_analyze_change_wrong_fingerprint();
    failures += test_analyze_change_null();

    printf("\nFull Analysis:\n");
    failures += test_full_analyze_clean();
    failures += test_full_analyze_all_external();
    failures += test_full_analyze_null();

    printf("\nUtility Functions:\n");
    failures += test_script_type_name();
    failures += test_fraud_check_secure_clean();
    failures += test_fraud_check_secure_high_fee();

    printf("\nComplex PSBTs:\n");
    failures += test_multiple_inputs_outputs();
    failures += test_psbt_p2wsh_multisig();

    wally_cleanup(0);

    printf("\n");
    if (failures == 0) {
        printf("=== All tests passed ===\n\n");
        return 0;
    } else {
        printf("=== %d test(s) failed ===\n\n", failures);
        return 1;
    }
}
