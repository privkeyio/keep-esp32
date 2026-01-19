#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "secresult.h"

#define TEST(name) printf("  TEST: %s\n", name)
#define PASS()     printf("    PASS\n")
#define FAIL(msg)                      \
    do {                               \
        printf("    FAIL: %s\n", msg); \
        return 1;                      \
    } while (0)

#define PSBT_FRAUD_MAX_OUTPUTS 16
#define PSBT_FRAUD_MAX_INPUTS 16

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
    uint64_t fee_sats;
    uint64_t send_amount_sats;
} psbt_fraud_analysis_mock_t;

static secresult_t fraud_check_secure_mock(const psbt_fraud_analysis_mock_t *analysis,
                                           bool allow_high_fee,
                                           bool allow_dust,
                                           bool allow_unknown_scripts,
                                           bool allow_op_return,
                                           bool allow_no_change,
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

static int test_fraud_flags_high_fee(void) {
    TEST("fraud flags - high fee detection");

    psbt_fraud_analysis_mock_t fraud = {0};
    fraud.flags = PSBT_FRAUD_FLAG_HIGH_FEE;

    secresult_t result = fraud_check_secure_mock(&fraud, false, true, true, true, true, true);
    if (result != SECRESULT_ERR_HIGH_FEE) FAIL("expected high fee error");

    result = fraud_check_secure_mock(&fraud, true, true, true, true, true, true);
    if (!SECRESULT_IS_TRUE(result)) FAIL("should pass when high fee allowed");

    PASS();
    return 0;
}

static int test_fraud_flags_dust(void) {
    TEST("fraud flags - dust detection");

    psbt_fraud_analysis_mock_t fraud = {0};
    fraud.flags = PSBT_FRAUD_FLAG_DUST_OUTPUT;

    secresult_t result = fraud_check_secure_mock(&fraud, true, false, true, true, true, true);
    if (result != SECRESULT_ERR_DUST_OUTPUT) FAIL("expected dust error");

    result = fraud_check_secure_mock(&fraud, true, true, true, true, true, true);
    if (!SECRESULT_IS_TRUE(result)) FAIL("should pass when dust allowed");

    PASS();
    return 0;
}

static int test_fraud_flags_unknown_script(void) {
    TEST("fraud flags - unknown script detection");

    psbt_fraud_analysis_mock_t fraud = {0};
    fraud.flags = PSBT_FRAUD_FLAG_UNKNOWN_SCRIPT;

    secresult_t result = fraud_check_secure_mock(&fraud, true, true, false, true, true, true);
    if (result != SECRESULT_ERR_UNKNOWN_SCRIPT) FAIL("expected unknown script error");

    result = fraud_check_secure_mock(&fraud, true, true, true, true, true, true);
    if (!SECRESULT_IS_TRUE(result)) FAIL("should pass when unknown script allowed");

    PASS();
    return 0;
}

static int test_fraud_flags_no_change(void) {
    TEST("fraud flags - no change detection");

    psbt_fraud_analysis_mock_t fraud = {0};
    fraud.flags = PSBT_FRAUD_FLAG_NO_CHANGE;

    secresult_t result = fraud_check_secure_mock(&fraud, true, true, true, true, false, true);
    if (result != SECRESULT_ERR_NO_CHANGE) FAIL("expected no change error");

    result = fraud_check_secure_mock(&fraud, true, true, true, true, true, true);
    if (!SECRESULT_IS_TRUE(result)) FAIL("should pass when no change allowed");

    PASS();
    return 0;
}

static int test_fraud_flags_multiple(void) {
    TEST("fraud flags - multiple flags set");

    psbt_fraud_analysis_mock_t fraud = {0};
    fraud.flags = PSBT_FRAUD_FLAG_HIGH_FEE | PSBT_FRAUD_FLAG_DUST_OUTPUT;

    secresult_t result = fraud_check_secure_mock(&fraud, false, true, true, true, true, true);
    if (result != SECRESULT_ERR_HIGH_FEE) FAIL("expected high fee error (checked first)");

    result = fraud_check_secure_mock(&fraud, true, false, true, true, true, true);
    if (result != SECRESULT_ERR_DUST_OUTPUT) FAIL("expected dust error");

    result = fraud_check_secure_mock(&fraud, true, true, true, true, true, true);
    if (!SECRESULT_IS_TRUE(result)) FAIL("should pass when all allowed");

    PASS();
    return 0;
}

static int test_fraud_flags_none(void) {
    TEST("fraud flags - no flags set");

    psbt_fraud_analysis_mock_t fraud = {0};
    fraud.flags = PSBT_FRAUD_FLAG_NONE;

    secresult_t result = fraud_check_secure_mock(&fraud, false, false, false, false, false, false);
    if (!SECRESULT_IS_TRUE(result)) FAIL("should pass with no flags set");

    PASS();
    return 0;
}

static int test_fraud_null_analysis(void) {
    TEST("fraud check - null analysis");

    secresult_t result = fraud_check_secure_mock(NULL, true, true, true, true, true, true);
    if (result != SECRESULT_ERR_POLICY_DENIED) FAIL("expected policy denied for null");

    PASS();
    return 0;
}

static int test_fraud_flags_op_return(void) {
    TEST("fraud flags - op_return detection");

    psbt_fraud_analysis_mock_t fraud = {0};
    fraud.flags = PSBT_FRAUD_FLAG_OP_RETURN;

    secresult_t result = fraud_check_secure_mock(&fraud, true, true, true, false, true, true);
    if (result != SECRESULT_ERR_OP_RETURN) FAIL("expected op_return error");

    result = fraud_check_secure_mock(&fraud, true, true, true, true, true, true);
    if (!SECRESULT_IS_TRUE(result)) FAIL("should pass when op_return allowed");

    PASS();
    return 0;
}

static int test_fraud_flags_all_external(void) {
    TEST("fraud flags - all external detection");

    psbt_fraud_analysis_mock_t fraud = {0};
    fraud.flags = PSBT_FRAUD_FLAG_ALL_EXTERNAL;

    secresult_t result = fraud_check_secure_mock(&fraud, true, true, true, true, true, false);
    if (result != SECRESULT_ERR_ALL_EXTERNAL) FAIL("expected all external error");

    result = fraud_check_secure_mock(&fraud, true, true, true, true, true, true);
    if (!SECRESULT_IS_TRUE(result)) FAIL("should pass when all external allowed");

    PASS();
    return 0;
}

static int test_secresult_values(void) {
    TEST("secresult error code values");

    if (SECRESULT_ERR_HIGH_FEE == SECRESULT_TRUE) FAIL("HIGH_FEE should not equal TRUE");
    if (SECRESULT_ERR_DUST_OUTPUT == SECRESULT_TRUE) FAIL("DUST_OUTPUT should not equal TRUE");
    if (SECRESULT_ERR_UNKNOWN_SCRIPT == SECRESULT_TRUE) FAIL("UNKNOWN_SCRIPT should not equal TRUE");
    if (SECRESULT_ERR_NO_CHANGE == SECRESULT_TRUE) FAIL("NO_CHANGE should not equal TRUE");
    if (SECRESULT_ERR_OP_RETURN == SECRESULT_TRUE) FAIL("OP_RETURN should not equal TRUE");
    if (SECRESULT_ERR_ALL_EXTERNAL == SECRESULT_TRUE) FAIL("ALL_EXTERNAL should not equal TRUE");

    if (!SECRESULT_IS_ERROR(SECRESULT_ERR_HIGH_FEE)) FAIL("HIGH_FEE should be error");
    if (!SECRESULT_IS_ERROR(SECRESULT_ERR_DUST_OUTPUT)) FAIL("DUST_OUTPUT should be error");
    if (!SECRESULT_IS_ERROR(SECRESULT_ERR_UNKNOWN_SCRIPT)) FAIL("UNKNOWN_SCRIPT should be error");
    if (!SECRESULT_IS_ERROR(SECRESULT_ERR_NO_CHANGE)) FAIL("NO_CHANGE should be error");
    if (!SECRESULT_IS_ERROR(SECRESULT_ERR_OP_RETURN)) FAIL("OP_RETURN should be error");
    if (!SECRESULT_IS_ERROR(SECRESULT_ERR_ALL_EXTERNAL)) FAIL("ALL_EXTERNAL should be error");

    PASS();
    return 0;
}

static int test_flag_bit_values(void) {
    TEST("fraud flag bit values");

    if (PSBT_FRAUD_FLAG_HIGH_FEE != 1) FAIL("HIGH_FEE should be bit 0");
    if (PSBT_FRAUD_FLAG_DUST_OUTPUT != 2) FAIL("DUST_OUTPUT should be bit 1");
    if (PSBT_FRAUD_FLAG_UNKNOWN_SCRIPT != 4) FAIL("UNKNOWN_SCRIPT should be bit 2");
    if (PSBT_FRAUD_FLAG_NO_CHANGE != 8) FAIL("NO_CHANGE should be bit 3");
    if (PSBT_FRAUD_FLAG_OP_RETURN != 16) FAIL("OP_RETURN should be bit 4");
    if (PSBT_FRAUD_FLAG_ALL_EXTERNAL != 32) FAIL("ALL_EXTERNAL should be bit 5");

    PASS();
    return 0;
}

int main(void) {
    printf("PSBT Fraud Detection Tests (Native)\n");
    printf("====================================\n");

    int failures = 0;

    failures += test_fraud_flags_high_fee();
    failures += test_fraud_flags_dust();
    failures += test_fraud_flags_unknown_script();
    failures += test_fraud_flags_no_change();
    failures += test_fraud_flags_op_return();
    failures += test_fraud_flags_all_external();
    failures += test_fraud_flags_multiple();
    failures += test_fraud_flags_none();
    failures += test_fraud_null_analysis();
    failures += test_secresult_values();
    failures += test_flag_bit_values();

    printf("\n");
    if (failures == 0) {
        printf("All tests passed!\n");
        return 0;
    } else {
        printf("%d test(s) failed\n", failures);
        return 1;
    }
}
