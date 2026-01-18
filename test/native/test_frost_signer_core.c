/**
 * @file test_frost_signer_core.c
 * @brief Unit tests for pure FROST signing core functions.
 *
 * Tests Layer 1 parsing and validation functions that have no crypto dependencies.
 * Links against the production frost_signer_core.c implementation.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define NATIVE_TEST 1

#include "session.h"

static uint32_t mock_time_ms = 1000;
static uint32_t test_now_ms(void) {
    return mock_time_ms;
}
#define now_ms test_now_ms

#include "../mocks/nostr.h"
#include "../../main/session.c"

#include "frost_signer_core.h"

#define TEST(name) printf("  TEST: %s\n", name)
#define PASS()     printf("    PASS\n")
#define FAIL(msg)                      \
    do {                               \
        printf("    FAIL: %s\n", msg); \
        return 1;                      \
    } while (0)

static int test_session_id_valid(void) {
    TEST("frost_is_session_id_valid");

    uint8_t valid_id[32];
    memset(valid_id, 0x42, 32);
    if (!frost_is_session_id_valid(valid_id))
        FAIL("valid ID rejected");

    uint8_t zero_id[32] = {0};
    if (frost_is_session_id_valid(zero_id))
        FAIL("zero ID accepted");

    uint8_t all_ones[32];
    memset(all_ones, 0xff, 32);
    if (frost_is_session_id_valid(all_ones))
        FAIL("all-ones ID accepted");

    uint8_t almost_zero[32] = {0};
    almost_zero[15] = 0x01;
    if (!frost_is_session_id_valid(almost_zero))
        FAIL("almost-zero rejected");

    uint8_t almost_ones[32];
    memset(almost_ones, 0xff, 32);
    almost_ones[0] = 0xfe;
    if (!frost_is_session_id_valid(almost_ones))
        FAIL("almost-ones rejected");

    if (frost_is_session_id_valid(NULL))
        FAIL("NULL accepted");

    PASS();
    return 0;
}

static int test_parse_commitment(void) {
    TEST("frost_parse_commitment");

    char valid_hex[COMMITMENT_HEX_LEN + 1];
    memset(valid_hex, '0', COMMITMENT_HEX_LEN);
    valid_hex[0] = '0';
    valid_hex[1] = '1';
    valid_hex[2] = '0';
    valid_hex[3] = '2';
    valid_hex[COMMITMENT_HEX_LEN] = '\0';

    uint8_t out[COMMITMENT_LEN];
    uint16_t index;

    if (frost_parse_commitment(valid_hex, out, &index) != 0)
        FAIL("valid hex failed");
    if (index != 0x0201)
        FAIL("wrong index parsed");

    char short_hex[COMMITMENT_HEX_LEN];
    memset(short_hex, '0', COMMITMENT_HEX_LEN - 1);
    short_hex[COMMITMENT_HEX_LEN - 1] = '\0';
    if (frost_parse_commitment(short_hex, out, &index) != FROST_CORE_ERR_PARSE)
        FAIL("short hex accepted");

    if (frost_parse_commitment(NULL, out, &index) != FROST_CORE_ERR_PARSE)
        FAIL("NULL hex accepted");
    if (frost_parse_commitment(valid_hex, NULL, &index) != FROST_CORE_ERR_PARSE)
        FAIL("NULL out accepted");

    PASS();
    return 0;
}

static int test_parse_commitments_empty(void) {
    TEST("frost_parse_commitments empty");

    session_t session;
    memset(&session, 0, sizeof(session));

    int result = frost_parse_commitments("", &session);
    if (result != 0)
        FAIL("empty string should return 0");
    if (session.commitment_count != 0)
        FAIL("count should be 0");

    PASS();
    return 0;
}

static int test_parse_commitments_single(void) {
    TEST("frost_parse_commitments single");

    session_t session;
    memset(&session, 0, sizeof(session));

    char hex[COMMITMENT_HEX_LEN + 1];
    memset(hex, 'a', COMMITMENT_HEX_LEN);
    hex[0] = '0';
    hex[1] = '3';
    hex[2] = '0';
    hex[3] = '0';
    hex[COMMITMENT_HEX_LEN] = '\0';

    int result = frost_parse_commitments(hex, &session);
    if (result != 1)
        FAIL("should parse 1 commitment");
    if (session.commitment_count != 1)
        FAIL("count should be 1");
    if (session.commitment_indices[0] != 3)
        FAIL("wrong index");

    PASS();
    return 0;
}

static int test_parse_commitments_multiple(void) {
    TEST("frost_parse_commitments multiple");

    session_t session;
    memset(&session, 0, sizeof(session));

    char hex[COMMITMENT_HEX_LEN * 2 + 1];
    memset(hex, 'b', COMMITMENT_HEX_LEN * 2);
    hex[0] = '0';
    hex[1] = '1';
    hex[2] = '0';
    hex[3] = '0';
    hex[COMMITMENT_HEX_LEN + 0] = '0';
    hex[COMMITMENT_HEX_LEN + 1] = '2';
    hex[COMMITMENT_HEX_LEN + 2] = '0';
    hex[COMMITMENT_HEX_LEN + 3] = '0';
    hex[COMMITMENT_HEX_LEN * 2] = '\0';

    int result = frost_parse_commitments(hex, &session);
    if (result != 2)
        FAIL("should parse 2 commitments");
    if (session.commitment_count != 2)
        FAIL("count should be 2");
    if (session.commitment_indices[0] != 1)
        FAIL("wrong first index");
    if (session.commitment_indices[1] != 2)
        FAIL("wrong second index");

    PASS();
    return 0;
}

static int test_parse_commitments_invalid_length(void) {
    TEST("frost_parse_commitments invalid length");

    session_t session;
    memset(&session, 0, sizeof(session));

    char hex[COMMITMENT_HEX_LEN + 10];
    memset(hex, 'c', COMMITMENT_HEX_LEN + 5);
    hex[COMMITMENT_HEX_LEN + 5] = '\0';

    int result = frost_parse_commitments(hex, &session);
    if (result != FROST_CORE_ERR_PARSE)
        FAIL("invalid length should fail");

    PASS();
    return 0;
}

static int test_parse_commitments_null(void) {
    TEST("frost_parse_commitments null params");

    session_t session;
    memset(&session, 0, sizeof(session));

    if (frost_parse_commitments(NULL, &session) != FROST_CORE_ERR_PARSE)
        FAIL("NULL hex accepted");
    if (frost_parse_commitments("", NULL) != FROST_CORE_ERR_PARSE)
        FAIL("NULL session accepted");

    PASS();
    return 0;
}

static int test_parse_sig_share(void) {
    TEST("frost_parse_sig_share");

    uint8_t out[SIG_SHARE_LEN];
    size_t len;

    char valid_hex[72 + 1];
    memset(valid_hex, 'a', 72);
    valid_hex[72] = '\0';

    if (frost_parse_sig_share(valid_hex, out, &len) != 0)
        FAIL("valid hex failed");
    if (len != 36)
        FAIL("wrong length");

    char too_long[80];
    memset(too_long, 'a', 74);
    too_long[74] = '\0';
    if (frost_parse_sig_share(too_long, out, &len) != FROST_CORE_ERR_PARSE)
        FAIL("too long accepted");

    if (frost_parse_sig_share("", out, &len) != FROST_CORE_ERR_PARSE)
        FAIL("empty accepted");

    if (frost_parse_sig_share(NULL, out, &len) != FROST_CORE_ERR_PARSE)
        FAIL("NULL hex accepted");
    if (frost_parse_sig_share(valid_hex, NULL, &len) != FROST_CORE_ERR_PARSE)
        FAIL("NULL out accepted");
    if (frost_parse_sig_share(valid_hex, out, NULL) != FROST_CORE_ERR_PARSE)
        FAIL("NULL len accepted");

    PASS();
    return 0;
}

static int test_parse_sig_share_short(void) {
    TEST("frost_parse_sig_share short valid");

    uint8_t out[SIG_SHARE_LEN];
    size_t len;

    char short_hex[40 + 1];
    memset(short_hex, 'f', 40);
    short_hex[40] = '\0';

    if (frost_parse_sig_share(short_hex, out, &len) != 0)
        FAIL("short valid hex failed");
    if (len != 20)
        FAIL("wrong length for short");

    PASS();
    return 0;
}

static int test_init_signing_session(void) {
    TEST("frost_init_signing_session");

    session_t session;
    uint8_t session_id[32];
    uint8_t message[32];

    memset(session_id, 0xAA, 32);
    memset(message, 0xBB, 32);

    int ret = frost_init_signing_session(&session, session_id, message, 5, 3);
    if (ret != FROST_CORE_OK)
        FAIL("init returned error");

    if (memcmp(session.session_id, session_id, 32) != 0)
        FAIL("session_id mismatch");
    if (memcmp(session.message, message, 32) != 0)
        FAIL("message mismatch");
    if (session.message_len != 32)
        FAIL("wrong message_len");
    if (session.threshold != 3)
        FAIL("wrong threshold");
    if (session.participants[0] != 5)
        FAIL("wrong participant");
    if (session.participant_count != 1)
        FAIL("wrong participant_count");
    if (session.state != SESSION_AWAITING_COMMITMENTS)
        FAIL("wrong state");

    PASS();
    return 0;
}

static int test_init_signing_session_null(void) {
    TEST("frost_init_signing_session null params");

    session_t session;
    uint8_t session_id[32] = {0};
    uint8_t message[32] = {0};

    int ret;
    ret = frost_init_signing_session(NULL, session_id, message, 1, 2);
    if (ret != FROST_CORE_ERR_INVALID_SESSION)
        FAIL("NULL session not rejected");

    ret = frost_init_signing_session(&session, NULL, message, 1, 2);
    if (ret != FROST_CORE_ERR_INVALID_SESSION)
        FAIL("NULL session_id not rejected");

    ret = frost_init_signing_session(&session, session_id, NULL, 1, 2);
    if (ret != FROST_CORE_ERR_INVALID_SESSION)
        FAIL("NULL message not rejected");

    PASS();
    return 0;
}

static int test_parse_commitments_overflow(void) {
    TEST("frost_parse_commitments overflow protection");

    session_t session;
    memset(&session, 0, sizeof(session));
    session.commitment_count = MAX_PARTICIPANTS;

    char hex[COMMITMENT_HEX_LEN + 1];
    memset(hex, 'a', COMMITMENT_HEX_LEN);
    hex[COMMITMENT_HEX_LEN] = '\0';

    int result = frost_parse_commitments(hex, &session);
    if (result != FROST_CORE_ERR_OVERFLOW)
        FAIL("overflow not detected");

    PASS();
    return 0;
}

static int test_parse_commitments_malformed(void) {
    TEST("frost_parse_commitments malformed rejection");

    session_t session;
    memset(&session, 0, sizeof(session));

    char hex[COMMITMENT_HEX_LEN + 1];
    memset(hex, 'g', COMMITMENT_HEX_LEN);
    hex[COMMITMENT_HEX_LEN] = '\0';

    int result = frost_parse_commitments(hex, &session);
    if (result != FROST_CORE_ERR_PARSE)
        FAIL("malformed commitment should return error");
    if (session.commitment_count != 0)
        FAIL("count should remain 0");

    PASS();
    return 0;
}

int main(void) {
    printf("\n=== FROST Signer Core Native Tests ===\n\n");

    int failures = 0;
    failures += test_session_id_valid();
    failures += test_parse_commitment();
    failures += test_parse_commitments_empty();
    failures += test_parse_commitments_single();
    failures += test_parse_commitments_multiple();
    failures += test_parse_commitments_invalid_length();
    failures += test_parse_commitments_null();
    failures += test_parse_sig_share();
    failures += test_parse_sig_share_short();
    failures += test_init_signing_session();
    failures += test_init_signing_session_null();
    failures += test_parse_commitments_overflow();
    failures += test_parse_commitments_malformed();

    printf("\n");
    if (failures == 0) {
        printf("=== All tests passed ===\n\n");
        return 0;
    } else {
        printf("=== %d test(s) failed ===\n\n", failures);
        return 1;
    }
}
