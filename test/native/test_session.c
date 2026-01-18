#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

static uint32_t mock_time_ms = 0;

static uint32_t test_now_ms(void) {
    return mock_time_ms;
}

#define now_ms test_now_ms

#include "session.h"
#include "session.c"

#define TEST(name) printf("  TEST: %s\n", name)
#define PASS() printf("    PASS\n")
#define FAIL(msg) do { printf("    FAIL: %s\n", msg); return 1; } while(0)

static void setup_request(sign_request_t *req, uint8_t count) {
    memset(req, 0, sizeof(*req));
    memset(req->session_id, 0xAA, SESSION_ID_LEN);
    memcpy(req->message, "test message", 12);
    req->message_len = 12;
    req->participant_count = count;
    for (int i = 0; i < count; i++) {
        req->participants[i] = (uint16_t)(i + 1);
    }
}

static int test_init_and_destroy(void) {
    TEST("session init and destroy");
    session_t s;
    sign_request_t req;
    setup_request(&req, 3);
    mock_time_ms = 1000;

    if (session_init(&s, &req, 2) != 0) FAIL("session_init failed");
    if (s.state != SESSION_AWAITING_COMMITMENTS) FAIL("wrong initial state");
    if (s.threshold != 2) FAIL("wrong threshold");
    if (s.participant_count != 3) FAIL("wrong participant count");
    if (s.message_len != 12) FAIL("wrong message len");
    if (memcmp(s.session_id, req.session_id, SESSION_ID_LEN) != 0) FAIL("session_id mismatch");

    session_destroy(&s);
    uint8_t zero[sizeof(session_t)] = {0};
    if (memcmp(&s, zero, sizeof(s)) != 0) FAIL("not zeroed after destroy");

    PASS();
    return 0;
}

static int test_is_participant(void) {
    TEST("session_is_participant");
    session_t s;
    sign_request_t req;
    setup_request(&req, 3);
    mock_time_ms = 1000;
    if (session_init(&s, &req, 2) != 0) FAIL("session_init failed");

    if (!session_is_participant(&s, 1)) FAIL("1 should be participant");
    if (!session_is_participant(&s, 2)) FAIL("2 should be participant");
    if (!session_is_participant(&s, 3)) FAIL("3 should be participant");
    if (session_is_participant(&s, 0)) FAIL("0 should not be participant");
    if (session_is_participant(&s, 4)) FAIL("4 should not be participant");
    if (session_is_participant(&s, 100)) FAIL("100 should not be participant");

    session_destroy(&s);
    PASS();
    return 0;
}

static int test_add_commitment(void) {
    TEST("session_add_commitment");
    session_t s;
    sign_request_t req;
    setup_request(&req, 3);
    mock_time_ms = 1000;
    if (session_init(&s, &req, 2) != 0) FAIL("session_init failed");

    uint8_t commit[64];
    memset(commit, 0xBB, sizeof(commit));

    if (session_add_commitment(&s, 1, commit, sizeof(commit)) != 0) FAIL("add commitment failed");
    if (s.commitment_count != 1) FAIL("wrong count after first");
    if (s.state != SESSION_AWAITING_COMMITMENTS) FAIL("should still await more");

    if (session_add_commitment(&s, 2, commit, sizeof(commit)) != 0) FAIL("add second failed");
    if (s.commitment_count != 2) FAIL("wrong count after second");
    if (s.state != SESSION_AWAITING_SHARES) FAIL("should transition to awaiting shares");

    session_destroy(&s);
    PASS();
    return 0;
}

static int test_commitment_wrong_state(void) {
    TEST("commitment wrong state");
    session_t s;
    sign_request_t req;
    setup_request(&req, 3);
    mock_time_ms = 1000;
    if (session_init(&s, &req, 2) != 0) FAIL("session_init failed");

    uint8_t commit[64] = {0};
    session_add_commitment(&s, 1, commit, sizeof(commit));
    session_add_commitment(&s, 2, commit, sizeof(commit));

    if (session_add_commitment(&s, 3, commit, sizeof(commit)) != SESSION_ERR_INVALID_STATE) FAIL("should fail in wrong state");

    session_destroy(&s);
    PASS();
    return 0;
}

static int test_commitment_not_participant(void) {
    TEST("commitment from non-participant");
    session_t s;
    sign_request_t req;
    setup_request(&req, 3);
    mock_time_ms = 1000;
    if (session_init(&s, &req, 2) != 0) FAIL("session_init failed");

    uint8_t commit[64] = {0};
    if (session_add_commitment(&s, 99, commit, sizeof(commit)) != SESSION_ERR_NOT_PARTICIPANT) FAIL("should fail for non-participant");

    session_destroy(&s);
    PASS();
    return 0;
}

static int test_commitment_too_long(void) {
    TEST("commitment too long");
    session_t s;
    sign_request_t req;
    setup_request(&req, 3);
    mock_time_ms = 1000;
    if (session_init(&s, &req, 2) != 0) FAIL("session_init failed");

    uint8_t commit[256];
    memset(commit, 0, sizeof(commit));
    if (session_add_commitment(&s, 1, commit, COMMITMENT_LEN + 1) != SESSION_ERR_INVALID_LEN) FAIL("should fail for too long");

    session_destroy(&s);
    PASS();
    return 0;
}

static int test_commitment_duplicate(void) {
    TEST("commitment duplicate");
    session_t s;
    sign_request_t req;
    setup_request(&req, 3);
    mock_time_ms = 1000;
    if (session_init(&s, &req, 2) != 0) FAIL("session_init failed");

    uint8_t commit[64] = {0};
    if (session_add_commitment(&s, 1, commit, sizeof(commit)) != 0) FAIL("first add failed");
    if (session_add_commitment(&s, 1, commit, sizeof(commit)) != SESSION_ERR_DUPLICATE) FAIL("duplicate should fail");

    session_destroy(&s);
    PASS();
    return 0;
}

static int test_add_signature_share(void) {
    TEST("session_add_signature_share");
    session_t s;
    sign_request_t req;
    setup_request(&req, 3);
    mock_time_ms = 1000;
    if (session_init(&s, &req, 2) != 0) FAIL("session_init failed");

    uint8_t commit[64] = {0};
    session_add_commitment(&s, 1, commit, sizeof(commit));
    session_add_commitment(&s, 2, commit, sizeof(commit));

    uint8_t share[32];
    memset(share, 0xCC, sizeof(share));

    if (session_add_signature_share(&s, 1, share, sizeof(share)) != 0) FAIL("add share failed");
    if (s.sig_share_count != 1) FAIL("wrong count");

    session_destroy(&s);
    PASS();
    return 0;
}

static int test_signature_share_wrong_state(void) {
    TEST("signature share wrong state");
    session_t s;
    sign_request_t req;
    setup_request(&req, 3);
    mock_time_ms = 1000;
    if (session_init(&s, &req, 2) != 0) FAIL("session_init failed");

    uint8_t share[32] = {0};
    if (session_add_signature_share(&s, 1, share, sizeof(share)) != SESSION_ERR_INVALID_STATE) FAIL("should fail in wrong state");

    session_destroy(&s);
    PASS();
    return 0;
}

static int test_signature_share_not_participant(void) {
    TEST("signature share from non-participant");
    session_t s;
    sign_request_t req;
    setup_request(&req, 3);
    mock_time_ms = 1000;
    if (session_init(&s, &req, 2) != 0) FAIL("session_init failed");

    uint8_t commit[64] = {0};
    session_add_commitment(&s, 1, commit, sizeof(commit));
    session_add_commitment(&s, 2, commit, sizeof(commit));

    uint8_t share[32] = {0};
    if (session_add_signature_share(&s, 99, share, sizeof(share)) != SESSION_ERR_NOT_PARTICIPANT) FAIL("should fail for non-participant");

    session_destroy(&s);
    PASS();
    return 0;
}

static int test_signature_share_too_long(void) {
    TEST("signature share too long");
    session_t s;
    sign_request_t req;
    setup_request(&req, 3);
    mock_time_ms = 1000;
    if (session_init(&s, &req, 2) != 0) FAIL("session_init failed");

    uint8_t commit[64] = {0};
    session_add_commitment(&s, 1, commit, sizeof(commit));
    session_add_commitment(&s, 2, commit, sizeof(commit));

    uint8_t share[128] = {0};
    if (session_add_signature_share(&s, 1, share, SIGNATURE_LEN + 1) != SESSION_ERR_INVALID_LEN) FAIL("should fail for too long");

    session_destroy(&s);
    PASS();
    return 0;
}

static int test_signature_share_duplicate(void) {
    TEST("signature share duplicate");
    session_t s;
    sign_request_t req;
    setup_request(&req, 3);
    mock_time_ms = 1000;
    if (session_init(&s, &req, 2) != 0) FAIL("session_init failed");

    uint8_t commit[64] = {0};
    session_add_commitment(&s, 1, commit, sizeof(commit));
    session_add_commitment(&s, 2, commit, sizeof(commit));

    uint8_t share[32] = {0};
    if (session_add_signature_share(&s, 1, share, sizeof(share)) != 0) FAIL("first add failed");
    if (session_add_signature_share(&s, 1, share, sizeof(share)) != SESSION_ERR_DUPLICATE) FAIL("duplicate should fail");

    session_destroy(&s);
    PASS();
    return 0;
}

static int test_timeout(void) {
    TEST("session timeout");
    session_t s;
    sign_request_t req;
    setup_request(&req, 3);
    mock_time_ms = 1000;
    if (session_init(&s, &req, 2) != 0) FAIL("session_init failed");

    if (session_state(&s) != SESSION_AWAITING_COMMITMENTS) FAIL("should be awaiting");

    mock_time_ms = 1000 + SESSION_TIMEOUT_MS - 1;
    if (session_state(&s) != SESSION_AWAITING_COMMITMENTS) FAIL("should still be awaiting before timeout");

    mock_time_ms = 1000 + SESSION_TIMEOUT_MS + 1;
    if (session_state(&s) != SESSION_EXPIRED) FAIL("should be expired");

    session_destroy(&s);
    PASS();
    return 0;
}

static int test_timeout_wraparound(void) {
    TEST("session timeout with counter wraparound");
    session_t s;
    sign_request_t req;
    setup_request(&req, 3);

    mock_time_ms = UINT32_MAX - 10000;
    if (session_init(&s, &req, 2) != 0) FAIL("session_init failed");

    mock_time_ms = UINT32_MAX - 5000;
    if (session_state(&s) != SESSION_AWAITING_COMMITMENTS) FAIL("should be awaiting mid-way");

    mock_time_ms = 25000;
    if (session_state(&s) != SESSION_EXPIRED) FAIL("should be expired after wraparound");

    session_destroy(&s);
    PASS();
    return 0;
}

static int test_has_all_commitments(void) {
    TEST("session_has_all_commitments");
    session_t s;
    sign_request_t req;
    setup_request(&req, 3);
    mock_time_ms = 1000;
    if (session_init(&s, &req, 2) != 0) FAIL("session_init failed");

    uint8_t commit[64] = {0};
    if (session_has_all_commitments(&s)) FAIL("should not have all initially");

    session_add_commitment(&s, 1, commit, sizeof(commit));
    if (session_has_all_commitments(&s)) FAIL("should not have all after one");

    session_add_commitment(&s, 2, commit, sizeof(commit));
    if (!session_has_all_commitments(&s)) FAIL("should have all after two (n-1)");

    session_destroy(&s);
    PASS();
    return 0;
}

static int test_has_all_shares(void) {
    TEST("session_has_all_shares");
    session_t s;
    sign_request_t req;
    setup_request(&req, 3);
    mock_time_ms = 1000;
    if (session_init(&s, &req, 2) != 0) FAIL("session_init failed");

    uint8_t commit[64] = {0};
    session_add_commitment(&s, 1, commit, sizeof(commit));
    session_add_commitment(&s, 2, commit, sizeof(commit));

    uint8_t share[32] = {0};
    if (session_has_all_shares(&s)) FAIL("should not have all initially");

    session_add_signature_share(&s, 1, share, sizeof(share));
    if (session_has_all_shares(&s)) FAIL("should not have all after one");

    session_add_signature_share(&s, 2, share, sizeof(share));
    if (!session_has_all_shares(&s)) FAIL("should have all after two (n-1)");

    session_destroy(&s);
    PASS();
    return 0;
}

static int test_max_participants(void) {
    TEST("max participants limit");
    session_t s;
    sign_request_t req;
    setup_request(&req, MAX_PARTICIPANTS);
    mock_time_ms = 1000;
    if (session_init(&s, &req, MAX_PARTICIPANTS) != 0) FAIL("session_init failed");

    if (s.participant_count != MAX_PARTICIPANTS) FAIL("wrong participant count");

    uint8_t commit[64] = {0};
    for (int i = 0; i < MAX_PARTICIPANTS; i++) {
        int res = session_add_commitment(&s, (uint16_t)(i + 1), commit, sizeof(commit));
        if (res != 0 && i < MAX_PARTICIPANTS - 1) FAIL("should accept more commitments");
    }

    session_destroy(&s);
    PASS();
    return 0;
}

static int test_complete_state_no_timeout(void) {
    TEST("complete state not affected by timeout");
    session_t s;
    sign_request_t req;
    setup_request(&req, 3);
    mock_time_ms = 1000;
    if (session_init(&s, &req, 2) != 0) FAIL("session_init failed");

    s.state = SESSION_COMPLETE;
    mock_time_ms = 1000 + SESSION_TIMEOUT_MS + 10000;

    if (session_state(&s) != SESSION_COMPLETE) FAIL("complete should not expire");

    session_destroy(&s);
    PASS();
    return 0;
}

static int test_failed_state_no_timeout(void) {
    TEST("failed state not affected by timeout");
    session_t s;
    sign_request_t req;
    setup_request(&req, 3);
    mock_time_ms = 1000;
    if (session_init(&s, &req, 2) != 0) FAIL("session_init failed");

    s.state = SESSION_FAILED;
    mock_time_ms = 1000 + SESSION_TIMEOUT_MS + 10000;

    if (session_state(&s) != SESSION_FAILED) FAIL("failed should not expire");

    session_destroy(&s);
    PASS();
    return 0;
}

static int test_zero_participants(void) {
    TEST("zero participants edge case");
    session_t s;
    sign_request_t req;
    setup_request(&req, 0);
    mock_time_ms = 1000;
    if (session_init(&s, &req, 0) != 0) FAIL("session_init failed");

    if (session_has_all_commitments(&s)) FAIL("should return false with 0 participants");
    if (session_has_all_shares(&s)) FAIL("should return false with 0 participants");

    session_destroy(&s);
    PASS();
    return 0;
}

static int test_init_null_params(void) {
    TEST("session_init null params");
    session_t s;
    sign_request_t req;
    memset(&req, 0, sizeof(req));

    if (session_init(NULL, &req, 2) != -1) FAIL("NULL session should fail");
    if (session_init(&s, NULL, 2) != -1) FAIL("NULL request should fail");
    PASS();
    return 0;
}

static int test_init_overflow_protection(void) {
    TEST("session_init overflow protection");
    session_t s;
    sign_request_t req;
    memset(&req, 0, sizeof(req));

    req.message_len = MAX_MESSAGE_LEN + 1;
    if (session_init(&s, &req, 2) != -2) FAIL("should reject oversized message");

    req.message_len = 0;
    req.participant_count = MAX_PARTICIPANTS + 1;
    if (session_init(&s, &req, 2) != -3) FAIL("should reject too many participants");

    PASS();
    return 0;
}

static int test_commitment_null_pointer(void) {
    TEST("commitment null pointer");
    session_t s;
    sign_request_t req;
    setup_request(&req, 3);
    mock_time_ms = 1000;
    if (session_init(&s, &req, 2) != 0) FAIL("session_init failed");

    if (session_add_commitment(&s, 1, NULL, 64) != SESSION_ERR_INVALID_LEN) FAIL("NULL should fail");

    session_destroy(&s);
    PASS();
    return 0;
}

int main(void) {
    printf("\n=== Session Native Tests ===\n\n");

    int failures = 0;
    failures += test_init_and_destroy();
    failures += test_is_participant();
    failures += test_add_commitment();
    failures += test_commitment_wrong_state();
    failures += test_commitment_not_participant();
    failures += test_commitment_too_long();
    failures += test_commitment_duplicate();
    failures += test_add_signature_share();
    failures += test_signature_share_wrong_state();
    failures += test_signature_share_not_participant();
    failures += test_signature_share_too_long();
    failures += test_signature_share_duplicate();
    failures += test_timeout();
    failures += test_timeout_wraparound();
    failures += test_has_all_commitments();
    failures += test_has_all_shares();
    failures += test_max_participants();
    failures += test_complete_state_no_timeout();
    failures += test_failed_state_no_timeout();
    failures += test_zero_participants();
    failures += test_init_null_params();
    failures += test_init_overflow_protection();
    failures += test_commitment_null_pointer();

    printf("\n");
    if (failures == 0) {
        printf("=== All tests passed ===\n\n");
        return 0;
    } else {
        printf("=== %d test(s) failed ===\n\n", failures);
        return 1;
    }
}
