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

static void secure_zero(void *buf, size_t len) {
    volatile uint8_t *p = buf;
    while (len--) *p++ = 0;
}

void session_init(session_t *s, const sign_request_t *req, uint16_t threshold) {
    memset(s, 0, sizeof(*s));
    memcpy(s->session_id, req->session_id, SESSION_ID_LEN);
    memcpy(s->message, req->message, req->message_len);
    s->message_len = req->message_len;
    s->threshold = threshold;
    memcpy(s->participants, req->participants, req->participant_count * sizeof(uint16_t));
    s->participant_count = req->participant_count;
    s->state = SESSION_AWAITING_COMMITMENTS;
    s->created_at = test_now_ms();
}

void session_destroy(session_t *s) {
    secure_zero(s, sizeof(session_t));
}

session_state_t session_state(session_t *s) {
    if (s->state != SESSION_COMPLETE && s->state != SESSION_FAILED) {
        uint32_t now = test_now_ms();
        uint32_t created = s->created_at;
        uint32_t elapsed = (now >= created) ? (now - created) : (UINT32_MAX - created + now + 1);
        if (elapsed > SESSION_TIMEOUT_MS) {
            s->state = SESSION_EXPIRED;
        }
    }
    return s->state;
}

bool session_is_participant(session_t *s, uint16_t share_index) {
    for (int i = 0; i < s->participant_count; i++) {
        if (s->participants[i] == share_index) return true;
    }
    return false;
}

int session_add_commitment(session_t *s, uint16_t share_index, const uint8_t *commitment, size_t len) {
    if (s->state != SESSION_AWAITING_COMMITMENTS) return -1;
    if (!session_is_participant(s, share_index)) return -2;
    if (len > 128) return -3;

    for (int i = 0; i < s->commitment_count; i++) {
        if (s->commitment_indices[i] == share_index) return -4;
    }

    int idx = s->commitment_count;
    memcpy(s->commitments[idx], commitment, len);
    s->commitment_lens[idx] = len;
    s->commitment_indices[idx] = share_index;
    s->commitment_count++;

    if (s->commitment_count >= s->threshold) {
        s->state = SESSION_AWAITING_SHARES;
    }
    return 0;
}

int session_add_signature_share(session_t *s, uint16_t share_index, const uint8_t *share, size_t len) {
    if (s->state != SESSION_AWAITING_SHARES) return -1;
    if (!session_is_participant(s, share_index)) return -2;
    if (len > 64) return -3;

    for (int i = 0; i < s->sig_share_count; i++) {
        if (s->sig_share_indices[i] == share_index) return -4;
    }

    int idx = s->sig_share_count;
    memcpy(s->sig_shares[idx], share, len);
    s->sig_share_lens[idx] = len;
    s->sig_share_indices[idx] = share_index;
    s->sig_share_count++;

    return 0;
}

bool session_has_all_commitments(session_t *s) {
    if (s->participant_count == 0) return false;
    return s->commitment_count >= s->participant_count - 1;
}

bool session_has_all_shares(session_t *s) {
    if (s->participant_count == 0) return false;
    return s->sig_share_count >= s->participant_count - 1;
}

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

    session_init(&s, &req, 2);
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
    session_init(&s, &req, 2);

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
    session_init(&s, &req, 2);

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
    session_init(&s, &req, 2);

    uint8_t commit[64] = {0};
    session_add_commitment(&s, 1, commit, sizeof(commit));
    session_add_commitment(&s, 2, commit, sizeof(commit));

    if (session_add_commitment(&s, 3, commit, sizeof(commit)) != -1) FAIL("should fail in wrong state");

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
    session_init(&s, &req, 2);

    uint8_t commit[64] = {0};
    if (session_add_commitment(&s, 99, commit, sizeof(commit)) != -2) FAIL("should fail for non-participant");

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
    session_init(&s, &req, 2);

    uint8_t commit[256];
    memset(commit, 0, sizeof(commit));
    if (session_add_commitment(&s, 1, commit, 129) != -3) FAIL("should fail for too long");

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
    session_init(&s, &req, 2);

    uint8_t commit[64] = {0};
    if (session_add_commitment(&s, 1, commit, sizeof(commit)) != 0) FAIL("first add failed");
    if (session_add_commitment(&s, 1, commit, sizeof(commit)) != -4) FAIL("duplicate should fail");

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
    session_init(&s, &req, 2);

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
    session_init(&s, &req, 2);

    uint8_t share[32] = {0};
    if (session_add_signature_share(&s, 1, share, sizeof(share)) != -1) FAIL("should fail in wrong state");

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
    session_init(&s, &req, 2);

    uint8_t commit[64] = {0};
    session_add_commitment(&s, 1, commit, sizeof(commit));
    session_add_commitment(&s, 2, commit, sizeof(commit));

    uint8_t share[32] = {0};
    if (session_add_signature_share(&s, 99, share, sizeof(share)) != -2) FAIL("should fail for non-participant");

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
    session_init(&s, &req, 2);

    uint8_t commit[64] = {0};
    session_add_commitment(&s, 1, commit, sizeof(commit));
    session_add_commitment(&s, 2, commit, sizeof(commit));

    uint8_t share[128] = {0};
    if (session_add_signature_share(&s, 1, share, 65) != -3) FAIL("should fail for too long");

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
    session_init(&s, &req, 2);

    uint8_t commit[64] = {0};
    session_add_commitment(&s, 1, commit, sizeof(commit));
    session_add_commitment(&s, 2, commit, sizeof(commit));

    uint8_t share[32] = {0};
    if (session_add_signature_share(&s, 1, share, sizeof(share)) != 0) FAIL("first add failed");
    if (session_add_signature_share(&s, 1, share, sizeof(share)) != -4) FAIL("duplicate should fail");

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
    session_init(&s, &req, 2);

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
    session_init(&s, &req, 2);

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
    session_init(&s, &req, 2);

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
    session_init(&s, &req, 2);

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
    session_init(&s, &req, MAX_PARTICIPANTS);

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
    session_init(&s, &req, 2);

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
    session_init(&s, &req, 2);

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
    session_init(&s, &req, 0);

    if (session_has_all_commitments(&s)) FAIL("should return false with 0 participants");
    if (session_has_all_shares(&s)) FAIL("should return false with 0 participants");

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

    printf("\n");
    if (failures == 0) {
        printf("=== All tests passed ===\n\n");
        return 0;
    } else {
        printf("=== %d test(s) failed ===\n\n", failures);
        return 1;
    }
}
