#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define NATIVE_TEST 1

static uint32_t mock_time_ms = 1000;
static uint32_t test_now_ms(void) {
    return mock_time_ms;
}
#define now_ms test_now_ms

#include "../mocks/secresult.h"
#include "../mocks/crypto_asm.h"
#include "../../main/session.h"

#define STORAGE_SESSION_ID_LEN 32
int storage_save_session_checkpoint(const uint8_t *id, const void *d, size_t l) {
    (void)id;
    (void)d;
    (void)l;
    return -1;
}
int storage_load_session_checkpoint(const uint8_t *id, void *d, size_t l) {
    (void)id;
    (void)d;
    (void)l;
    return -1;
}
int storage_delete_session_checkpoint(const uint8_t *id) {
    (void)id;
    return -1;
}
int storage_list_session_checkpoints(uint8_t ids[][STORAGE_SESSION_ID_LEN], int m) {
    (void)ids;
    (void)m;
    return 0;
}
int storage_count_session_checkpoints(void) {
    return 0;
}

#include "../../main/session.c"
#include "../../main/protocol.h"

#ifdef HAS_CJSON
#include "cJSON.h"
#include "../../main/protocol.c"
#include "../../main/error_context.c"
#endif

#define TEST(name) printf("  TEST: %s\n", name)
#define PASS()     printf("    PASS\n")
#define FAIL(msg)                      \
    do {                               \
        printf("    FAIL: %s\n", msg); \
        return 1;                      \
    } while (0)

#define MAX_TEST_SESSIONS 4

typedef struct {
    bool active;
    uint8_t session_id[SESSION_ID_LEN];
    session_t session;
    char group[65];
} test_signing_session_t;

static test_signing_session_t test_sessions[MAX_TEST_SESSIONS];

static void test_sessions_init(void) {
    for (int i = 0; i < MAX_TEST_SESSIONS; i++) {
        test_sessions[i].active = false;
        memset(&test_sessions[i].session, 0, sizeof(session_t));
    }
}

static test_signing_session_t *test_find_session(const uint8_t *session_id) {
    for (int i = 0; i < MAX_TEST_SESSIONS; i++) {
        if (test_sessions[i].active &&
            ct_compare(test_sessions[i].session_id, session_id, SESSION_ID_LEN) == 0) {
            return &test_sessions[i];
        }
    }
    return NULL;
}

static test_signing_session_t *test_alloc_session(const uint8_t *session_id) {
    for (int i = 0; i < MAX_TEST_SESSIONS; i++) {
        if (!test_sessions[i].active) {
            memset(&test_sessions[i], 0, sizeof(test_signing_session_t));
            test_sessions[i].active = true;
            memcpy(test_sessions[i].session_id, session_id, SESSION_ID_LEN);
            return &test_sessions[i];
        }
    }
    return NULL;
}

static void test_free_session(test_signing_session_t *s) {
    if (s) {
        session_destroy(&s->session);
        secure_memzero(s, sizeof(test_signing_session_t));
    }
}

static int test_session_allocation(void) {
    TEST("session allocation and lookup");
    test_sessions_init();

    uint8_t sid1[32], sid2[32], sid3[32], sid4[32], sid5[32];
    memset(sid1, 0x11, 32);
    memset(sid2, 0x22, 32);
    memset(sid3, 0x33, 32);
    memset(sid4, 0x44, 32);
    memset(sid5, 0x55, 32);

    test_signing_session_t *s1 = test_alloc_session(sid1);
    if (!s1)
        FAIL("failed to alloc s1");

    test_signing_session_t *s2 = test_alloc_session(sid2);
    if (!s2)
        FAIL("failed to alloc s2");

    test_signing_session_t *s3 = test_alloc_session(sid3);
    if (!s3)
        FAIL("failed to alloc s3");

    test_signing_session_t *s4 = test_alloc_session(sid4);
    if (!s4)
        FAIL("failed to alloc s4");

    test_signing_session_t *s5 = test_alloc_session(sid5);
    if (s5 != NULL)
        FAIL("should not alloc 5th session");

    if (test_find_session(sid1) != s1)
        FAIL("find s1 failed");
    if (test_find_session(sid2) != s2)
        FAIL("find s2 failed");
    if (test_find_session(sid3) != s3)
        FAIL("find s3 failed");
    if (test_find_session(sid4) != s4)
        FAIL("find s4 failed");
    if (test_find_session(sid5) != NULL)
        FAIL("should not find s5");

    test_free_session(s2);
    if (test_find_session(sid2) != NULL)
        FAIL("s2 should be freed");

    test_signing_session_t *s5_retry = test_alloc_session(sid5);
    if (!s5_retry)
        FAIL("should reuse freed slot");

    test_sessions_init();
    PASS();
    return 0;
}

static int test_concurrent_sessions_isolation(void) {
    TEST("concurrent sessions isolation");
    test_sessions_init();
    mock_time_ms = 1000;

    uint8_t sid1[32], sid2[32];
    memset(sid1, 0x11, 32);
    memset(sid2, 0x22, 32);

    test_signing_session_t *ts1 = test_alloc_session(sid1);
    test_signing_session_t *ts2 = test_alloc_session(sid2);
    if (!ts1 || !ts2)
        FAIL("alloc failed");

    sign_request_t req1, req2;
    memset(&req1, 0, sizeof(req1));
    memset(&req2, 0, sizeof(req2));
    memcpy(req1.session_id, sid1, SESSION_ID_LEN);
    memcpy(req2.session_id, sid2, SESSION_ID_LEN);
    req1.message_len = 32;
    req2.message_len = 32;
    req1.participant_count = 2;
    req2.participant_count = 3;
    req1.participants[0] = 1;
    req1.participants[1] = 2;
    req2.participants[0] = 10;
    req2.participants[1] = 20;
    req2.participants[2] = 30;

    if (session_init(&ts1->session, &req1, 2) != 0)
        FAIL("s1 init failed");
    if (session_init(&ts2->session, &req2, 2) != 0)
        FAIL("s2 init failed");

    uint8_t commit[COMMITMENT_LEN] = {0};

    if (session_add_commitment(&ts1->session, 1, commit, sizeof(commit)) != 0)
        FAIL("s1 add commit failed");
    if (ts1->session.commitment_count != 1)
        FAIL("s1 count wrong");
    if (ts2->session.commitment_count != 0)
        FAIL("s2 should be unaffected");

    if (session_add_commitment(&ts2->session, 10, commit, sizeof(commit)) != 0)
        FAIL("s2 add commit failed");
    if (ts2->session.commitment_count != 1)
        FAIL("s2 count wrong");

    int reject_result = session_add_commitment(&ts1->session, 10, commit, sizeof(commit));
    if (reject_result != SESSION_ERR_NOT_PARTICIPANT && reject_result != SESSION_ERR_INVALID_STATE)
        FAIL("s1 should reject s2 participant or wrong state");

    test_sessions_init();
    PASS();
    return 0;
}

static int test_session_cleanup_on_timeout(void) {
    TEST("session cleanup on timeout");
    test_sessions_init();
    mock_time_ms = 1000;

    uint8_t sid[32];
    memset(sid, 0x77, 32);
    test_signing_session_t *ts = test_alloc_session(sid);
    if (!ts)
        FAIL("alloc failed");

    sign_request_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.session_id, sid, SESSION_ID_LEN);
    req.message_len = 32;
    req.participant_count = 2;
    req.participants[0] = 1;
    req.participants[1] = 2;

    if (session_init(&ts->session, &req, 2) != 0)
        FAIL("init failed");

    mock_time_ms = 1000 + SESSION_TIMEOUT_MS + 1000;
    if (session_state(&ts->session) != SESSION_EXPIRED)
        FAIL("should be expired");

    test_sessions_init();
    PASS();
    return 0;
}

#ifdef HAS_CJSON
static int test_protocol_parse_basic(void) {
    TEST("protocol parse basic request");

    rpc_request_t req;
    const char *json = "{\"id\":1,\"method\":\"ping\"}";

    int ret = protocol_parse_request(json, &req);
    if (ret != 0)
        FAIL("parse failed");
    if (req.id != 1)
        FAIL("wrong id");
    if (req.method != RPC_METHOD_PING)
        FAIL("wrong method");

    protocol_free_request(&req);
    PASS();
    return 0;
}

static int test_protocol_parse_with_params(void) {
    TEST("protocol parse with params");

    rpc_request_t req;
    const char *json =
        "{\"id\":42,\"method\":\"frost_commit\",\"params\":{\"group\":\"test\",\"session_id\":"
        "\"aaaa\",\"message\":\"bbbb\"}}";

    int ret = protocol_parse_request(json, &req);
    if (ret != 0)
        FAIL("parse failed");
    if (req.id != 42)
        FAIL("wrong id");
    if (req.method != RPC_METHOD_FROST_COMMIT)
        FAIL("wrong method");
    if (strcmp(req.group, "test") != 0)
        FAIL("wrong group");
    if (strcmp(req.session_id, "aaaa") != 0)
        FAIL("wrong session_id");
    if (strcmp(req.message, "bbbb") != 0)
        FAIL("wrong message");

    protocol_free_request(&req);
    PASS();
    return 0;
}

static int test_protocol_parse_invalid(void) {
    TEST("protocol parse invalid json");

    rpc_request_t req;
    int ret = protocol_parse_request("not json", &req);
    if (ret != PROTOCOL_ERR_PARSE)
        FAIL("should fail");

    ret = protocol_parse_request("{\"method\":\"ping\"}", &req);
    if (ret != PROTOCOL_ERR_PARSE)
        FAIL("missing id should fail");

    ret = protocol_parse_request("{\"id\":1}", &req);
    if (ret != PROTOCOL_ERR_PARSE)
        FAIL("missing method should fail");

    PASS();
    return 0;
}

static int test_protocol_format_response(void) {
    TEST("protocol format response");

    rpc_response_t resp;
    memset(&resp, 0, sizeof(resp));
    protocol_success(&resp, 123, "{\"ok\":true}");

    char buf[256];
    int len = protocol_format_response(&resp, buf, sizeof(buf));
    if (len <= 0)
        FAIL("format failed");
    if (strstr(buf, "\"id\":123") == NULL)
        FAIL("missing id");
    if (strstr(buf, "\"result\"") == NULL)
        FAIL("missing result");

    PASS();
    return 0;
}

static int test_protocol_format_error(void) {
    TEST("protocol format error response");

    rpc_response_t resp;
    memset(&resp, 0, sizeof(resp));
    protocol_error(&resp, 456, -32600, "Invalid request");

    char buf[256];
    int len = protocol_format_response(&resp, buf, sizeof(buf));
    if (len <= 0)
        FAIL("format failed");
    if (strstr(buf, "\"id\":456") == NULL)
        FAIL("missing id");
    if (strstr(buf, "\"error\"") == NULL)
        FAIL("missing error");
    if (strstr(buf, "-32600") == NULL)
        FAIL("missing code");

    PASS();
    return 0;
}

static int test_protocol_dkg_params(void) {
    TEST("protocol parse DKG params");

    rpc_request_t req;
    const char *json = "{\"id\":1,\"method\":\"dkg_init\",\"params\":{\"group\":\"dkg_test\","
                       "\"threshold\":2,\"participant_count\":3,\"our_index\":1}}";

    int ret = protocol_parse_request(json, &req);
    if (ret != 0)
        FAIL("parse failed");
    if (req.method != RPC_METHOD_DKG_INIT)
        FAIL("wrong method");
    if (req.threshold != 2)
        FAIL("wrong threshold");
    if (req.participant_count != 3)
        FAIL("wrong participant_count");
    if (req.our_index != 1)
        FAIL("wrong our_index");

    protocol_free_request(&req);
    PASS();
    return 0;
}
#endif

int main(void) {
    printf("\n=== Integration Native Tests ===\n\n");

    int failures = 0;
    failures += test_session_allocation();
    failures += test_concurrent_sessions_isolation();
    failures += test_session_cleanup_on_timeout();

#ifdef HAS_CJSON
    printf("\n  --- Protocol Tests (cJSON available) ---\n");
    failures += test_protocol_parse_basic();
    failures += test_protocol_parse_with_params();
    failures += test_protocol_parse_invalid();
    failures += test_protocol_format_response();
    failures += test_protocol_format_error();
    failures += test_protocol_dkg_params();
#else
    printf("\n  --- Skipping protocol tests (cJSON not available) ---\n");
#endif

    printf("\n");
    if (failures == 0) {
        printf("=== All tests passed ===\n\n");
        return 0;
    } else {
        printf("=== %d test(s) failed ===\n\n", failures);
        return 1;
    }
}
