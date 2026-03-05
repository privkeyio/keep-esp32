// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "cJSON.h"
#include "protocol.h"

#define TEST(name) printf("  TEST: %s\n", name)
#define PASS()     printf("    PASS\n")
#define FAIL(msg)                      \
    do {                               \
        printf("    FAIL: %s\n", msg); \
        return 1;                      \
    } while (0)

static int test_parse_ping(void) {
    TEST("parse ping");
    const char *json = "{\"id\":1,\"method\":\"ping\"}";
    rpc_request_t req;
    int result = protocol_parse_request(json, &req);
    if (result != 0)
        FAIL("parse failed");
    if (req.id != 1)
        FAIL("wrong id");
    if (req.method != RPC_METHOD_PING)
        FAIL("wrong method");
    protocol_free_request(&req);
    PASS();
    return 0;
}

static int test_parse_frost_sign(void) {
    TEST("parse frost_sign");
    const char *json = "{\"id\":42,\"method\":\"frost_sign\",\"params\":{\"group\":\"npub1abc\","
                       "\"message\":\"deadbeef\"}}";
    rpc_request_t req;
    int result = protocol_parse_request(json, &req);
    if (result != 0)
        FAIL("parse failed");
    if (req.id != 42)
        FAIL("wrong id");
    if (req.method != RPC_METHOD_FROST_SIGN)
        FAIL("wrong method");
    if (strcmp(req.group, "npub1abc") != 0)
        FAIL("wrong group");
    if (strcmp(req.message, "deadbeef") != 0)
        FAIL("wrong message");
    protocol_free_request(&req);
    PASS();
    return 0;
}

static int test_parse_import_share(void) {
    TEST("parse import_share");
    const char *json = "{\"id\":5,\"method\":\"import_share\",\"params\":{\"group\":\"npub1xyz\","
                       "\"share\":\"aabbcc\"}}";
    rpc_request_t req;
    int result = protocol_parse_request(json, &req);
    if (result != 0)
        FAIL("parse failed");
    if (req.id != 5)
        FAIL("wrong id");
    if (req.method != RPC_METHOD_IMPORT_SHARE)
        FAIL("wrong method");
    if (strcmp(req.group, "npub1xyz") != 0)
        FAIL("wrong group");
    if (strcmp(req.share, "aabbcc") != 0)
        FAIL("wrong share");
    protocol_free_request(&req);
    PASS();
    return 0;
}

static int test_parse_invalid_json(void) {
    TEST("parse invalid json");
    rpc_request_t req;
    if (protocol_parse_request("not json", &req) != PROTOCOL_ERR_PARSE)
        FAIL("should fail");
    if (protocol_parse_request("{incomplete", &req) != PROTOCOL_ERR_PARSE)
        FAIL("incomplete should fail");
    if (protocol_parse_request("", &req) != PROTOCOL_ERR_PARSE)
        FAIL("empty should fail");
    if (protocol_parse_request("null", &req) != PROTOCOL_ERR_PARSE)
        FAIL("null should fail");
    if (protocol_parse_request("[]", &req) != PROTOCOL_ERR_PARSE)
        FAIL("array should fail");
    PASS();
    return 0;
}

static int test_parse_missing_id(void) {
    TEST("parse missing id");
    rpc_request_t req;
    if (protocol_parse_request("{\"method\":\"ping\"}", &req) != PROTOCOL_ERR_PARSE)
        FAIL("should fail");
    PASS();
    return 0;
}

static int test_parse_missing_method(void) {
    TEST("parse missing method");
    rpc_request_t req;
    if (protocol_parse_request("{\"id\":1}", &req) != PROTOCOL_ERR_PARSE)
        FAIL("should fail");
    PASS();
    return 0;
}

static int test_parse_id_wrong_type(void) {
    TEST("parse id wrong type");
    rpc_request_t req;
    if (protocol_parse_request("{\"id\":\"str\",\"method\":\"ping\"}", &req) != PROTOCOL_ERR_PARSE)
        FAIL("string id should fail");
    if (protocol_parse_request("{\"id\":null,\"method\":\"ping\"}", &req) != PROTOCOL_ERR_PARSE)
        FAIL("null id should fail");
    PASS();
    return 0;
}

static int test_parse_method_wrong_type(void) {
    TEST("parse method wrong type");
    rpc_request_t req;
    if (protocol_parse_request("{\"id\":1,\"method\":123}", &req) != PROTOCOL_ERR_PARSE)
        FAIL("number method should fail");
    if (protocol_parse_request("{\"id\":1,\"method\":null}", &req) != PROTOCOL_ERR_PARSE)
        FAIL("null method should fail");
    PASS();
    return 0;
}

static int test_format_success(void) {
    TEST("format success response");
    rpc_response_t resp;
    protocol_success(&resp, 1, "{\"pong\":true}");
    char buf[256];
    int len = protocol_format_response(&resp, buf, sizeof(buf));
    if (len <= 0)
        FAIL("format failed");
    if (strstr(buf, "\"id\":1") == NULL)
        FAIL("missing id");
    if (strstr(buf, "\"result\"") == NULL)
        FAIL("missing result");
    if (strstr(buf, "\"pong\":true") == NULL)
        FAIL("missing pong");
    PASS();
    return 0;
}

static int test_format_error(void) {
    TEST("format error response");
    rpc_response_t resp;
    protocol_error(&resp, 2, -1, "Share not found");
    char buf[256];
    int len = protocol_format_response(&resp, buf, sizeof(buf));
    if (len <= 0)
        FAIL("format failed");
    if (strstr(buf, "\"id\":2") == NULL)
        FAIL("missing id");
    if (strstr(buf, "\"error\"") == NULL)
        FAIL("missing error");
    if (strstr(buf, "\"code\":-32603") == NULL)
        FAIL("missing code");
    if (strstr(buf, "Share not found") == NULL)
        FAIL("missing message");
    if (strstr(buf, "\"context\"") != NULL)
        FAIL("should not have context");
    PASS();
    return 0;
}

static int test_format_error_with_context(void) {
    TEST("format error response with context");
    rpc_response_t resp;
    PROTOCOL_ERROR(&resp, 3, -2, "Test error");
    char buf[512];
    int len = protocol_format_response(&resp, buf, sizeof(buf));
    if (len <= 0)
        FAIL("format failed");
    if (strstr(buf, "\"id\":3") == NULL)
        FAIL("missing id");
    if (strstr(buf, "\"error\"") == NULL)
        FAIL("missing error");
    if (strstr(buf, "\"code\":-32603") == NULL)
        FAIL("missing code");
    if (strstr(buf, "Test error") == NULL)
        FAIL("missing message");
    if (strstr(buf, "\"context\"") == NULL)
        FAIL("missing context");
    if (strstr(buf, "\"file\"") == NULL)
        FAIL("missing file");
    if (strstr(buf, "\"line\"") == NULL)
        FAIL("missing line");
    if (strstr(buf, "\"func\"") == NULL)
        FAIL("missing func");
    if (strstr(buf, "test_protocol.c") == NULL)
        FAIL("wrong file");
    PASS();
    return 0;
}

static int test_all_methods(void) {
    TEST("all method types");
    struct {
        const char *json;
        rpc_method_t expected;
    } cases[] = {
        {"{\"id\":1,\"method\":\"ping\"}", RPC_METHOD_PING},
        {"{\"id\":1,\"method\":\"get_share_pubkey\"}", RPC_METHOD_GET_SHARE_PUBKEY},
        {"{\"id\":1,\"method\":\"get_share_info\"}", RPC_METHOD_GET_SHARE_INFO},
        {"{\"id\":1,\"method\":\"frost_commit\"}", RPC_METHOD_FROST_COMMIT},
        {"{\"id\":1,\"method\":\"frost_sign\"}", RPC_METHOD_FROST_SIGN},
        {"{\"id\":1,\"method\":\"import_share\"}", RPC_METHOD_IMPORT_SHARE},
        {"{\"id\":1,\"method\":\"delete_share\"}", RPC_METHOD_DELETE_SHARE},
        {"{\"id\":1,\"method\":\"list_shares\"}", RPC_METHOD_LIST_SHARES},
        {"{\"id\":1,\"method\":\"dkg_init\"}", RPC_METHOD_DKG_INIT},
        {"{\"id\":1,\"method\":\"dkg_round1\"}", RPC_METHOD_DKG_ROUND1},
        {"{\"id\":1,\"method\":\"dkg_round1_peer\"}", RPC_METHOD_DKG_ROUND1_PEER},
        {"{\"id\":1,\"method\":\"dkg_round2\"}", RPC_METHOD_DKG_ROUND2},
        {"{\"id\":1,\"method\":\"dkg_receive_share\"}", RPC_METHOD_DKG_RECEIVE_SHARE},
        {"{\"id\":1,\"method\":\"dkg_finalize\"}", RPC_METHOD_DKG_FINALIZE},
        {"{\"id\":1,\"method\":\"bitcoin_parse\"}", RPC_METHOD_BITCOIN_PARSE},
        {"{\"id\":1,\"method\":\"bitcoin_sign\"}", RPC_METHOD_BITCOIN_SIGN},
        {"{\"id\":1,\"method\":\"policy_update\"}", RPC_METHOD_POLICY_UPDATE},
        {"{\"id\":1,\"method\":\"policy_get\"}", RPC_METHOD_POLICY_GET},
        {"{\"id\":1,\"method\":\"unknown_method\"}", RPC_METHOD_UNKNOWN},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        rpc_request_t req;
        int result = protocol_parse_request(cases[i].json, &req);
        if (result != 0)
            FAIL("parse failed");
        if (req.method != cases[i].expected)
            FAIL("wrong method");
        protocol_free_request(&req);
    }
    PASS();
    return 0;
}

static int test_threshold_boundary(void) {
    TEST("threshold boundary");
    rpc_request_t req;
    if (protocol_parse_request("{\"id\":1,\"method\":\"dkg_init\",\"params\":{\"threshold\":0}}",
                               &req) != 0)
        FAIL("0 should work");
    protocol_free_request(&req);
    if (protocol_parse_request("{\"id\":1,\"method\":\"dkg_init\",\"params\":{\"threshold\":16}}",
                               &req) != 0)
        FAIL("16 should work");
    protocol_free_request(&req);
    if (protocol_parse_request("{\"id\":1,\"method\":\"dkg_init\",\"params\":{\"threshold\":17}}",
                               &req) != PROTOCOL_ERR_PARAMS)
        FAIL("17 should fail");
    if (protocol_parse_request("{\"id\":1,\"method\":\"dkg_init\",\"params\":{\"threshold\":-1}}",
                               &req) != PROTOCOL_ERR_PARAMS)
        FAIL("-1 should fail");
    PASS();
    return 0;
}

static int test_participant_count_boundary(void) {
    TEST("participant_count boundary");
    rpc_request_t req;
    if (protocol_parse_request(
            "{\"id\":1,\"method\":\"dkg_init\",\"params\":{\"participant_count\":16}}", &req) != 0)
        FAIL("16 should work");
    protocol_free_request(&req);
    if (protocol_parse_request(
            "{\"id\":1,\"method\":\"dkg_init\",\"params\":{\"participant_count\":17}}", &req) !=
        PROTOCOL_ERR_PARAMS)
        FAIL("17 should fail");
    PASS();
    return 0;
}

static int test_our_index_boundary(void) {
    TEST("our_index boundary");
    rpc_request_t req;
    if (protocol_parse_request("{\"id\":1,\"method\":\"dkg_init\",\"params\":{\"our_index\":16}}",
                               &req) != 0)
        FAIL("16 should work");
    protocol_free_request(&req);
    if (protocol_parse_request("{\"id\":1,\"method\":\"dkg_init\",\"params\":{\"our_index\":17}}",
                               &req) != PROTOCOL_ERR_PARAMS)
        FAIL("17 should fail");
    PASS();
    return 0;
}

static int test_peer_index_boundary(void) {
    TEST("peer_index boundary");
    rpc_request_t req;
    if (protocol_parse_request(
            "{\"id\":1,\"method\":\"dkg_round1_peer\",\"params\":{\"peer_index\":16}}", &req) != 0)
        FAIL("16 should work");
    protocol_free_request(&req);
    if (protocol_parse_request(
            "{\"id\":1,\"method\":\"dkg_round1_peer\",\"params\":{\"peer_index\":17}}", &req) !=
        PROTOCOL_ERR_PARAMS)
        FAIL("17 should fail");
    PASS();
    return 0;
}

static int test_psbt_too_long(void) {
    TEST("psbt too long");
    static char json[PROTOCOL_MAX_PSBT_LEN + 256];
    static char psbt[PROTOCOL_MAX_PSBT_LEN + 1];
    memset(psbt, 'a', PROTOCOL_MAX_PSBT_LEN);
    psbt[PROTOCOL_MAX_PSBT_LEN] = '\0';
    snprintf(json, sizeof(json),
             "{\"id\":1,\"method\":\"bitcoin_sign\",\"params\":{\"psbt\":\"%s\"}}", psbt);
    rpc_request_t req;
    if (protocol_parse_request(json, &req) != PROTOCOL_ERR_PARAMS)
        FAIL("should fail");
    PASS();
    return 0;
}

static int test_psbt_allocation(void) {
    TEST("psbt allocation and free");
    rpc_request_t req;
    if (protocol_parse_request(
            "{\"id\":1,\"method\":\"bitcoin_sign\",\"params\":{\"psbt\":\"cHNidP8B\"}}", &req) != 0)
        FAIL("parse failed");
    if (req.psbt[0] == '\0')
        FAIL("psbt should be populated");
    if (strcmp(req.psbt, "cHNidP8B") != 0)
        FAIL("wrong psbt value");
    protocol_free_request(&req);
    PASS();
    return 0;
}

static int test_dkg_params(void) {
    TEST("dkg params");
    rpc_request_t req;
    if (protocol_parse_request("{\"id\":1,\"method\":\"dkg_round1\",\"params\":{\"group\":\"test\","
                               "\"dkg_data\":\"abc123\"}}",
                               &req) != 0)
        FAIL("parse failed");
    if (strcmp(req.group, "test") != 0)
        FAIL("wrong group");
    if (strcmp(req.dkg_data, "abc123") != 0)
        FAIL("wrong dkg_data");
    protocol_free_request(&req);
    PASS();
    return 0;
}

static int test_session_id_param(void) {
    TEST("session_id param");
    rpc_request_t req;
    if (protocol_parse_request(
            "{\"id\":1,\"method\":\"frost_commit\",\"params\":{\"session_id\":\"deadbeef\"}}",
            &req) != 0)
        FAIL("parse failed");
    if (strcmp(req.session_id, "deadbeef") != 0)
        FAIL("wrong session_id");
    protocol_free_request(&req);
    PASS();
    return 0;
}

static int test_commitments_param(void) {
    TEST("commitments param");
    rpc_request_t req;
    if (protocol_parse_request(
            "{\"id\":1,\"method\":\"frost_sign\",\"params\":{\"commitments\":\"aabbccdd\"}}",
            &req) != 0)
        FAIL("parse failed");
    if (strcmp(req.commitments, "aabbccdd") != 0)
        FAIL("wrong commitments");
    protocol_free_request(&req);
    PASS();
    return 0;
}

static int test_policy_bundle_param(void) {
    TEST("policy bundle param");
    rpc_request_t req;
    if (protocol_parse_request(
            "{\"id\":1,\"method\":\"policy_update\",\"params\":{\"bundle\":\"data\"}}", &req) != 0)
        FAIL("parse failed");
    if (strcmp(req.policy_bundle, "data") != 0)
        FAIL("wrong bundle");
    protocol_free_request(&req);
    PASS();
    return 0;
}

static int test_input_idx_param(void) {
    TEST("input_idx param");
    rpc_request_t req;
    if (protocol_parse_request(
            "{\"id\":1,\"method\":\"bitcoin_sign\",\"params\":{\"input_idx\":5}}", &req) != 0)
        FAIL("parse failed");
    if (req.input_idx != 5)
        FAIL("wrong input_idx");
    protocol_free_request(&req);
    PASS();
    return 0;
}

static int test_format_buffer_too_small(void) {
    TEST("format buffer too small");
    rpc_response_t resp;
    protocol_success(&resp, 1, "{\"data\":\"test\"}");
    char small[10];
    int len = protocol_format_response(&resp, small, sizeof(small));
    if (len != -1)
        FAIL("should fail with small buffer");
    PASS();
    return 0;
}

static int test_empty_params(void) {
    TEST("empty params object");
    rpc_request_t req;
    if (protocol_parse_request("{\"id\":1,\"method\":\"ping\",\"params\":{}}", &req) != 0)
        FAIL("parse failed");
    if (req.method != RPC_METHOD_PING)
        FAIL("wrong method");
    protocol_free_request(&req);
    PASS();
    return 0;
}

static int test_null_params(void) {
    TEST("null params");
    rpc_request_t req;
    if (protocol_parse_request("{\"id\":1,\"method\":\"ping\",\"params\":null}", &req) != 0)
        FAIL("parse failed");
    protocol_free_request(&req);
    PASS();
    return 0;
}

static int test_negative_id(void) {
    TEST("negative id");
    rpc_request_t req;
    if (protocol_parse_request("{\"id\":-5,\"method\":\"ping\"}", &req) != 0)
        FAIL("parse failed");
    if (req.id != -5)
        FAIL("wrong id");
    protocol_free_request(&req);
    PASS();
    return 0;
}

static int test_parse_null_input(void) {
    TEST("parse null input");
    rpc_request_t req;
    if (protocol_parse_request(NULL, &req) != PROTOCOL_ERR_PARSE)
        FAIL("NULL json should fail");
    if (protocol_parse_request("{\"id\":1,\"method\":\"ping\"}", NULL) != PROTOCOL_ERR_PARSE)
        FAIL("NULL req should fail");
    PASS();
    return 0;
}

static int test_format_null_input(void) {
    TEST("format null input");
    rpc_response_t resp;
    char buf[256];
    protocol_success(&resp, 1, "{\"ok\":true}");
    if (protocol_format_response(NULL, buf, sizeof(buf)) != -1)
        FAIL("NULL resp should fail");
    if (protocol_format_response(&resp, NULL, sizeof(buf)) != -1)
        FAIL("NULL buf should fail");
    if (protocol_format_response(&resp, buf, 0) != -1)
        FAIL("zero len should fail");
    PASS();
    return 0;
}

int main(void) {
    printf("\n=== Protocol Native Tests ===\n\n");

    int failures = 0;
    failures += test_parse_ping();
    failures += test_parse_frost_sign();
    failures += test_parse_import_share();
    failures += test_parse_invalid_json();
    failures += test_parse_missing_id();
    failures += test_parse_missing_method();
    failures += test_parse_id_wrong_type();
    failures += test_parse_method_wrong_type();
    failures += test_format_success();
    failures += test_format_error();
    failures += test_format_error_with_context();
    failures += test_all_methods();
    failures += test_threshold_boundary();
    failures += test_participant_count_boundary();
    failures += test_our_index_boundary();
    failures += test_peer_index_boundary();
    failures += test_psbt_too_long();
    failures += test_psbt_allocation();
    failures += test_dkg_params();
    failures += test_session_id_param();
    failures += test_commitments_param();
    failures += test_policy_bundle_param();
    failures += test_input_idx_param();
    failures += test_format_buffer_too_small();
    failures += test_empty_params();
    failures += test_null_params();
    failures += test_negative_id();
    failures += test_parse_null_input();
    failures += test_format_null_input();

    printf("\n");
    if (failures == 0) {
        printf("=== All tests passed ===\n\n");
        return 0;
    } else {
        printf("=== %d test(s) failed ===\n\n", failures);
        return 1;
    }
}
