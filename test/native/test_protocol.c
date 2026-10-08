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
                       "\"key_package\":\"aabbcc\",\"participants\":3}}";
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
    if (strcmp(req.key_package, "aabbcc") != 0 || req.participants != 3)
        FAIL("wrong key_package or participants");
    if (req.legacy_share)
        FAIL("no share field was sent");
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
        {"{\"id\":1,\"method\":\"dkg_init\"}", RPC_METHOD_RETIRED},
        {"{\"id\":1,\"method\":\"dkg_round1\"}", RPC_METHOD_RETIRED},
        {"{\"id\":1,\"method\":\"dkg_checkpoint\"}", RPC_METHOD_RETIRED},
        {"{\"id\":1,\"method\":\"frost_session_resume\"}", RPC_METHOD_RETIRED},
        {"{\"id\":1,\"method\":\"frost_session_list\"}", RPC_METHOD_RETIRED},
        {"{\"id\":1,\"method\":\"dkg\"}", RPC_METHOD_UNKNOWN},
        {"{\"id\":1,\"method\":\"unlock\"}", RPC_METHOD_UNLOCK},
        {"{\"id\":1,\"method\":\"export_share\"}", RPC_METHOD_EXPORT_SHARE},
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

static int test_participants_boundary(void) {
    TEST("participants boundary");
    rpc_request_t req;
    if (protocol_parse_request(
            "{\"id\":1,\"method\":\"import_share\",\"params\":{\"participants\":16}}", &req) != 0 ||
        req.participants != 16)
        FAIL("16 should be accepted");
    protocol_free_request(&req);
    if (protocol_parse_request(
            "{\"id\":1,\"method\":\"import_share\",\"params\":{\"participants\":17}}", &req) !=
        ERR_PROTOCOL_PARAMS)
        FAIL("17 should be rejected");
    if (protocol_parse_request(
            "{\"id\":1,\"method\":\"import_share\",\"params\":{\"participants\":-1}}", &req) !=
        ERR_PROTOCOL_PARAMS)
        FAIL("-1 should be rejected");
    PASS();
    return 0;
}

static int hex_param_request(const char *method, const char *name, size_t len, rpc_request_t *req) {
    static char json[PROTOCOL_SIGNING_PACKAGE_HEX + 256];
    int n = snprintf(json, sizeof(json), "{\"id\":1,\"method\":\"%s\",\"params\":{\"%s\":\"",
                     method, name);
    memset(json + n, 'a', len);
    snprintf(json + n + len, sizeof(json) - n - len, "\"}}");
    return protocol_parse_request(json, req);
}

static int test_key_package_length(void) {
    TEST("key_package longest accepted, longer refused rather than truncated");
    rpc_request_t req;
    if (hex_param_request("import_share", "key_package", PROTOCOL_KEY_PACKAGE_HEX, &req) != 0 ||
        strlen(req.key_package) != PROTOCOL_KEY_PACKAGE_HEX)
        FAIL("longest key_package should be kept whole");
    protocol_free_request(&req);
    if (hex_param_request("import_share", "key_package", PROTOCOL_KEY_PACKAGE_HEX + 1, &req) !=
        ERR_PROTOCOL_PARAMS)
        FAIL("overlong key_package should be refused");
    PASS();
    return 0;
}

static int test_signing_package_length(void) {
    TEST("signing_package longest accepted, longer refused rather than truncated");
    rpc_request_t req;
    if (hex_param_request("frost_sign", "signing_package", PROTOCOL_SIGNING_PACKAGE_HEX, &req) !=
            0 ||
        strlen(req.signing_package) != PROTOCOL_SIGNING_PACKAGE_HEX)
        FAIL("longest signing_package should be kept whole");
    protocol_free_request(&req);
    if (hex_param_request("frost_sign", "signing_package", PROTOCOL_SIGNING_PACKAGE_HEX + 1,
                          &req) != ERR_PROTOCOL_PARAMS)
        FAIL("overlong signing_package should be refused");
    PASS();
    return 0;
}

static int test_session_id_length(void) {
    TEST("session_id of 64 accepted, longer refused rather than truncated");
    rpc_request_t req;
    if (hex_param_request("frost_commit", "session_id", 64, &req) != 0 ||
        strlen(req.session_id) != 64)
        FAIL("64-character session_id should be kept whole");
    protocol_free_request(&req);
    if (hex_param_request("frost_commit", "session_id", 66, &req) != ERR_PROTOCOL_PARAMS)
        FAIL("66-character session_id should be refused");
    PASS();
    return 0;
}

static int test_derivation_path(void) {
    TEST("derivation_path: unhardened indexes up to 8 deep, anything else refused");
    rpc_request_t req;
    if (protocol_parse_request(
            "{\"id\":1,\"method\":\"frost_commit\",\"params\":{\"derivation_path\":"
            "[0,7,2147483647]}}",
            &req) != 0 ||
        req.derivation_path_len != 3 || req.derivation_path[0] != 0 ||
        req.derivation_path[1] != 7 || req.derivation_path[2] != 2147483647u)
        FAIL("valid path not parsed");
    protocol_free_request(&req);
    if (protocol_parse_request(
            "{\"id\":1,\"method\":\"frost_commit\",\"params\":{\"derivation_path\":"
            "[0,1,2,3,4,5,6,7]}}",
            &req) != 0 ||
        req.derivation_path_len != 8)
        FAIL("eight indexes should be accepted");
    protocol_free_request(&req);
    if (protocol_parse_request("{\"id\":1,\"method\":\"frost_commit\",\"params\":{}}", &req) != 0 ||
        req.derivation_path_len != 0)
        FAIL("no path means an empty path");
    protocol_free_request(&req);
    if (protocol_parse_request(
            "{\"id\":1,\"method\":\"frost_commit\",\"params\":{\"derivation_path\":[]}}", &req) !=
            0 ||
        req.derivation_path_len != 0)
        FAIL("an explicit empty path is the group key");
    protocol_free_request(&req);
    if (protocol_parse_request(
            "{\"id\":1,\"method\":\"frost_commit\",\"params\":{\"Derivation_Path\":[0]}}", &req) !=
            0 ||
        req.derivation_path_len != 0)
        FAIL("only the exact name is the path");
    protocol_free_request(&req);
    if (protocol_parse_request(
            "{\"id\":1,\"method\":\"frost_sign\",\"params\":{\"derivation_path\":[0]}}", &req) !=
        ERR_PROTOCOL_PARAMS)
        FAIL("a path outside frost_commit should be refused");
    const char *bad[] = {"[2147483648]",
                         "[0,1,2,3,4,5,6,7,8]",
                         "[-1]",
                         "[-0]",
                         "[1.5]",
                         "5",
                         "[\"0\"]",
                         "[null]",
                         "[true]",
                         "[1e400]",
                         "{}"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char json[128];
        snprintf(json, sizeof(json),
                 "{\"id\":1,\"method\":\"frost_commit\",\"params\":{\"derivation_path\":%s}}",
                 bad[i]);
        if (protocol_parse_request(json, &req) != ERR_PROTOCOL_PARAMS)
            FAIL(bad[i]);
    }
    PASS();
    return 0;
}

static int test_taproot_tweak(void) {
    TEST("taproot_tweak: an optional 32-byte merkle_root on frost_commit, anything else refused");
    const char *root = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    rpc_request_t req;
    char json[256];
    if (protocol_parse_request("{\"id\":1,\"method\":\"frost_commit\",\"params\":{}}", &req) != 0 ||
        req.taproot_tweak || req.has_merkle_root)
        FAIL("no tweak unless asked");
    protocol_free_request(&req);
    if (protocol_parse_request(
            "{\"id\":1,\"method\":\"frost_commit\",\"params\":{\"taproot_tweak\":{}}}", &req) !=
            0 ||
        !req.taproot_tweak || req.has_merkle_root)
        FAIL("an empty tweak is a key-path spend with no script tree");
    protocol_free_request(&req);
    if (protocol_parse_request(
            "{\"id\":1,\"method\":\"frost_commit\",\"params\":{\"Taproot_Tweak\":{}}}", &req) !=
            0 ||
        req.taproot_tweak)
        FAIL("only the exact name is the tweak");
    protocol_free_request(&req);
    snprintf(json, sizeof(json),
             "{\"id\":1,\"method\":\"frost_commit\",\"params\":{\"derivation_path\":[0,3],"
             "\"taproot_tweak\":{\"merkle_root\":\"%s\"}}}",
             root);
    if (protocol_parse_request(json, &req) != 0 || !req.taproot_tweak || !req.has_merkle_root ||
        req.merkle_root[0] != 0x00 || req.merkle_root[1] != 0x11 || req.merkle_root[31] != 0xff ||
        req.derivation_path_len != 2)
        FAIL("merkle root not parsed");
    protocol_free_request(&req);
    snprintf(json, sizeof(json),
             "{\"id\":1,\"method\":\"frost_sign\",\"params\":{\"taproot_tweak\":{}}}");
    if (protocol_parse_request(json, &req) != ERR_PROTOCOL_PARAMS)
        FAIL("a tweak outside frost_commit should be refused");
    const char *bad[] = {
        "true",
        "null",
        "[]",
        "\"\"",
        "{\"merkle_root\":null}",
        "{\"merkle_root\":\"\"}",
        "{\"merkle_root\":\"0011\"}",
        "{\"merkle_root\":12}",
        "{\"Merkle_root\":\"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\"}",
        "{\"merkle_root\":\"zz112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\"}",
        "{\"merkle_root\":\"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00\"}",
        "{\"root\":\"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\"}",
        "{\"merkle_root\":\"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\","
        "\"extra\":1}",
        "{\"merkle_root\":\"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\","
        "\"merkle_root\":\"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\"}"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char req_json[512];
        snprintf(req_json, sizeof(req_json),
                 "{\"id\":1,\"method\":\"frost_commit\",\"params\":{\"taproot_tweak\":%s}}",
                 bad[i]);
        if (protocol_parse_request(req_json, &req) != ERR_PROTOCOL_PARAMS)
            FAIL(bad[i]);
    }
    PASS();
    return 0;
}

static int test_legacy_share_field(void) {
    TEST("a request with the retired share field is flagged");
    rpc_request_t req;
    if (protocol_parse_request(
            "{\"id\":1,\"method\":\"import_share\",\"params\":{\"share\":\"aa\"}}", &req) != 0 ||
        !req.legacy_share)
        FAIL("share field not flagged");
    protocol_free_request(&req);
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

static int test_signing_package_param(void) {
    TEST("signing_package param");
    rpc_request_t req;
    if (protocol_parse_request(
            "{\"id\":1,\"method\":\"frost_sign\",\"params\":{\"signing_package\":\"aabbccdd\"}}",
            &req) != 0)
        FAIL("parse failed");
    if (strcmp(req.signing_package, "aabbccdd") != 0)
        FAIL("wrong signing_package");
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
    failures += test_participants_boundary();
    failures += test_key_package_length();
    failures += test_signing_package_length();
    failures += test_session_id_length();
    failures += test_derivation_path();
    failures += test_taproot_tweak();
    failures += test_legacy_share_field();
    failures += test_psbt_too_long();
    failures += test_psbt_allocation();
    failures += test_session_id_param();
    failures += test_signing_package_param();
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
