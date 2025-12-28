#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "cJSON.h"
#include "protocol.h"

static void test_parse_ping(void) {
    const char *json = "{\"id\":1,\"method\":\"ping\"}";
    rpc_request_t req;

    int result = protocol_parse_request(json, &req);
    assert(result == 0);
    assert(req.id == 1);
    assert(req.method == RPC_METHOD_PING);

    printf("PASS: parse ping\n");
}

static void test_parse_frost_sign(void) {
    const char *json = "{\"id\":42,\"method\":\"frost_sign\",\"params\":{\"group\":\"npub1abc\",\"message\":\"deadbeef\"}}";
    rpc_request_t req;

    int result = protocol_parse_request(json, &req);
    assert(result == 0);
    assert(req.id == 42);
    assert(req.method == RPC_METHOD_FROST_SIGN);
    assert(strcmp(req.group, "npub1abc") == 0);
    assert(strcmp(req.message, "deadbeef") == 0);

    printf("PASS: parse frost_sign\n");
}

static void test_parse_import_share(void) {
    const char *json = "{\"id\":5,\"method\":\"import_share\",\"params\":{\"group\":\"npub1xyz\",\"share\":\"aabbcc\"}}";
    rpc_request_t req;

    int result = protocol_parse_request(json, &req);
    assert(result == 0);
    assert(req.id == 5);
    assert(req.method == RPC_METHOD_IMPORT_SHARE);
    assert(strcmp(req.group, "npub1xyz") == 0);
    assert(strcmp(req.share, "aabbcc") == 0);

    printf("PASS: parse import_share\n");
}

static void test_parse_invalid_json(void) {
    const char *json = "not json";
    rpc_request_t req;

    int result = protocol_parse_request(json, &req);
    assert(result == PROTOCOL_ERR_PARSE);

    printf("PASS: parse invalid json\n");
}

static void test_parse_missing_id(void) {
    const char *json = "{\"method\":\"ping\"}";
    rpc_request_t req;

    int result = protocol_parse_request(json, &req);
    assert(result == PROTOCOL_ERR_PARSE);

    printf("PASS: parse missing id\n");
}

static void test_format_success(void) {
    rpc_response_t resp;
    protocol_success(&resp, 1, "{\"pong\":true}");

    char buf[256];
    int len = protocol_format_response(&resp, buf, sizeof(buf));
    assert(len > 0);
    assert(strstr(buf, "\"id\":1") != NULL);
    assert(strstr(buf, "\"result\"") != NULL);
    assert(strstr(buf, "\"pong\":true") != NULL);

    printf("PASS: format success response\n");
}

static void test_format_error(void) {
    rpc_response_t resp;
    protocol_error(&resp, 2, -1, "Share not found");

    char buf[256];
    int len = protocol_format_response(&resp, buf, sizeof(buf));
    assert(len > 0);
    assert(strstr(buf, "\"id\":2") != NULL);
    assert(strstr(buf, "\"error\"") != NULL);
    assert(strstr(buf, "\"code\":-1") != NULL);
    assert(strstr(buf, "Share not found") != NULL);

    printf("PASS: format error response\n");
}

static void test_all_methods(void) {
    struct {
        const char *json;
        rpc_method_t expected;
    } cases[] = {
        {"{\"id\":1,\"method\":\"ping\"}", RPC_METHOD_PING},
        {"{\"id\":1,\"method\":\"get_share_pubkey\"}", RPC_METHOD_GET_SHARE_PUBKEY},
        {"{\"id\":1,\"method\":\"frost_sign\"}", RPC_METHOD_FROST_SIGN},
        {"{\"id\":1,\"method\":\"import_share\"}", RPC_METHOD_IMPORT_SHARE},
        {"{\"id\":1,\"method\":\"delete_share\"}", RPC_METHOD_DELETE_SHARE},
        {"{\"id\":1,\"method\":\"list_shares\"}", RPC_METHOD_LIST_SHARES},
        {"{\"id\":1,\"method\":\"unknown_method\"}", RPC_METHOD_UNKNOWN},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        rpc_request_t req;
        int result = protocol_parse_request(cases[i].json, &req);
        assert(result == 0);
        assert(req.method == cases[i].expected);
    }

    printf("PASS: all method types\n");
}

int main(void) {
    printf("=== Protocol Tests ===\n");

    test_parse_ping();
    test_parse_frost_sign();
    test_parse_import_share();
    test_parse_invalid_json();
    test_parse_missing_id();
    test_format_success();
    test_format_error();
    test_all_methods();

    printf("\n=== All tests passed ===\n");
    return 0;
}
