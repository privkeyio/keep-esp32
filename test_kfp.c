#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "main/kfp.h"

int test_announce(void) {
    const char *json = "{\"type\":\"announce\",\"version\":1,\"group_pubkey\":\"020102030405060708091011121314151617181920212223242526272829303132\",\"share_index\":2,\"name\":\"esp32\"}";
    kfp_msg_t msg;
    if (kfp_parse(json, &msg) != KFP_MSG_ANNOUNCE) return 1;
    if (msg.announce.share_index != 2) return 2;
    if (msg.announce.group_pubkey[0] != 0x02) return 3;
    if (strcmp(msg.announce.name, "esp32") != 0) return 4;
    char *out = kfp_serialize_announce(&msg.announce);
    if (!out) return 5;
    printf("  Announce: %s\n", out);
    free(out);
    return 0;
}

int test_sign_request(void) {
    const char *json = "{\"type\":\"sign_request\",\"session_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"group_pubkey\":\"02bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"message\":\"48656c6c6f\",\"message_type\":\"raw\",\"participants\":[1,2],\"timestamp\":1234567890}";
    kfp_msg_t msg;
    if (kfp_parse(json, &msg) != KFP_MSG_SIGN_REQUEST) return 1;
    if (msg.sign_request.message_len != 5) return 2;
    if (msg.sign_request.message[0] != 0x48) return 3;
    if (msg.sign_request.participant_count != 2) return 4;
    if (msg.sign_request.participants[0] != 1) return 5;
    printf("  SignRequest: session=%02x%02x..., msg_len=%zu, parts=%d\n",
           msg.sign_request.session_id[0], msg.sign_request.session_id[1],
           msg.sign_request.message_len, msg.sign_request.participant_count);
    return 0;
}

int test_commitment(void) {
    const char *json = "{\"type\":\"commitment\",\"session_id\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"share_index\":1,\"commitment\":\"deadbeef\"}";
    kfp_msg_t msg;
    if (kfp_parse(json, &msg) != KFP_MSG_COMMITMENT) return 1;
    if (msg.commitment.share_index != 1) return 2;
    if (msg.commitment.commitment_len != 4) return 3;
    char *out = kfp_serialize_commitment(&msg.commitment);
    if (!out) return 4;
    printf("  Commitment: %s\n", out);
    free(out);
    return 0;
}

int test_signature_share(void) {
    const char *json = "{\"type\":\"signature_share\",\"session_id\":\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"share_index\":2,\"signature_share\":\"cafebabe\"}";
    kfp_msg_t msg;
    if (kfp_parse(json, &msg) != KFP_MSG_SIGNATURE_SHARE) return 1;
    if (msg.signature_share.share_index != 2) return 2;
    char *out = kfp_serialize_signature_share(&msg.signature_share);
    if (!out) return 3;
    printf("  SigShare: %s\n", out);
    free(out);
    return 0;
}

int test_ping_pong(void) {
    const char *json = "{\"type\":\"ping\",\"challenge\":\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\",\"timestamp\":9999}";
    kfp_msg_t msg;
    if (kfp_parse(json, &msg) != KFP_MSG_PING) return 1;
    kfp_pong_t pong = { .timestamp = 10000 };
    memcpy(pong.challenge, msg.ping.challenge, 32);
    char *out = kfp_serialize_pong(&pong);
    if (!out) return 2;
    printf("  Pong: %s\n", out);
    free(out);
    return 0;
}

int main(void) {
    printf("=== KFP Protocol Tests ===\n");
    int failed = 0;

    printf("Test announce: ");
    int r = test_announce();
    printf("%s\n", r == 0 ? "PASS" : "FAIL");
    if (r) failed++;

    printf("Test sign_request: ");
    r = test_sign_request();
    printf("%s\n", r == 0 ? "PASS" : "FAIL");
    if (r) failed++;

    printf("Test commitment: ");
    r = test_commitment();
    printf("%s\n", r == 0 ? "PASS" : "FAIL");
    if (r) failed++;

    printf("Test signature_share: ");
    r = test_signature_share();
    printf("%s\n", r == 0 ? "PASS" : "FAIL");
    if (r) failed++;

    printf("Test ping/pong: ");
    r = test_ping_pong();
    printf("%s\n", r == 0 ? "PASS" : "FAIL");
    if (r) failed++;

    printf("\nResults: %d/5 passed\n", 5 - failed);
    return failed;
}
