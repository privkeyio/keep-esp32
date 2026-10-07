// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "frost_signer_storage.h"
#include "hex_utils.h"

#define TEST(name) printf("  TEST: %s\n", name)
#define PASS()     printf("    PASS\n")
#define FAIL(msg)                      \
    do {                               \
        printf("    FAIL: %s\n", msg); \
        return 1;                      \
    } while (0)

/* One slot of share storage, holding hex as storage.c's API does. */
static char stored_hex[STORAGE_SHARE_LEN * 2 + 1];
static bool stored = false;

int storage_save_share(const char *group, const char *share_hex) {
    (void)group;
    if (strlen(share_hex) > STORAGE_SHARE_LEN * 2) {
        return STORAGE_ERR_INVALID_DATA;
    }
    strcpy(stored_hex, share_hex);
    stored = true;
    return STORAGE_OK;
}

int storage_load_share(const char *group, char *share_hex, size_t len) {
    (void)group;
    if (!stored || strlen(stored_hex) >= len) {
        return STORAGE_ERR_NOT_FOUND;
    }
    strcpy(share_hex, stored_hex);
    return STORAGE_OK;
}

static share_key_t sample(size_t kp_len) {
    share_key_t k = {.key_package_len = kp_len, .participants = 0x0105};
    for (size_t i = 0; i < kp_len; i++) {
        k.key_package[i] = (uint8_t)(i * 7 + 1);
    }
    return k;
}

static int test_round_trip(void) {
    TEST("a payload decodes to the key it encoded");
    share_key_t k = sample(136), out;
    uint8_t buf[STORAGE_SHARE_LEN] = {0};
    size_t len = 0;
    if (share_payload_encode(&k, buf, &len) != SHARE_KEY_OK || len != 139)
        FAIL("encode");
    if (buf[0] != SHARE_PAYLOAD_VERSION || buf[1] != 0x01 || buf[2] != 0x05)
        FAIL("header is version, then participants big-endian");
    if (share_payload_decode(buf, len, &out) != SHARE_KEY_OK)
        FAIL("decode");
    if (out.participants != k.participants || out.key_package_len != k.key_package_len ||
        memcmp(out.key_package, k.key_package, k.key_package_len) != 0)
        FAIL("round trip changed the key");
    PASS();
    return 0;
}

static int test_legacy_lengths(void) {
    TEST("102- and 104-byte shares are reported as legacy, whatever their first byte");
    uint8_t buf[STORAGE_SHARE_LEN] = {0};
    share_key_t out;
    for (int first = 0; first < 2; first++) {
        memset(buf, 0x11, sizeof(buf));
        buf[0] = first ? SHARE_PAYLOAD_VERSION : 0x7f;
        if (share_payload_decode(buf, 102, &out) != SHARE_KEY_ERR_LEGACY ||
            share_payload_decode(buf, 104, &out) != SHARE_KEY_ERR_LEGACY)
            FAIL("legacy length not recognized");
    }
    share_key_t k = sample(99);
    size_t len = 0;
    if (share_payload_encode(&k, buf, &len) != SHARE_KEY_ERR_DECODE)
        FAIL("a payload that would look legacy was encoded");
    k = sample(101);
    if (share_payload_encode(&k, buf, &len) != SHARE_KEY_ERR_DECODE)
        FAIL("a payload that would look legacy was encoded");
    PASS();
    return 0;
}

static int test_malformed(void) {
    TEST("malformed payloads are refused");
    uint8_t buf[STORAGE_SHARE_LEN] = {0};
    share_key_t out;
    memset(buf, 0, sizeof(buf));
    buf[0] = SHARE_PAYLOAD_VERSION;
    if (share_payload_decode(buf, 3, &out) != SHARE_KEY_ERR_DECODE)
        FAIL("header only accepted");
    if (share_payload_decode(buf, STORAGE_SHARE_LEN + 1, &out) != SHARE_KEY_ERR_DECODE)
        FAIL("oversized accepted");
    buf[0] = 0x01;
    if (share_payload_decode(buf, 139, &out) != SHARE_KEY_ERR_DECODE)
        FAIL("wrong version accepted");
    share_key_t k = sample(0);
    size_t len = 0;
    if (share_payload_encode(&k, buf, &len) != SHARE_KEY_ERR_DECODE)
        FAIL("empty key package encoded");
    k = sample(SHARE_KEY_PACKAGE_MAX);
    if (share_payload_encode(&k, buf, &len) != SHARE_KEY_OK || len != STORAGE_SHARE_LEN)
        FAIL("largest key package refused");
    k.key_package_len = SHARE_KEY_PACKAGE_MAX + 1;
    if (share_payload_encode(&k, buf, &len) != SHARE_KEY_ERR_DECODE)
        FAIL("key package past the slot encoded");
    PASS();
    return 0;
}

static int test_store(void) {
    TEST("save and load go through share storage");
    stored = false;
    share_key_t out;
    if (share_key_load("g", &out) != SHARE_KEY_ERR_NOT_FOUND)
        FAIL("empty storage loaded");
    share_key_t k = sample(136);
    if (share_key_save("g", &k) != STORAGE_OK)
        FAIL("save");
    if (share_key_load("g", &out) != SHARE_KEY_OK || out.participants != k.participants ||
        memcmp(out.key_package, k.key_package, 136) != 0)
        FAIL("load");
    strcpy(stored_hex, "");
    for (int i = 0; i < 104; i++)
        strcat(stored_hex, "ab");
    if (share_key_load("g", &out) != SHARE_KEY_ERR_LEGACY)
        FAIL("legacy share loaded as a key");
    if (out.key_package_len != 0 || out.participants != 0)
        FAIL("refused load left data behind");
    uint8_t raw[STORAGE_SHARE_LEN];
    size_t len = 0;
    if (share_raw_load("g", raw, &len) != SHARE_KEY_OK || len != 104 || raw[0] != 0xab)
        FAIL("raw load");
    strcpy(stored_hex, "abc");
    if (share_key_load("g", &out) != SHARE_KEY_ERR_DECODE)
        FAIL("bad hex loaded");
    PASS();
    return 0;
}

int main(void) {
    printf("Share payload tests\n");
    int failed = 0;
    failed += test_round_trip();
    failed += test_legacy_lengths();
    failed += test_malformed();
    failed += test_store();
    printf("%s: %d failed\n", failed ? "FAILED" : "OK", failed);
    return failed ? 1 : 0;
}
