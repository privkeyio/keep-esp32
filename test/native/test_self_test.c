#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "esp_partition.h"
#include "esp_log.h"
#include "crypto_asm.h"
#include "secresult.h"
#include "storage_crypto.h"
#include "nostr.h"

static uint8_t mock_flash[8192];
static esp_partition_t mock_storage = {"storage", 4096, 0};
static esp_partition_t mock_policy = {"policy", 4096, 0};
static bool storage_exists = true;
static bool policy_exists = true;
static bool read_fails = false;
static bool mock_rng_fails = false;
static bool mock_secp256k1_ctx_fails = false;

const esp_partition_t *esp_partition_find_first(esp_partition_type_t type,
                                                esp_partition_subtype_t subtype,
                                                const char *label) {
    (void)type;
    (void)subtype;
    if (strcmp(label, "storage") == 0) {
        return storage_exists ? &mock_storage : NULL;
    }
    if (strcmp(label, "policy") == 0) {
        return policy_exists ? &mock_policy : NULL;
    }
    return NULL;
}

esp_err_t esp_partition_read(const esp_partition_t *partition, size_t src_offset, void *dst,
                             size_t size) {
    if (read_fails)
        return ESP_FAIL;
    if (!partition)
        return ESP_FAIL;
    size_t base = (partition == &mock_policy) ? 4096 : 0;
    if (src_offset + size > 4096)
        return ESP_FAIL;
    memcpy(dst, mock_flash + base + src_offset, size);
    return ESP_OK;
}

#define RANDOM_UTILS_CUSTOM_IMPL
#include "random_utils.h"

int rng_fill_checked(uint8_t *buf, size_t len) {
    if (mock_rng_fails)
        return -1;
    return nostr_random_bytes(buf, len) == 1 ? 0 : -1;
}

bool rng_is_healthy(void) {
    return !mock_rng_fails;
}

secresult_t rng_is_healthy_secure(void) {
    return mock_rng_fails ? SECRESULT_FALSE : SECRESULT_TRUE;
}

int rng_init(void) {
    return mock_rng_fails ? -1 : 0;
}

void rng_get_health(rng_health_stats_t *stats) {
    if (stats) {
        stats->total_calls = 0;
        stats->failed_checks = 0;
        stats->retries = 0;
        stats->healthy = !mock_rng_fails;
        stats->entropy_source_verified = !mock_rng_fails;
    }
}

#include <secp256k1.h>

secp256k1_context *secp256k1_context_create(unsigned int flags) {
    (void)flags;
    if (mock_secp256k1_ctx_fails)
        return NULL;
    static secp256k1_context dummy;
    return &dummy;
}

void secp256k1_context_destroy(secp256k1_context *ctx) {
    (void)ctx;
}

int secp256k1_context_randomize(secp256k1_context *ctx, const unsigned char *seed32) {
    (void)ctx;
    (void)seed32;
    return 1;
}

int secp256k1_ec_pubkey_create(const secp256k1_context *ctx, secp256k1_pubkey *pubkey,
                               const unsigned char *seckey) {
    (void)ctx;
    (void)pubkey;
    (void)seckey;
    return 1;
}

#include <mbedtls/gcm.h>
#include "self_test.h"
#include "self_test.c"

#define TEST(name) printf("  TEST: %s\n", name)
#define PASS()     printf("    PASS\n")
#define FAIL(msg)                      \
    do {                               \
        printf("    FAIL: %s\n", msg); \
        return 1;                      \
    } while (0)

static void reset_state(void) {
    memset(mock_flash, 0xFF, sizeof(mock_flash));
    storage_exists = true;
    policy_exists = true;
    read_fails = false;
    mock_secp256k1_ctx_fails = false;
    mock_crypto_initialized = true;
    mock_rng_fails = false;
}

static int test_storage_crypto_pass(void) {
    TEST("storage_crypto test passes");
    reset_state();
    if (self_test_storage_crypto() != 0)
        FAIL("should pass");
    PASS();
    return 0;
}

static int test_storage_crypto_uses_test_vectors(void) {
    TEST("storage_crypto uses test vectors without initialized crypto");
    reset_state();
    mock_crypto_initialized = false;
    if (self_test_storage_crypto() != 0)
        FAIL("should pass using test vectors");
    PASS();
    return 0;
}

static int test_crypto_lib_pass(void) {
    TEST("crypto_lib test passes");
    reset_state();
    if (self_test_crypto_lib() != 0)
        FAIL("should pass");
    PASS();
    return 0;
}

static int test_crypto_lib_fail(void) {
    TEST("crypto_lib fails when context creation fails");
    reset_state();
    mock_secp256k1_ctx_fails = true;
    if (self_test_crypto_lib() == 0)
        FAIL("should fail");
    PASS();
    return 0;
}

static int test_flash_partitions_pass(void) {
    TEST("flash_partitions test passes");
    reset_state();
    if (self_test_flash_partitions() != 0)
        FAIL("should pass");
    PASS();
    return 0;
}

static int test_flash_partitions_no_storage(void) {
    TEST("flash_partitions fails without storage partition");
    reset_state();
    storage_exists = false;
    if (self_test_flash_partitions() == 0)
        FAIL("should fail");
    PASS();
    return 0;
}

static int test_flash_partitions_no_policy(void) {
    TEST("flash_partitions fails without policy partition");
    reset_state();
    policy_exists = false;
    if (self_test_flash_partitions() == 0)
        FAIL("should fail");
    PASS();
    return 0;
}

static int test_flash_partitions_read_fail(void) {
    TEST("flash_partitions fails when read fails");
    reset_state();
    read_fails = true;
    if (self_test_flash_partitions() == 0)
        FAIL("should fail");
    PASS();
    return 0;
}

static int test_storage_slots_pass(void) {
    TEST("storage_slots test passes with empty flash");
    reset_state();
    if (self_test_storage_slots() != 0)
        FAIL("should pass");
    PASS();
    return 0;
}

static int test_storage_slots_with_valid_data(void) {
    TEST("storage_slots passes with valid slot data");
    reset_state();
    strcpy((char *)mock_flash, "valid_group");
    if (self_test_storage_slots() != 0)
        FAIL("should pass");
    PASS();
    return 0;
}

static int test_run_all_pass(void) {
    TEST("run_all passes when all required tests pass");
    reset_state();
    if (self_test_run_all() != 0)
        FAIL("should pass");
    self_test_stats_t stats;
    self_test_get_stats(&stats);
    if (stats.passed != SELF_TEST_COUNT)
        FAIL("wrong pass count");
    if (stats.failed != 0)
        FAIL("wrong fail count");
    if (!stats.all_required_passed)
        FAIL("should have all_required_passed");
    PASS();
    return 0;
}

static int test_run_all_fail_required(void) {
    TEST("run_all fails when required test fails");
    reset_state();
    mock_secp256k1_ctx_fails = true;
    if (self_test_run_all() == 0)
        FAIL("should fail");
    self_test_stats_t stats;
    self_test_get_stats(&stats);
    if (stats.all_required_passed)
        FAIL("should not have all_required_passed");
    PASS();
    return 0;
}

static int test_stats_populated(void) {
    TEST("stats are populated after run_all");
    reset_state();
    self_test_run_all();
    self_test_stats_t stats;
    self_test_get_stats(&stats);
    if (stats.results == 0)
        FAIL("results should be set");
    PASS();
    return 0;
}

int main(void) {
    printf("\n=== Self-Test Native Tests ===\n\n");

    int failures = 0;
    failures += test_storage_crypto_pass();
    failures += test_storage_crypto_uses_test_vectors();
    failures += test_crypto_lib_pass();
    failures += test_crypto_lib_fail();
    failures += test_flash_partitions_pass();
    failures += test_flash_partitions_no_storage();
    failures += test_flash_partitions_no_policy();
    failures += test_flash_partitions_read_fail();
    failures += test_storage_slots_pass();
    failures += test_storage_slots_with_valid_data();
    failures += test_run_all_pass();
    failures += test_run_all_fail_required();
    failures += test_stats_populated();

    printf("\n");
    if (failures == 0) {
        printf("=== All tests passed ===\n\n");
        return 0;
    } else {
        printf("=== %d test(s) failed ===\n\n", failures);
        return 1;
    }
}
