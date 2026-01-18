#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "esp_partition.h"
#include "esp_log.h"
#include "crypto_asm.h"

static uint8_t mock_flash[4096];
static esp_partition_t mock_partition = {"storage", 4096, 0};
static bool partition_exists = true;

const esp_partition_t *esp_partition_find_first(esp_partition_type_t type,
                                                esp_partition_subtype_t subtype,
                                                const char *label) {
    (void)type;
    (void)subtype;
    (void)label;
    return partition_exists ? &mock_partition : NULL;
}

esp_err_t esp_partition_read(const esp_partition_t *partition, size_t src_offset, void *dst,
                             size_t size) {
    if (!partition || src_offset + size > sizeof(mock_flash))
        return ESP_FAIL;
    memcpy(dst, mock_flash + src_offset, size);
    return ESP_OK;
}

esp_err_t esp_partition_write(const esp_partition_t *partition, size_t dst_offset, const void *src,
                              size_t size) {
    if (!partition || dst_offset + size > sizeof(mock_flash))
        return ESP_FAIL;
    memcpy(mock_flash + dst_offset, src, size);
    return ESP_OK;
}

esp_err_t esp_partition_erase_range(const esp_partition_t *partition, size_t offset, size_t size) {
    if (!partition || offset + size > sizeof(mock_flash))
        return ESP_FAIL;
    memset(mock_flash + offset, 0xFF, size);
    return ESP_OK;
}

#include "hex_utils.h"
#include "storage_crypto.h"
#include "storage.h"
#include "storage.c"

#define TEST(name) printf("  TEST: %s\n", name)
#define PASS()     printf("    PASS\n")
#define FAIL(msg)                      \
    do {                               \
        printf("    FAIL: %s\n", msg); \
        return 1;                      \
    } while (0)

static void reset_flash(void) {
    memset(mock_flash, 0xFF, sizeof(mock_flash));
    initialized = false;
    storage_partition = NULL;
}

static int test_init(void) {
    TEST("storage_init");
    reset_flash();
    partition_exists = true;
    if (storage_init() != 0)
        FAIL("init failed");
    if (storage_init() != 0)
        FAIL("double init failed");
    PASS();
    return 0;
}

static int test_init_no_partition(void) {
    TEST("storage_init without partition");
    reset_flash();
    partition_exists = false;
    if (storage_init() != -1)
        FAIL("should fail without partition");
    partition_exists = true;
    PASS();
    return 0;
}

static int test_save_load_roundtrip(void) {
    TEST("save/load roundtrip");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");

    const char *group = "test_group";
    const char *share_hex = "deadbeef1234567890abcdef";
    if (storage_save_share(group, share_hex) != 0)
        FAIL("save failed");

    char loaded[128];
    if (storage_load_share(group, loaded, sizeof(loaded)) != 0)
        FAIL("load failed");
    if (strcmp(loaded, share_hex) != 0)
        FAIL("data mismatch");

    PASS();
    return 0;
}

static int test_save_overwrite(void) {
    TEST("save overwrites existing");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");

    const char *group = "overwrite_test";
    if (storage_save_share(group, "aabbccdd") != 0)
        FAIL("first save failed");
    if (storage_save_share(group, "11223344") != 0)
        FAIL("overwrite failed");

    char loaded[128];
    if (storage_load_share(group, loaded, sizeof(loaded)) != 0)
        FAIL("load failed");
    if (strcmp(loaded, "11223344") != 0)
        FAIL("overwrite data mismatch");

    PASS();
    return 0;
}

static int test_delete(void) {
    TEST("delete share");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");

    const char *group = "delete_test";
    if (storage_save_share(group, "cafebabe") != 0)
        FAIL("save failed");
    if (!storage_has_share(group))
        FAIL("should exist before delete");
    if (storage_delete_share(group) != 0)
        FAIL("delete failed");
    if (storage_has_share(group))
        FAIL("should not exist after delete");

    PASS();
    return 0;
}

static int test_delete_nonexistent(void) {
    TEST("delete nonexistent");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");

    if (storage_delete_share("nonexistent") != STORAGE_ERR_NOT_FOUND)
        FAIL("should fail");

    PASS();
    return 0;
}

static int test_load_nonexistent(void) {
    TEST("load nonexistent");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");

    char buf[128];
    if (storage_load_share("nonexistent", buf, sizeof(buf)) != STORAGE_ERR_NOT_FOUND)
        FAIL("should fail");

    PASS();
    return 0;
}

static int test_list_shares(void) {
    TEST("list shares");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");

    if (storage_save_share("group_a", "aa") != 0)
        FAIL("save a failed");
    if (storage_save_share("group_b", "bb") != 0)
        FAIL("save b failed");
    if (storage_save_share("group_c", "cc") != 0)
        FAIL("save c failed");

    char groups[8][STORAGE_GROUP_LEN + 1];
    int count = storage_list_shares(groups, 8);
    if (count != 3)
        FAIL("wrong count");

    PASS();
    return 0;
}

static int test_full_slots(void) {
    TEST("full slots");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");

    char name[32];
    for (int i = 0; i < 8; i++) {
        snprintf(name, sizeof(name), "group_%d", i);
        if (storage_save_share(name, "aa") != 0)
            FAIL("save failed");
    }

    if (storage_save_share("group_overflow", "bb") != STORAGE_ERR_NO_SLOT)
        FAIL("should fail when full");

    PASS();
    return 0;
}

static int test_invalid_group_name(void) {
    TEST("invalid group names");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");

    if (storage_save_share("", "aa") != STORAGE_ERR_INVALID_GROUP)
        FAIL("empty name should fail");
    if (storage_save_share("bad/name", "aa") != STORAGE_ERR_INVALID_GROUP)
        FAIL("slash should fail");
    if (storage_save_share("bad name", "aa") != STORAGE_ERR_INVALID_GROUP)
        FAIL("space should fail");

    PASS();
    return 0;
}

static int test_invalid_hex(void) {
    TEST("invalid hex");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");

    if (storage_save_share("test", "gg") != STORAGE_ERR_INVALID_DATA)
        FAIL("invalid hex should fail");
    if (storage_save_share("test", "abc") != STORAGE_ERR_INVALID_DATA)
        FAIL("odd length should fail");

    PASS();
    return 0;
}

static int test_buffer_too_small(void) {
    TEST("output buffer too small");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");

    if (storage_save_share("test", "aabbccdd") != 0)
        FAIL("save failed");

    char small[4];
    if (storage_load_share("test", small, sizeof(small)) != STORAGE_ERR_INVALID_DATA)
        FAIL("should fail with small buffer");

    PASS();
    return 0;
}

static int test_uninitialized(void) {
    TEST("operations before init");
    reset_flash();

    char buf[128];
    if (storage_save_share("test", "aa") != STORAGE_ERR_NOT_INIT)
        FAIL("save should fail");
    if (storage_load_share("test", buf, sizeof(buf)) != STORAGE_ERR_NOT_INIT)
        FAIL("load should fail");
    if (storage_delete_share("test") != STORAGE_ERR_NOT_INIT)
        FAIL("delete should fail");
    if (storage_has_share("test"))
        FAIL("has_share should return false");

    PASS();
    return 0;
}

static int test_corrupt_share_len(void) {
    TEST("corrupt share_len field");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");

    if (storage_save_share("test", "aabbccdd") != 0)
        FAIL("save failed");
    mock_flash[65] = 0xFF;
    mock_flash[66] = 0xFF;

    char buf[128];
    if (storage_load_share("test", buf, sizeof(buf)) != STORAGE_ERR_NOT_FOUND)
        FAIL("should fail with corrupt len");

    PASS();
    return 0;
}

static int test_max_group_name_len(void) {
    TEST("max group name length");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");

    char long_name[STORAGE_GROUP_LEN + 1];
    memset(long_name, 'a', STORAGE_GROUP_LEN);
    long_name[STORAGE_GROUP_LEN] = '\0';

    if (storage_save_share(long_name, "aa") != 0)
        FAIL("max length should work");
    if (!storage_has_share(long_name))
        FAIL("should exist");

    char too_long[STORAGE_GROUP_LEN + 2];
    memset(too_long, 'a', STORAGE_GROUP_LEN + 1);
    too_long[STORAGE_GROUP_LEN + 1] = '\0';

    if (storage_save_share(too_long, "aa") != STORAGE_ERR_INVALID_GROUP)
        FAIL("too long should fail");

    PASS();
    return 0;
}

static int test_format_version_set(void) {
    TEST("format_version is set on new shares");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");

    if (storage_save_share("test", "aabbccdd") != 0)
        FAIL("save failed");

    share_slot_t slot;
    memcpy(&slot, mock_flash, sizeof(slot));
    if (slot.format_version != STORAGE_FORMAT_CURRENT)
        FAIL("format_version not set");

    PASS();
    return 0;
}

static int test_migrate_v1_to_v2(void) {
    TEST("migrate V1 slot to V2");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");

    share_slot_t v1_slot;
    memset(&v1_slot, 0, sizeof(v1_slot));
    strncpy(v1_slot.group, "test", STORAGE_GROUP_LEN);
    v1_slot.format_version = STORAGE_FORMAT_V1;
    v1_slot.flags = 0;

    uint8_t plaintext[] = {0xde, 0xad, 0xbe, 0xef};
    uint8_t encrypted[STORAGE_SHARE_LEN];
    if (storage_crypto_encrypt(plaintext, sizeof(plaintext), NULL, 0, v1_slot.nonce, encrypted,
                               v1_slot.tag) != 0) {
        FAIL("V1 encryption failed");
    }
    v1_slot.share_len = sizeof(plaintext) | ENCRYPTED_FLAG;
    memcpy(v1_slot.share_data, encrypted, sizeof(plaintext));

    memcpy(mock_flash, &v1_slot, sizeof(v1_slot));

    share_slot_t slot_before;
    memcpy(&slot_before, mock_flash, sizeof(slot_before));
    if (!slot_is_v1(&slot_before))
        FAIL("slot should be detected as V1");
    if (mock_flash[offsetof(share_slot_t, format_version)] != STORAGE_FORMAT_V1) {
        FAIL("format_version byte not at expected offset");
    }

    mock_crypto_reset_aad();
    if (storage_migrate_if_needed() != 0)
        FAIL("migration failed");

    if (mock_last_decrypt_aad_len != 0)
        FAIL("V1 decrypt should use no AAD");
    if (mock_last_encrypt_aad_len != STORAGE_GROUP_LEN + 1)
        FAIL("V2 encrypt should use AAD");

    share_slot_t slot_after;
    memcpy(&slot_after, mock_flash, sizeof(slot_after));
    if (slot_after.format_version != STORAGE_FORMAT_CURRENT)
        FAIL("format_version not updated");
    if (slot_is_v1(&slot_after))
        FAIL("slot should be V2 after migration");

    char loaded[128];
    if (storage_load_share("test", loaded, sizeof(loaded)) != 0)
        FAIL("load after migration failed");
    if (strcmp(loaded, "deadbeef") != 0)
        FAIL("data mismatch after migration");

    PASS();
    return 0;
}

static int test_no_migration_for_v2(void) {
    TEST("no migration needed for V2 slots");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");

    if (storage_save_share("test", "cafebabe") != 0)
        FAIL("save failed");

    uint8_t snapshot[512];
    memcpy(snapshot, mock_flash, sizeof(snapshot));

    if (storage_migrate_if_needed() != 0)
        FAIL("migration failed");

    if (memcmp(snapshot, mock_flash, sizeof(snapshot)) != 0)
        FAIL("V2 slot was modified");

    PASS();
    return 0;
}

static int test_aad_passed_to_crypto(void) {
    TEST("AAD passed correctly to crypto functions");
    reset_flash();
    mock_crypto_reset_aad();
    if (storage_init() != 0)
        FAIL("init failed");

    const char *group = "test_aad";
    const char *share_hex = "deadbeef";
    if (storage_save_share(group, share_hex) != 0)
        FAIL("save failed");

    if (mock_last_encrypt_aad_len != STORAGE_GROUP_LEN + 1)
        FAIL("encrypt AAD length wrong");

    char expected_aad[STORAGE_GROUP_LEN + 1];
    memset(expected_aad, 0, sizeof(expected_aad));
    strncpy(expected_aad, group, STORAGE_GROUP_LEN);
    if (memcmp(mock_last_encrypt_aad, expected_aad, STORAGE_GROUP_LEN + 1) != 0)
        FAIL("encrypt AAD content wrong");

    mock_crypto_reset_aad();
    char loaded[128];
    if (storage_load_share(group, loaded, sizeof(loaded)) != 0)
        FAIL("load failed");

    if (mock_last_decrypt_aad_len != STORAGE_GROUP_LEN + 1)
        FAIL("decrypt AAD length wrong");
    if (memcmp(mock_last_decrypt_aad, expected_aad, STORAGE_GROUP_LEN + 1) != 0)
        FAIL("decrypt AAD content wrong");

    PASS();
    return 0;
}

static int test_corrupt_format_version_zero(void) {
    TEST("corrupt format_version=0x00 treated as invalid");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");

    if (storage_save_share("test", "aabbccdd") != 0)
        FAIL("save failed");

    mock_flash[offsetof(share_slot_t, format_version)] = 0x00;

    char buf[128];
    if (storage_load_share("test", buf, sizeof(buf)) != STORAGE_ERR_NOT_FOUND)
        FAIL("should not find corrupted slot");
    if (storage_has_share("test"))
        FAIL("corrupted slot should not be found");

    PASS();
    return 0;
}

int main(void) {
    printf("\n=== Storage Native Tests ===\n\n");

    int failures = 0;
    failures += test_init();
    failures += test_init_no_partition();
    failures += test_save_load_roundtrip();
    failures += test_save_overwrite();
    failures += test_delete();
    failures += test_delete_nonexistent();
    failures += test_load_nonexistent();
    failures += test_list_shares();
    failures += test_full_slots();
    failures += test_invalid_group_name();
    failures += test_invalid_hex();
    failures += test_buffer_too_small();
    failures += test_uninitialized();
    failures += test_corrupt_share_len();
    failures += test_max_group_name_len();
    failures += test_format_version_set();
    failures += test_migrate_v1_to_v2();
    failures += test_no_migration_for_v2();
    failures += test_aad_passed_to_crypto();
    failures += test_corrupt_format_version_zero();

    printf("\n");
    if (failures == 0) {
        printf("=== All tests passed ===\n\n");
        return 0;
    } else {
        printf("=== %d test(s) failed ===\n\n", failures);
        return 1;
    }
}
