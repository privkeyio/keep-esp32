// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "esp_partition.h"
#include "esp_log.h"
#include "crypto_asm.h"

static uint8_t mock_flash[65536];
static uint8_t mock_checkpoint_flash[28672];
static esp_partition_t mock_partition = {"storage", 65536, 0};
static esp_partition_t mock_checkpoint_partition = {"checkpoint", 28672, 0};
static bool partition_exists = true;
static bool mock_storage_read_fails = false;
static int mock_reads_before_fault = -1;
static bool checkpoint_partition_exists = true;
static size_t mock_read_fault_from = SIZE_MAX;

const esp_partition_t *esp_partition_find_first(esp_partition_type_t type,
                                                esp_partition_subtype_t subtype,
                                                const char *label) {
    (void)type;
    (void)subtype;
    if (label && strcmp(label, "checkpoint") == 0) {
        return checkpoint_partition_exists ? &mock_checkpoint_partition : NULL;
    }
    return partition_exists ? &mock_partition : NULL;
}

esp_err_t esp_partition_read(const esp_partition_t *partition, size_t src_offset, void *dst,
                             size_t size) {
    if (!partition)
        return ESP_FAIL;
    if (partition == &mock_checkpoint_partition) {
        if (src_offset + size > sizeof(mock_checkpoint_flash))
            return ESP_FAIL;
        memcpy(dst, mock_checkpoint_flash + src_offset, size);
        return ESP_OK;
    }
    if (mock_storage_read_fails || src_offset >= mock_read_fault_from ||
        src_offset + size > sizeof(mock_flash))
        return ESP_FAIL;
    if (mock_reads_before_fault >= 0 && mock_reads_before_fault-- == 0)
        return ESP_FAIL;
    memcpy(dst, mock_flash + src_offset, size);
    return ESP_OK;
}

esp_err_t esp_partition_write(const esp_partition_t *partition, size_t dst_offset, const void *src,
                              size_t size) {
    if (!partition)
        return ESP_FAIL;
    if (partition == &mock_checkpoint_partition) {
        if (dst_offset + size > sizeof(mock_checkpoint_flash))
            return ESP_FAIL;
        memcpy(mock_checkpoint_flash + dst_offset, src, size);
        return ESP_OK;
    }
    if (dst_offset + size > sizeof(mock_flash))
        return ESP_FAIL;
    memcpy(mock_flash + dst_offset, src, size);
    return ESP_OK;
}

static int mock_erases;

esp_err_t esp_partition_erase_range(const esp_partition_t *partition, size_t offset, size_t size) {
    if (!partition)
        return ESP_FAIL;
    mock_erases++;
    if (partition == &mock_checkpoint_partition) {
        if (offset + size > sizeof(mock_checkpoint_flash))
            return ESP_FAIL;
        memset(mock_checkpoint_flash + offset, 0xFF, size);
        return ESP_OK;
    }
    if (offset + size > sizeof(mock_flash))
        return ESP_FAIL;
    memset(mock_flash + offset, 0xFF, size);
    return ESP_OK;
}

#include "hex_utils.h"
#include "storage_crypto.h"
#include "random_utils.h"
#include "storage.h"
#include "storage_internal.h"
#include "storage.c"
#include "storage_metadata.c"
#include "storage_export.c"

#define TEST(name) printf("  TEST: %s\n", name)
#define PASS()     printf("    PASS\n")
#define FAIL(msg)                      \
    do {                               \
        printf("    FAIL: %s\n", msg); \
        return 1;                      \
    } while (0)

static void reset_flash(void) {
    memset(mock_flash, 0xFF, sizeof(mock_flash));
    memset(mock_checkpoint_flash, 0xFF, sizeof(mock_checkpoint_flash));
    initialized = false;
    storage_partition = NULL;
    export_attempt_count = 0;
    export_lockout_until = 0;
    export_consecutive_failures = 0;
    memset(export_attempt_times, 0, sizeof(export_attempt_times));
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

static int test_load_does_not_count_attempts(void) {
    TEST("share loads after unlock leave the PIN counter alone");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");
    if (storage_save_share("grp", "deadbeef") != 0)
        FAIL("save failed");

    char loaded[128];
    mock_begin_attempt_calls = 0;
    mock_record_success_calls = 0;
    mock_record_failure_calls = 0;
    if (storage_load_share("grp", loaded, sizeof(loaded)) != 0)
        FAIL("load failed");
    mock_decrypt_result = -1;
    int ret = storage_load_share("grp", loaded, sizeof(loaded));
    mock_decrypt_result = 0;
    if (ret != STORAGE_ERR_DECRYPT)
        FAIL("a slot that does not decrypt must be reported");
    if (mock_begin_attempt_calls || mock_record_success_calls || mock_record_failure_calls)
        FAIL("the PIN was proven at unlock; loads must not count attempts");
    PASS();
    return 0;
}

static int test_delete_requires_unlock(void) {
    TEST("deleting a share requires an unlocked device");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");
    if (storage_save_share("grp", "deadbeef") != 0)
        FAIL("save failed");
    mock_crypto_initialized = false;
    int ret = storage_delete_share("grp");
    mock_crypto_initialized = true;
    if (ret != STORAGE_ERR_CRYPTO_NOT_INIT)
        FAIL("delete while locked must be refused");
    if (!storage_has_share("grp"))
        FAIL("the share must still be there");
    if (storage_delete_share("grp") != STORAGE_OK)
        FAIL("delete once unlocked failed");
    PASS();
    return 0;
}

static int unlock_case(int verifier, bool with_share, int decrypt, int store, int *stores) {
    reset_flash();
    storage_init();
    mock_crypto_initialized = true;
    if (with_share && storage_save_share("grp", "deadbeef") != STORAGE_OK) {
        return -99;
    }
    mock_check_verifier_result = verifier;
    mock_decrypt_result = decrypt;
    mock_store_verifier_result = store;
    mock_store_verifier_calls = 0;
    mock_begin_attempt_calls = 0;
    int ret = storage_unlock("1234");
    *stores = mock_store_verifier_calls;
    mock_check_verifier_result = STORAGE_CRYPTO_NO_VERIFIER;
    mock_decrypt_result = 0;
    mock_store_verifier_result = 0;
    return ret;
}

static int unlock_case_keep_flash(int *stores) {
    mock_crypto_initialized = true;
    mock_check_verifier_result = STORAGE_CRYPTO_NO_VERIFIER;
    mock_store_verifier_calls = 0;
    int ret = storage_unlock("1234");
    *stores = mock_store_verifier_calls;
    return ret;
}

static int test_unlock_verifies_pin(void) {
    TEST("unlock proves the PIN before anything else can decrypt");
    int stores = 0;
    if (unlock_case(0, true, 0, 0, &stores) != 0 || !storage_crypto_is_initialized() || stores)
        FAIL("a verifier match should unlock without rewriting it");
    if (unlock_case(ERR_PIN_INVALID, true, 0, 0, &stores) != ERR_PIN_INVALID ||
        storage_crypto_is_initialized())
        FAIL("a verifier mismatch must refuse and clear the key");
    if (unlock_case(STORAGE_CRYPTO_NO_VERIFIER, true, 0, 0, &stores) != 0 || stores != 1 ||
        mock_begin_attempt_calls != 1)
        FAIL("without a verifier, a counted share decrypt should prove the PIN and store one");
    mock_record_failure_calls = 0;
    if (unlock_case(STORAGE_CRYPTO_NO_VERIFIER, true, -1, 0, &stores) != ERR_PIN_INVALID ||
        stores || storage_crypto_is_initialized())
        FAIL("a share that does not decrypt must refuse without storing a verifier");
    if (mock_record_failure_calls != 1 || !mock_decrypt_saw_begin)
        FAIL("the wrong PIN must be counted, with the attempt marked before decrypting");
    if (unlock_case(STORAGE_CRYPTO_NO_VERIFIER, false, 0, 0, &stores) != 0 || stores != 1)
        FAIL("with no shares the PIN should become the verifier");
    if (unlock_case(STORAGE_CRYPTO_NO_VERIFIER, false, 0, -1, &stores) != STORAGE_ERR_IO ||
        storage_crypto_is_initialized())
        FAIL("a verifier that cannot be stored must refuse and clear the key");
    if (unlock_case(-1, true, 0, 0, &stores) != STORAGE_ERR_IO || storage_crypto_is_initialized())
        FAIL("a verifier read error must refuse and clear the key");
    mock_crypto_initialized = true;
    PASS();
    return 0;
}

static int test_unlock_storage_edge_cases(void) {
    TEST("unlock refuses unreadable storage and accepts the PIN if any share proves it");
    int stores = 0;

    reset_flash();
    storage_init();
    mock_crypto_initialized = true;
    storage_save_share("grp", "deadbeef");
    storage_cleanup();
    mock_store_verifier_calls = 0;
    int ret = storage_unlock("1234");
    if (ret != STORAGE_ERR_NOT_INIT || mock_store_verifier_calls || storage_crypto_is_initialized())
        FAIL("storage that is not initialized must refuse without storing a verifier");

    reset_flash();
    storage_init();
    mock_crypto_initialized = true;
    storage_save_share("grp", "deadbeef");
    mock_storage_read_fails = true;
    mock_store_verifier_calls = 0;
    ret = storage_unlock("1234");
    mock_storage_read_fails = false;
    if (ret != STORAGE_ERR_IO || mock_store_verifier_calls || storage_crypto_is_initialized())
        FAIL("a read error must refuse without storing a verifier");

    reset_flash();
    storage_init();
    mock_crypto_initialized = true;
    storage_save_share("one", "deadbeef");
    storage_save_share("two", "cafebabe");
    mock_decrypt_fail_first = 1;
    mock_record_success_calls = 0;
    mock_record_failure_calls = 0;
    if (unlock_case_keep_flash(&stores) != 0 || stores != 1)
        FAIL("a damaged first slot must not stop a good one proving the PIN");
    if (mock_record_success_calls != 1 || mock_record_failure_calls != 0)
        FAIL("the check must be recorded once, as a success");

    reset_flash();
    storage_init();
    share_slot_t v1_slot;
    memset(&v1_slot, 0, sizeof(v1_slot));
    strncpy(v1_slot.group, "legacy", STORAGE_GROUP_LEN);
    v1_slot.format_version = STORAGE_FORMAT_V1;
    uint8_t plaintext[] = {0xde, 0xad, 0xbe, 0xef};
    uint8_t encrypted[STORAGE_SHARE_LEN];
    storage_crypto_encrypt(plaintext, sizeof(plaintext), NULL, 0, v1_slot.nonce, encrypted,
                           v1_slot.tag);
    v1_slot.share_len = sizeof(plaintext) | ENCRYPTED_FLAG;
    memcpy(v1_slot.share_data, encrypted, sizeof(plaintext));
    memcpy(mock_flash, &v1_slot, sizeof(v1_slot));
    mock_crypto_reset_aad();
    if (unlock_case_keep_flash(&stores) != 0 || stores != 1 || mock_last_decrypt_aad_len != 0)
        FAIL("a legacy V1 share must prove the PIN, decrypted without AAD");

    reset_flash();
    storage_init();
    mock_crypto_initialized = true;
    storage_save_share("grp", "deadbeef");
    mock_reads_before_fault = STORAGE_MAX_SHARES;
    mock_abandon_attempt_calls = 0;
    mock_record_failure_calls = 0;
    ret = unlock_case_keep_flash(&stores);
    mock_reads_before_fault = -1;
    if (ret != STORAGE_ERR_IO || mock_abandon_attempt_calls != 1 || mock_record_failure_calls)
        FAIL("a read fault before any decrypt must abandon the attempt, not count it");

    reset_flash();
    storage_init();
    mock_crypto_initialized = true;
    storage_save_share("grp", "deadbeef");
    storage_save_share("grp2", "deadbeef");
    mock_reads_before_fault = STORAGE_MAX_SHARES + 1;
    mock_decrypt_result = -1;
    mock_abandon_attempt_calls = 0;
    mock_record_failure_calls = 0;
    ret = unlock_case_keep_flash(&stores);
    mock_reads_before_fault = -1;
    mock_decrypt_result = 0;
    if (ret != STORAGE_ERR_IO || mock_abandon_attempt_calls || mock_record_failure_calls != 1)
        FAIL("a read fault after a failed decrypt must still count the PIN");

    reset_flash();
    storage_init();
    mock_can_keep_verifier = false;
    ret = unlock_case_keep_flash(&stores);
    mock_can_keep_verifier = true;
    if (ret != ERR_PIN_NO_STATE || stores || storage_crypto_is_initialized())
        FAIL("with no shares and nowhere to keep a verifier the PIN must not be taken on trust");
    mock_crypto_initialized = true;

    reset_flash();
    storage_init();
    mock_crypto_initialized = true;
    storage_save_share("grp", "deadbeef");
    mock_record_result = -1;
    ret = unlock_case_keep_flash(&stores);
    mock_record_result = 0;
    if (ret != STORAGE_ERR_IO || stores || storage_crypto_is_initialized())
        FAIL("a proven PIN whose result cannot be saved must refuse and clear the key");
    mock_crypto_initialized = true;
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

static int test_metadata_save_load(void) {
    TEST("metadata save/load roundtrip");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");

    group_metadata_t meta = {0};
    meta.threshold = 2;
    meta.participant_count = 3;
    meta.our_index = 1;
    meta.created_at = 1234567890;
    meta.group_pubkey[0] = 0x02;
    meta.participants[0].index = 1;
    meta.participants[1].index = 2;
    meta.participants[2].index = 3;

    if (storage_save_metadata("testgroup", &meta) != 0)
        FAIL("save metadata failed");
    if (!storage_has_metadata("testgroup"))
        FAIL("metadata should exist");

    group_metadata_t loaded;
    if (storage_load_metadata("testgroup", &loaded) != 0)
        FAIL("load metadata failed");
    if (loaded.threshold != 2)
        FAIL("threshold mismatch");
    if (loaded.participant_count != 3)
        FAIL("participant_count mismatch");
    if (loaded.our_index != 1)
        FAIL("our_index mismatch");
    if (loaded.created_at != 1234567890)
        FAIL("created_at mismatch");

    PASS();
    return 0;
}

static int test_metadata_not_found(void) {
    TEST("metadata not found");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");

    group_metadata_t loaded;
    if (storage_load_metadata("nonexistent", &loaded) != STORAGE_ERR_NOT_FOUND)
        FAIL("should return not found");
    if (storage_has_metadata("nonexistent"))
        FAIL("should not have metadata");

    PASS();
    return 0;
}

static const share_export_meta_t export_meta = {
    .threshold = 2, .participants = 3, .share_index = 1};

static int test_export_records_metadata(void) {
    TEST("export records the caller's share metadata and authenticates it");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");
    mock_crypto_initialized = true;
    if (storage_save_share("testgroup", "deadbeefcafe") != 0)
        FAIL("save failed");
    share_export_meta_t meta = {.threshold = 3, .participants = 5, .share_index = 4};
    memset(meta.group_pubkey, 0x02, sizeof(meta.group_pubkey));
    share_export_t out;
    if (storage_export_share("testgroup", "password123", &meta, &out) != STORAGE_OK)
        FAIL("export failed");
    if (out.version != STORAGE_EXPORT_VERSION || out.threshold != 3 || out.participants != 5 ||
        out.share_index != 4 || memcmp(out.group_pubkey, meta.group_pubkey, 33) != 0)
        FAIL("metadata not recorded");
    if (out.encrypted_len != 6 + 16)
        FAIL("ciphertext should be the share plus the tag");
    if (storage_export_share("testgroup", "password123", NULL, &out) != STORAGE_ERR_INVALID_DATA)
        FAIL("missing metadata accepted");
    PASS();
    return 0;
}

static int test_export_rate_limit_initial(void) {
    TEST("export rate limit initial state");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");

    if (storage_export_check_rate_limit() != STORAGE_OK)
        FAIL("initial state should allow exports");

    PASS();
    return 0;
}

static int test_export_rate_limit_after_attempts(void) {
    TEST("export rate limit after max attempts");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");

    for (int i = 0; i < EXPORT_RATE_LIMIT_MAX; i++) {
        storage_export_record_attempt(true);
    }

    if (storage_export_check_rate_limit() != STORAGE_ERR_RATE_LIMITED)
        FAIL("should be rate limited after max attempts");

    PASS();
    return 0;
}

static int test_export_lockout_after_failures(void) {
    TEST("export lockout after consecutive failures");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");

    for (int i = 0; i < EXPORT_LOCKOUT_FAILURE_THRESH; i++) {
        storage_export_record_attempt(false);
    }

    if (storage_export_check_rate_limit() != STORAGE_ERR_RATE_LIMITED)
        FAIL("should be locked out after consecutive failures");

    PASS();
    return 0;
}

static int test_export_success_resets_failures(void) {
    TEST("export success resets consecutive failures");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");

    for (int i = 0; i < EXPORT_LOCKOUT_FAILURE_THRESH - 1; i++) {
        storage_export_record_attempt(false);
    }

    storage_export_record_attempt(true);

    if (export_consecutive_failures != 0)
        FAIL("success should reset consecutive failures counter");

    PASS();
    return 0;
}

static int test_export_share_not_found(void) {
    TEST("export share not found");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");

    share_export_t export_data;
    int ret = storage_export_share("nonexistent", "password123", &export_meta, &export_data);
    if (ret != STORAGE_ERR_NOT_FOUND)
        FAIL("should return not found");

    PASS();
    return 0;
}

static int test_export_share_invalid_passphrase(void) {
    TEST("export share invalid passphrase");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");

    if (storage_save_share("testgroup", "deadbeef") != 0)
        FAIL("save failed");

    share_export_t export_data;
    int ret = storage_export_share("testgroup", "short", &export_meta, &export_data);
    if (ret != STORAGE_ERR_INVALID_DATA)
        FAIL("should reject short passphrase");

    PASS();
    return 0;
}

static int test_export_share_invalid_group(void) {
    TEST("export share invalid group name");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");

    share_export_t export_data;
    int ret = storage_export_share("bad/group", "password123", &export_meta, &export_data);
    if (ret != STORAGE_ERR_INVALID_GROUP)
        FAIL("should reject invalid group name");

    PASS();
    return 0;
}

static int test_export_consecutive_failures_overflow(void) {
    TEST("export consecutive failures counter overflow protection");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");

    for (int i = 0; i < 300; i++) {
        storage_export_record_attempt(false);
    }

    if (export_consecutive_failures != 255)
        FAIL("counter should be capped at 255");

    PASS();
    return 0;
}

static int test_retired_checkpoints_erased(void) {
    TEST("unlock erases retired checkpoint regions once and nothing else");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");
    mock_crypto_initialized = true;
    if (storage_save_share("keep", "deadbeef") != 0)
        FAIL("save failed");
    uint8_t shares_before[STORAGE_SECTOR_SIZE * 9];
    memcpy(shares_before, mock_flash, sizeof(shares_before));
    memset(mock_flash + RETIRED_SESSION_CHECKPOINT_OFFSET + 100, 0x5A, 64);
    memset(mock_checkpoint_flash + 8000, 0xA5, 32);
    if (storage_migrate_if_needed() != STORAGE_OK)
        FAIL("migrate failed");
    for (size_t i = 0; i < RETIRED_SESSION_CHECKPOINT_SIZE; i++)
        if (mock_flash[RETIRED_SESSION_CHECKPOINT_OFFSET + i] != 0xFF)
            FAIL("session checkpoint region not erased");
    for (size_t i = 0; i < sizeof(mock_checkpoint_flash); i++)
        if (mock_checkpoint_flash[i] != 0xFF)
            FAIL("checkpoint partition not erased");
    if (memcmp(shares_before, mock_flash, sizeof(shares_before)) != 0)
        FAIL("share or metadata sectors changed");
    mock_erases = 0;
    if (storage_migrate_if_needed() != STORAGE_OK || mock_erases != 0)
        FAIL("clean regions were erased again");
    PASS();
    return 0;
}

static int test_retired_checkpoint_fault_keeps_unlock(void) {
    TEST("a fault erasing retired checkpoints does not fail the unlock");
    reset_flash();
    if (storage_init() != 0)
        FAIL("init failed");
    mock_crypto_initialized = true;
    memset(mock_flash + RETIRED_SESSION_CHECKPOINT_OFFSET, 0x00, 16);
    mock_read_fault_from = RETIRED_SESSION_CHECKPOINT_OFFSET;
    int ret = storage_migrate_if_needed();
    mock_read_fault_from = SIZE_MAX;
    if (ret != STORAGE_OK)
        FAIL("unlock-time migration should still succeed");
    if (mock_flash[RETIRED_SESSION_CHECKPOINT_OFFSET] != 0x00)
        FAIL("an unreadable region must not be erased blind");
    if (storage_migrate_if_needed() != STORAGE_OK ||
        mock_flash[RETIRED_SESSION_CHECKPOINT_OFFSET] != 0xFF)
        FAIL("the next unlock should erase it");
    PASS();
    return 0;
}

int main(void) {
    printf("\n=== Storage Native Tests ===\n\n");

    int failures = 0;
    failures += test_init();
    failures += test_init_no_partition();
    failures += test_save_load_roundtrip();
    failures += test_load_does_not_count_attempts();
    failures += test_delete_requires_unlock();
    failures += test_unlock_verifies_pin();
    failures += test_unlock_storage_edge_cases();
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
    failures += test_metadata_save_load();
    failures += test_metadata_not_found();
    failures += test_export_records_metadata();
    failures += test_retired_checkpoints_erased();
    failures += test_retired_checkpoint_fault_keeps_unlock();
    failures += test_export_rate_limit_initial();
    failures += test_export_rate_limit_after_attempts();
    failures += test_export_lockout_after_failures();
    failures += test_export_success_resets_failures();
    failures += test_export_share_not_found();
    failures += test_export_share_invalid_passphrase();
    failures += test_export_share_invalid_group();
    failures += test_export_consecutive_failures_overflow();

    printf("\n=== DKG Checkpoint Tests ===\n\n");

    printf("\n");
    if (failures == 0) {
        printf("=== All tests passed ===\n\n");
        return 0;
    } else {
        printf("=== %d test(s) failed ===\n\n", failures);
        return 1;
    }
}
