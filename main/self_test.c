// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include "self_test.h"
#include "storage_crypto.h"
#include "random_utils.h"
#include "crypto_asm.h"
#include "esp_partition.h"
#include "esp_log.h"
#include <secp256k1.h>
#include <mbedtls/gcm.h>
#include <string.h>

#define TAG "self_test"

#define STORAGE_PARTITION_NAME "storage"
#define POLICY_PARTITION_NAME  "policy"
#define SHARE_SLOT_SIZE        512
#define MAX_SHARES             8
#define STORAGE_GROUP_LEN      64
#define ARRAY_SIZE(arr)        (sizeof(arr) / sizeof((arr)[0]))

static self_test_stats_t g_stats;

static bool is_valid_group_char(unsigned char c) {
    return c == '_' || c == '-' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9');
}

static const self_test_t tests[] = {
    {SELF_TEST_STORAGE_CRYPTO, "storage_crypto", self_test_storage_crypto, true},
    {SELF_TEST_CRYPTO_LIB, "crypto_lib", self_test_crypto_lib, true},
    {SELF_TEST_FLASH_PARTITIONS, "flash_partitions", self_test_flash_partitions, true},
    {SELF_TEST_STORAGE_SLOTS, "storage_slots", self_test_storage_slots, false},
};

static const uint8_t AES_GCM_TEST_KEY[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
static const uint8_t AES_GCM_TEST_NONCE[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t AES_GCM_TEST_PT[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t AES_GCM_TEST_CT[16] = {0x0e, 0xbc, 0xb5, 0xde, 0xb5, 0x2c, 0x83, 0xbd,
                                            0x08, 0xa8, 0xa9, 0x35, 0x18, 0x2c, 0x91, 0x99};
static const uint8_t AES_GCM_TEST_TAG[16] = {0x38, 0x62, 0x64, 0x29, 0x86, 0xc9, 0x53, 0xe8,
                                             0x7b, 0x3c, 0xe9, 0x9b, 0x0d, 0xec, 0xdf, 0x34};

int self_test_storage_crypto(void) {
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int result = -1;
    uint8_t output[16];
    uint8_t tag[16];

    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, AES_GCM_TEST_KEY, 256) != 0) {
        goto cleanup;
    }

    if (mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, sizeof(AES_GCM_TEST_PT),
                                  AES_GCM_TEST_NONCE, sizeof(AES_GCM_TEST_NONCE), NULL, 0,
                                  AES_GCM_TEST_PT, output, sizeof(tag), tag) != 0) {
        goto cleanup;
    }

    if (ct_compare(output, AES_GCM_TEST_CT, sizeof(AES_GCM_TEST_CT)) != 0 ||
        ct_compare(tag, AES_GCM_TEST_TAG, sizeof(AES_GCM_TEST_TAG)) != 0) {
        goto cleanup;
    }

    if (mbedtls_gcm_auth_decrypt(&gcm, sizeof(AES_GCM_TEST_CT), AES_GCM_TEST_NONCE,
                                 sizeof(AES_GCM_TEST_NONCE), NULL, 0, AES_GCM_TEST_TAG,
                                 sizeof(AES_GCM_TEST_TAG), AES_GCM_TEST_CT, output) != 0) {
        goto cleanup;
    }

    if (ct_compare(output, AES_GCM_TEST_PT, sizeof(AES_GCM_TEST_PT)) != 0) {
        goto cleanup;
    }

    result = 0;

cleanup:
    mbedtls_gcm_free(&gcm);
    secure_memzero(output, sizeof(output));
    secure_memzero(tag, sizeof(tag));
    return result;
}

int self_test_crypto_lib(void) {
    secp256k1_context *ctx =
        secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        return -1;
    }

    uint8_t randomize[32];
    if (rng_fill_checked(randomize, sizeof(randomize)) != 0) {
        secp256k1_context_destroy(ctx);
        return -1;
    }
    if (secp256k1_context_randomize(ctx, randomize) != 1) {
        secure_memzero(randomize, sizeof(randomize));
        secp256k1_context_destroy(ctx);
        return -1;
    }
    secure_memzero(randomize, sizeof(randomize));

    uint8_t seckey[32];
    secp256k1_pubkey pubkey;
    int result = -1;

    if (rng_fill_checked(seckey, sizeof(seckey)) != 0) {
        goto cleanup;
    }

    result = secp256k1_ec_pubkey_create(ctx, &pubkey, seckey) == 1 ? 0 : -1;

cleanup:
    secure_memzero(seckey, sizeof(seckey));
    secure_memzero(&pubkey, sizeof(pubkey));
    secp256k1_context_destroy(ctx);

    return result;
}

int self_test_flash_partitions(void) {
    const esp_partition_t *storage = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, STORAGE_PARTITION_NAME);
    if (!storage) {
        ESP_LOGE(TAG, "Storage partition not found");
        return -1;
    }

    uint8_t header[16];
    int result = -1;

    if (esp_partition_read(storage, 0, header, sizeof(header)) != ESP_OK) {
        ESP_LOGE(TAG, "Storage partition read failed");
        goto cleanup;
    }

    const esp_partition_t *policy = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, POLICY_PARTITION_NAME);
    if (!policy) {
        ESP_LOGE(TAG, "Policy partition not found");
        goto cleanup;
    }

    if (esp_partition_read(policy, 0, header, sizeof(header)) != ESP_OK) {
        ESP_LOGE(TAG, "Policy partition read failed");
        goto cleanup;
    }

    result = 0;

cleanup:
    secure_memzero(header, sizeof(header));
    return result;
}

int self_test_storage_slots(void) {
    const esp_partition_t *storage = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, STORAGE_PARTITION_NAME);
    if (!storage) {
        return -1;
    }

    uint8_t slot_header[STORAGE_GROUP_LEN + 4];
    int result = 0;

    for (int i = 0; i < MAX_SHARES; i++) {
        if (esp_partition_read(storage, (size_t)i * SHARE_SLOT_SIZE, slot_header,
                               sizeof(slot_header)) != ESP_OK) {
            result = -1;
            goto cleanup;
        }

        if (slot_header[0] == 0xFF) {
            continue;
        }

        for (size_t j = 0; j < STORAGE_GROUP_LEN && slot_header[j] != '\0'; j++) {
            if (!is_valid_group_char(slot_header[j])) {
                ESP_LOGW(TAG, "Slot %d has invalid group name characters", i);
                result = -1;
                goto cleanup;
            }
        }
    }

cleanup:
    secure_memzero(slot_header, sizeof(slot_header));
    return result;
}

int self_test_run_all(void) {
    memset(&g_stats, 0, sizeof(g_stats));
    g_stats.all_required_passed = true;

    ESP_LOGI(TAG, "Running %d self-tests...", (int)ARRAY_SIZE(tests));

    for (size_t i = 0; i < ARRAY_SIZE(tests); i++) {
        const self_test_t *t = &tests[i];
        g_stats.results |= (1u << t->id);

        if (!t->run) {
            g_stats.skipped++;
            continue;
        }

        int ret = t->run();
        if (ret == 0) {
            ESP_LOGI(TAG, "  [PASS] %s", t->name);
            g_stats.passed++;
        } else {
            ESP_LOGE(TAG, "  [FAIL] %s", t->name);
            g_stats.failed++;
            if (t->required) {
                g_stats.all_required_passed = false;
            }
        }
    }

    ESP_LOGI(TAG, "Self-tests: %lu passed, %lu failed, %lu skipped", (unsigned long)g_stats.passed,
             (unsigned long)g_stats.failed, (unsigned long)g_stats.skipped);

    return g_stats.all_required_passed ? 0 : -1;
}

void self_test_get_stats(self_test_stats_t *stats) {
    if (stats) {
        *stats = g_stats;
    }
}
