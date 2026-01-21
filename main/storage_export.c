// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "storage.h"
#include "storage_crypto.h"
#include "storage_internal.h"
#include "hex_utils.h"
#include "random_utils.h"
#include "frost.h"
#include "crypto_asm.h"
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/sha256.h>
#include <string.h>

#ifdef ESP_PLATFORM
#include "esp_log.h"
#include "esp_timer.h"
static uint32_t get_time_ms(void) {
    return (uint32_t)(esp_timer_get_time() / 1000);
}
#else
#include <time.h>
#include <stdio.h>
#define ESP_LOGW(tag, fmt, ...) fprintf(stderr, "W (%s): " fmt "\n", tag, ##__VA_ARGS__)
static uint32_t get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}
#endif

#define TAG "storage_export"

#define EXPORT_RATE_LIMIT_WINDOW_MS   60000
#define EXPORT_RATE_LIMIT_MAX         3
#define EXPORT_LOCKOUT_MS             300000
#define EXPORT_LOCKOUT_FAILURE_THRESH 5
#define EXPORT_PBKDF2_ITERATIONS      100000
#define EXPORT_AAD_LEN                40

static uint32_t export_attempt_times[EXPORT_RATE_LIMIT_MAX];
static uint8_t export_attempt_count = 0;
static uint32_t export_lockout_until = 0;
static uint8_t export_consecutive_failures = 0;

static const uint8_t EXPORT_HKDF_INFO[] = "share-export-encryption";

static int derive_export_key(const char *passphrase, size_t pass_len,
                             const uint8_t salt[STORAGE_EXPORT_SALT_LEN], uint8_t key_out[32]) {
    uint8_t stretched[32];
    int ret = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, (const unsigned char *)passphrase,
                                            pass_len, salt, STORAGE_EXPORT_SALT_LEN,
                                            EXPORT_PBKDF2_ITERATIONS, sizeof(stretched), stretched);
    if (ret != 0) {
        secure_memzero(stretched, sizeof(stretched));
        return -1;
    }

    ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0, stretched,
                       sizeof(stretched), EXPORT_HKDF_INFO, sizeof(EXPORT_HKDF_INFO) - 1, key_out,
                       32);
    secure_memzero(stretched, sizeof(stretched));
    return (ret == 0) ? 0 : -1;
}

int storage_export_check_rate_limit(void) {
    uint32_t now = get_time_ms();

    if (export_lockout_until > 0) {
        if ((int32_t)(now - export_lockout_until) < 0) {
            return STORAGE_ERR_RATE_LIMITED;
        }
        export_lockout_until = 0;
        export_consecutive_failures = 0;
    }

    int recent = 0;
    for (int i = 0; i < export_attempt_count && i < EXPORT_RATE_LIMIT_MAX; i++) {
        if ((int32_t)(now - export_attempt_times[i]) < (int32_t)EXPORT_RATE_LIMIT_WINDOW_MS) {
            recent++;
        }
    }

    if (recent >= EXPORT_RATE_LIMIT_MAX) {
        return STORAGE_ERR_RATE_LIMITED;
    }

    return STORAGE_OK;
}

void storage_export_record_attempt(bool success) {
    uint32_t now = get_time_ms();

    if (export_attempt_count < EXPORT_RATE_LIMIT_MAX) {
        export_attempt_times[export_attempt_count++] = now;
    } else {
        memmove(export_attempt_times, export_attempt_times + 1,
                (EXPORT_RATE_LIMIT_MAX - 1) * sizeof(export_attempt_times[0]));
        export_attempt_times[EXPORT_RATE_LIMIT_MAX - 1] = now;
    }

    if (!success) {
        if (export_consecutive_failures < UINT8_MAX) {
            export_consecutive_failures++;
        }
        if (export_consecutive_failures >= EXPORT_LOCKOUT_FAILURE_THRESH) {
            export_lockout_until = now + EXPORT_LOCKOUT_MS;
            ESP_LOGW(TAG, "Export lockout activated for %d seconds", EXPORT_LOCKOUT_MS / 1000);
        }
    } else {
        export_consecutive_failures = 0;
    }
}

int storage_export_share(const char *group, const char *passphrase, share_export_t *export_out) {
    if (!storage_is_initialized()) {
        return STORAGE_ERR_NOT_INIT;
    }
    if (!storage_crypto_is_initialized()) {
        return STORAGE_ERR_CRYPTO_NOT_INIT;
    }
    if (!group || !passphrase || !export_out) {
        return STORAGE_ERR_INVALID_DATA;
    }
    if (!storage_validate_group_name(group)) {
        return STORAGE_ERR_INVALID_GROUP;
    }

    size_t pass_len = strnlen(passphrase, 256);
    if (pass_len < 8 || pass_len > 255) {
        return STORAGE_ERR_INVALID_DATA;
    }

    char share_hex[STORAGE_SHARE_LEN * 2 + 1];
    int ret = storage_load_share(group, share_hex, sizeof(share_hex));
    if (ret != STORAGE_OK) {
        secure_memzero(share_hex, sizeof(share_hex));
        return ret;
    }

    uint8_t share_bytes[STORAGE_SHARE_LEN];
    int share_len = hex_to_bytes(share_hex, share_bytes, sizeof(share_bytes));
    secure_memzero(share_hex, sizeof(share_hex));
    if (share_len < 0) {
        secure_memzero(share_bytes, sizeof(share_bytes));
        return STORAGE_ERR_INVALID_DATA;
    }

    frost_state_t frost_state;
    if (frost_init(&frost_state, share_bytes, share_len) != 0) {
        secure_memzero(share_bytes, sizeof(share_bytes));
        return STORAGE_ERR_INVALID_DATA;
    }

    memset(export_out, 0, sizeof(share_export_t));
    export_out->version = STORAGE_EXPORT_VERSION;
    export_out->threshold = frost_state.threshold;
    export_out->participants = frost_state.participants;
    export_out->share_index = frost_state.share_index;
    memcpy(export_out->group_pubkey, frost_state.group_pubkey, sizeof(export_out->group_pubkey));
    frost_free(&frost_state);

    if (rng_fill_checked(export_out->salt, STORAGE_EXPORT_SALT_LEN) != 0 ||
        rng_fill_checked(export_out->nonce, sizeof(export_out->nonce)) != 0) {
        secure_memzero(share_bytes, sizeof(share_bytes));
        secure_memzero(export_out, sizeof(share_export_t));
        return STORAGE_ERR_EXPORT;
    }

    uint8_t export_key[32];
    if (derive_export_key(passphrase, pass_len, export_out->salt, export_key) != 0) {
        secure_memzero(share_bytes, sizeof(share_bytes));
        secure_memzero(export_out, sizeof(share_export_t));
        return STORAGE_ERR_EXPORT;
    }

    uint8_t aad[EXPORT_AAD_LEN];
    aad[0] = export_out->version;
    aad[1] = (uint8_t)(export_out->threshold >> 8);
    aad[2] = (uint8_t)(export_out->threshold & 0xFF);
    aad[3] = (uint8_t)(export_out->participants >> 8);
    aad[4] = (uint8_t)(export_out->participants & 0xFF);
    aad[5] = (uint8_t)(export_out->share_index >> 8);
    aad[6] = (uint8_t)(export_out->share_index & 0xFF);
    memcpy(aad + 7, export_out->group_pubkey, sizeof(export_out->group_pubkey));

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, export_key, 256);
    secure_memzero(export_key, sizeof(export_key));
    if (ret != 0) {
        mbedtls_gcm_free(&gcm);
        secure_memzero(share_bytes, sizeof(share_bytes));
        secure_memzero(export_out, sizeof(share_export_t));
        return STORAGE_ERR_EXPORT;
    }

    uint8_t tag[16];
    ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, share_len, export_out->nonce,
                                    sizeof(export_out->nonce), aad, sizeof(aad), share_bytes,
                                    export_out->encrypted_share, sizeof(tag), tag);
    mbedtls_gcm_free(&gcm);
    secure_memzero(share_bytes, sizeof(share_bytes));
    if (ret != 0) {
        secure_memzero(aad, sizeof(aad));
        secure_memzero(export_out, sizeof(share_export_t));
        return STORAGE_ERR_EXPORT;
    }

    memcpy(export_out->encrypted_share + share_len, tag, sizeof(tag));
    export_out->encrypted_len = share_len + sizeof(tag);

    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0);
    mbedtls_sha256_update(&sha_ctx, aad, sizeof(aad));
    mbedtls_sha256_update(&sha_ctx, export_out->salt, sizeof(export_out->salt));
    mbedtls_sha256_update(&sha_ctx, export_out->nonce, sizeof(export_out->nonce));
    mbedtls_sha256_update(&sha_ctx, export_out->encrypted_share, export_out->encrypted_len);
    mbedtls_sha256_finish(&sha_ctx, export_out->checksum);
    mbedtls_sha256_free(&sha_ctx);
    secure_memzero(aad, sizeof(aad));

    return STORAGE_OK;
}

void storage_export_cleanup(void) {
    export_attempt_count = 0;
    export_lockout_until = 0;
    export_consecutive_failures = 0;
    memset(export_attempt_times, 0, sizeof(export_attempt_times));
}
