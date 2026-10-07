// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include "frost_signer_storage.h"
#include "hex_utils.h"
#include "crypto_asm.h"
#include <string.h>

#define LEGACY_SHARE_LEN          102
#define LEGACY_SHARE_LEN_WITH_MIN 104

int share_payload_encode(const share_key_t *key, uint8_t out[STORAGE_SHARE_LEN], size_t *out_len) {
    if (!key || !out || !out_len || key->key_package_len == 0 ||
        key->key_package_len > SHARE_KEY_PACKAGE_MAX) {
        return SHARE_KEY_ERR_DECODE;
    }
    size_t len = SHARE_PAYLOAD_HEADER + key->key_package_len;
    if (len == LEGACY_SHARE_LEN || len == LEGACY_SHARE_LEN_WITH_MIN) {
        return SHARE_KEY_ERR_DECODE;
    }
    out[0] = SHARE_PAYLOAD_VERSION;
    out[1] = (uint8_t)(key->participants >> 8);
    out[2] = (uint8_t)key->participants;
    memcpy(out + SHARE_PAYLOAD_HEADER, key->key_package, key->key_package_len);
    *out_len = len;
    return SHARE_KEY_OK;
}

int share_payload_decode(const uint8_t *payload, size_t len, share_key_t *out) {
    if (!payload || !out) {
        return SHARE_KEY_ERR_DECODE;
    }
    if (len == LEGACY_SHARE_LEN || len == LEGACY_SHARE_LEN_WITH_MIN) {
        return SHARE_KEY_ERR_LEGACY;
    }
    if (len <= SHARE_PAYLOAD_HEADER || len > STORAGE_SHARE_LEN ||
        payload[0] != SHARE_PAYLOAD_VERSION) {
        return SHARE_KEY_ERR_DECODE;
    }
    out->participants = (uint16_t)((payload[1] << 8) | payload[2]);
    out->key_package_len = len - SHARE_PAYLOAD_HEADER;
    memcpy(out->key_package, payload + SHARE_PAYLOAD_HEADER, out->key_package_len);
    return SHARE_KEY_OK;
}

int share_raw_load(const char *group, uint8_t out[STORAGE_SHARE_LEN], size_t *out_len) {
    char hex[STORAGE_SHARE_LEN * 2 + 1];
    if (!group || !out || !out_len || storage_load_share(group, hex, sizeof(hex)) != 0) {
        secure_memzero(hex, sizeof(hex));
        return SHARE_KEY_ERR_NOT_FOUND;
    }
    int len = hex_to_bytes(hex, out, STORAGE_SHARE_LEN);
    secure_memzero(hex, sizeof(hex));
    if (len <= 0) {
        secure_memzero(out, STORAGE_SHARE_LEN);
        return SHARE_KEY_ERR_DECODE;
    }
    *out_len = (size_t)len;
    return SHARE_KEY_OK;
}

int share_key_load(const char *group, share_key_t *out) {
    uint8_t raw[STORAGE_SHARE_LEN];
    size_t len = 0;
    int ret = share_raw_load(group, raw, &len);
    if (ret == SHARE_KEY_OK) {
        ret = share_payload_decode(raw, len, out);
    }
    secure_memzero(raw, sizeof(raw));
    if (ret != SHARE_KEY_OK && out) {
        secure_memzero(out, sizeof(*out));
    }
    return ret;
}

int share_key_save(const char *group, const share_key_t *key) {
    uint8_t raw[STORAGE_SHARE_LEN];
    char hex[STORAGE_SHARE_LEN * 2 + 1];
    size_t len = 0;
    int ret = share_payload_encode(key, raw, &len);
    if (ret == SHARE_KEY_OK) {
        bytes_to_hex(raw, len, hex, sizeof(hex));
        ret = storage_save_share(group, hex);
    }
    secure_memzero(raw, sizeof(raw));
    secure_memzero(hex, sizeof(hex));
    return ret;
}
