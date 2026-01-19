// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "frost_signer_storage.h"
#include "hex_utils.h"
#include "crypto_asm.h"
#include <string.h>

static share_store_t default_store = {.load = storage_load_share,
                                      .save = storage_save_share,
                                      .delete_share = storage_delete_share,
                                      .exists = storage_has_share};

const share_store_t *share_store_default(void) {
    return &default_store;
}

share_store_t share_store_create(share_load_fn load, share_save_fn save,
                                 share_delete_fn delete_share, share_exists_fn exists,
                                 bool *valid) {
    share_store_t store = {
        .load = load, .save = save, .delete_share = delete_share, .exists = exists};
    if (valid) {
        *valid = (load != NULL && save != NULL && delete_share != NULL && exists != NULL);
    }
    return store;
}

int share_store_load_frost_state(const share_store_t *store, const char *group,
                                 frost_state_t *state) {
    if (!store || !store->load || !group || !state) {
        return SHARE_STORE_ERR_NOT_FOUND;
    }

    char share_hex[STORAGE_SHARE_LEN * 2 + 1];
    if (store->load(group, share_hex, sizeof(share_hex)) != 0) {
        return SHARE_STORE_ERR_NOT_FOUND;
    }

    uint8_t share_bytes[STORAGE_SHARE_LEN];
    int share_len = hex_to_bytes(share_hex, share_bytes, sizeof(share_bytes));

    secure_memzero(share_hex, sizeof(share_hex));

    if (share_len < 0) {
        secure_memzero(share_bytes, sizeof(share_bytes));
        return SHARE_STORE_ERR_DECODE;
    }

    int ret = frost_init(state, share_bytes, (size_t)share_len);
    secure_memzero(share_bytes, sizeof(share_bytes));

    if (ret != 0) {
        return SHARE_STORE_ERR_INIT;
    }

    return SHARE_STORE_OK;
}

int share_store_load_share_bytes(const share_store_t *store, const char *group,
                                 uint8_t *share_bytes, size_t max_len, size_t *out_len) {
    if (!store || !store->load || !group || !share_bytes || !out_len) {
        return SHARE_STORE_ERR_NOT_FOUND;
    }

    *out_len = 0;

    char share_hex[STORAGE_SHARE_LEN * 2 + 1];
    if (store->load(group, share_hex, sizeof(share_hex)) != 0) {
        return SHARE_STORE_ERR_NOT_FOUND;
    }
    share_hex[sizeof(share_hex) - 1] = '\0';

    int share_len = hex_to_bytes(share_hex, share_bytes, max_len);
    secure_memzero(share_hex, sizeof(share_hex));

    if (share_len < 0) {
        secure_memzero(share_bytes, max_len);
        return SHARE_STORE_ERR_DECODE;
    }

    *out_len = (size_t)share_len;
    return SHARE_STORE_OK;
}
