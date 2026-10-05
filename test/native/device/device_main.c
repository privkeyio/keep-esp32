// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

/* A host build of the device's request handlers for end-to-end tests. Only flash,
 * share storage and the secure element are replaced; signing, PSBT and policy code
 * is the firmware's own. Reads one JSON-RPC request per line on stdin and writes
 * one response per line on stdout. Not a test_* binary: it blocks on stdin. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cJSON.h>
#include <wally_core.h>
#include <wally_psbt.h>
#include <wally_psbt_members.h>
#include <wally_transaction.h>

#include "bitcoin_rpc.h"
#include "esp_partition.h"
#include "frost_signer.h"
#include "policy.h"
#include "protocol.h"
#include "random_utils.h"
#include "sign_approval.h"
#include "storage.h"
#include "ux_interface.h"

static struct {
    char group[STORAGE_GROUP_LEN + 1];
    char share_hex[STORAGE_SHARE_LEN * 2 + 1];
    bool used;
} shares[STORAGE_MAX_SHARES];

int storage_save_share(const char *group, const char *share_hex) {
    if (!group || !share_hex || strlen(group) > STORAGE_GROUP_LEN ||
        strlen(share_hex) > STORAGE_SHARE_LEN * 2) {
        return STORAGE_ERR_INVALID_DATA;
    }
    for (int i = 0; i < STORAGE_MAX_SHARES; i++) {
        if (!shares[i].used || strcmp(shares[i].group, group) == 0) {
            shares[i].used = true;
            strcpy(shares[i].group, group);
            strcpy(shares[i].share_hex, share_hex);
            return STORAGE_OK;
        }
    }
    return STORAGE_ERR_NO_SLOT;
}

int storage_load_share(const char *group, char *share_hex, size_t len) {
    for (int i = 0; i < STORAGE_MAX_SHARES; i++) {
        if (shares[i].used && strcmp(shares[i].group, group) == 0) {
            if (strlen(shares[i].share_hex) >= len) {
                return -1;
            }
            strcpy(share_hex, shares[i].share_hex);
            return 0;
        }
    }
    return -1;
}

int storage_delete_share(const char *group) {
    for (int i = 0; i < STORAGE_MAX_SHARES; i++) {
        if (shares[i].used && strcmp(shares[i].group, group) == 0) {
            memset(&shares[i], 0, sizeof(shares[i]));
            return 0;
        }
    }
    return -1;
}

bool storage_has_share(const char *group) {
    char buf[STORAGE_SHARE_LEN * 2 + 1];
    return storage_load_share(group, buf, sizeof(buf)) == 0;
}

int storage_load_metadata(const char *group, group_metadata_t *metadata) {
    (void)group;
    (void)metadata;
    return -1;
}

/* Session checkpoints live in a flash partition on the device; here they are in memory
 * so frost_session_resume runs exactly as it does there. */
static struct {
    uint8_t id[STORAGE_SESSION_ID_LEN];
    uint8_t data[STORAGE_CHECKPOINT_MAX_SIZE];
    size_t len;
    bool used;
} checkpoints[STORAGE_MAX_SESSION_CHECKPOINTS];

static int find_checkpoint(const uint8_t *id) {
    for (int i = 0; i < STORAGE_MAX_SESSION_CHECKPOINTS; i++) {
        if (checkpoints[i].used && memcmp(checkpoints[i].id, id, STORAGE_SESSION_ID_LEN) == 0) {
            return i;
        }
    }
    return -1;
}

int storage_save_session_checkpoint(const uint8_t *id, const void *d, size_t l) {
    int i = find_checkpoint(id);
    for (int j = 0; i < 0 && j < STORAGE_MAX_SESSION_CHECKPOINTS; j++) {
        if (!checkpoints[j].used) {
            i = j;
        }
    }
    if (i < 0 || l > STORAGE_CHECKPOINT_MAX_SIZE) {
        return -1;
    }
    memcpy(checkpoints[i].id, id, STORAGE_SESSION_ID_LEN);
    memcpy(checkpoints[i].data, d, l);
    checkpoints[i].len = l;
    checkpoints[i].used = true;
    return 0;
}

int storage_load_session_checkpoint(const uint8_t *id, void *d, size_t l) {
    int i = find_checkpoint(id);
    if (i < 0 || checkpoints[i].len != l) {
        return -1;
    }
    memcpy(d, checkpoints[i].data, l);
    return 0;
}

int storage_delete_session_checkpoint(const uint8_t *id) {
    int i = find_checkpoint(id);
    if (i >= 0) {
        memset(&checkpoints[i], 0, sizeof(checkpoints[i]));
    }
    return 0;
}

int storage_list_session_checkpoints(uint8_t ids[][STORAGE_SESSION_ID_LEN], int m) {
    int n = 0;
    for (int i = 0; i < STORAGE_MAX_SESSION_CHECKPOINTS && n < m; i++) {
        if (checkpoints[i].used) {
            memcpy(ids[n++], checkpoints[i].id, STORAGE_SESSION_ID_LEN);
        }
    }
    return n;
}

int storage_count_session_checkpoints(void) {
    int n = 0;
    for (int i = 0; i < STORAGE_MAX_SESSION_CHECKPOINTS; i++) {
        n += checkpoints[i].used;
    }
    return n;
}

#define PARTITION_SIZE 65536
static uint8_t policy_flash[PARTITION_SIZE];
static const esp_partition_t policy_part = {.label = "policy", .size = PARTITION_SIZE};

const esp_partition_t *esp_partition_find_first(esp_partition_type_t type,
                                                esp_partition_subtype_t subtype,
                                                const char *label) {
    (void)type;
    (void)subtype;
    return strcmp(label, "policy") == 0 ? &policy_part : NULL;
}

esp_err_t esp_partition_read(const esp_partition_t *p, size_t off, void *dst, size_t size) {
    if (p != &policy_part || off + size > PARTITION_SIZE) {
        return ESP_FAIL;
    }
    memcpy(dst, policy_flash + off, size);
    return ESP_OK;
}

static bool fail_next_flash_write = false;

esp_err_t esp_partition_write(const esp_partition_t *p, size_t off, const void *src, size_t size) {
    if (p != &policy_part || off + size > PARTITION_SIZE) {
        return ESP_FAIL;
    }
    if (fail_next_flash_write) {
        fail_next_flash_write = false;
        return ESP_FAIL;
    }
    const uint8_t *s = src;
    for (size_t i = 0; i < size; i++) {
        policy_flash[off + i] &= s[i];
    }
    return ESP_OK;
}

esp_err_t esp_partition_erase_range(const esp_partition_t *p, size_t off, size_t size) {
    if (p != &policy_part || off + size > PARTITION_SIZE || off % 4096 || size % 4096) {
        return ESP_FAIL;
    }
    memset(policy_flash + off, 0xFF, size);
    return ESP_OK;
}

static void make_psbt(cJSON *params, int id, rpc_response_t *resp) {
    cJSON *key = cJSON_GetObjectItem(params, "xonly");
    cJSON *amount = cJSON_GetObjectItem(params, "amount");
    cJSON *sighash = cJSON_GetObjectItem(params, "sighash");
    uint8_t script[34] = {0x51, 0x20};
    size_t written = 0;
    if (!cJSON_IsString(key) || !cJSON_IsNumber(amount) || amount->valuedouble < 1000.0 ||
        wally_hex_to_bytes(key->valuestring, script + 2, 32, &written) != WALLY_OK ||
        written != 32) {
        protocol_error(resp, id, PROTOCOL_ERR_PARAMS, "bad params");
        return;
    }
    static const uint8_t prev_txid[32] = {0xab};
    uint64_t sats = (uint64_t)amount->valuedouble;
    struct wally_tx *tx = NULL;
    struct wally_psbt *psbt = NULL;
    struct wally_tx_output *utxo = NULL;
    char *b64 = NULL;
    int ok =
        wally_tx_init_alloc(2, 0, 1, 1, &tx) == WALLY_OK &&
        wally_tx_add_raw_input(tx, prev_txid, 32, 0, 0xfffffffd, NULL, 0, NULL, 0) == WALLY_OK &&
        wally_tx_add_raw_output(tx, sats - 1000, script, sizeof(script), 0) == WALLY_OK &&
        wally_psbt_from_tx(tx, 0, 0, &psbt) == WALLY_OK &&
        wally_tx_output_init_alloc(sats, script, sizeof(script), &utxo) == WALLY_OK &&
        wally_psbt_input_set_witness_utxo(&psbt->inputs[0], utxo) == WALLY_OK &&
        (!cJSON_IsNumber(sighash) ||
         wally_psbt_input_set_sighash(&psbt->inputs[0], (uint32_t)sighash->valueint) == WALLY_OK) &&
        wally_psbt_to_base64(psbt, 0, &b64) == WALLY_OK;
    if (ok) {
        static char result[PROTOCOL_MAX_PSBT_LEN + 32];
        snprintf(result, sizeof(result), "{\"psbt\":\"%s\"}", b64);
        protocol_success(resp, id, result);
    } else {
        protocol_error(resp, id, PROTOCOL_ERR_INTERNAL, "could not build PSBT");
    }
    wally_free_string(b64);
    wally_tx_output_free(utxo);
    wally_psbt_free(psbt);
    wally_tx_free(tx);
}

static void psbt_reply(struct wally_psbt *psbt, int id, rpc_response_t *resp) {
    char *b64 = NULL;
    if (wally_psbt_to_base64(psbt, 0, &b64) != WALLY_OK) {
        protocol_error(resp, id, PROTOCOL_ERR_INTERNAL, "could not encode PSBT");
        return;
    }
    static char result[PROTOCOL_MAX_PSBT_LEN + 32];
    snprintf(result, sizeof(result), "{\"psbt\":\"%s\"}", b64);
    protocol_success(resp, id, result);
    wally_free_string(b64);
}

static void set_sighash(cJSON *params, int id, rpc_response_t *resp) {
    cJSON *b64 = cJSON_GetObjectItem(params, "psbt");
    cJSON *sighash = cJSON_GetObjectItem(params, "sighash");
    struct wally_psbt *psbt = NULL;
    if (!cJSON_IsString(b64) || !cJSON_IsNumber(sighash) ||
        wally_psbt_from_base64(b64->valuestring, 0, &psbt) != WALLY_OK || psbt->num_inputs == 0 ||
        wally_psbt_input_set_sighash(&psbt->inputs[0], (uint32_t)sighash->valueint) != WALLY_OK) {
        protocol_error(resp, id, PROTOCOL_ERR_PARAMS, "bad params");
    } else {
        psbt_reply(psbt, id, resp);
    }
    wally_psbt_free(psbt);
}

static void finalize(cJSON *params, int id, rpc_response_t *resp) {
    cJSON *b64 = cJSON_GetObjectItem(params, "psbt");
    cJSON *sig_hex = cJSON_GetObjectItem(params, "witness_sig");
    struct wally_psbt *psbt = NULL;
    struct wally_tx_witness_stack *wit = NULL;
    struct wally_tx *tx = NULL;
    char *hex = NULL;
    uint8_t sig[65];
    size_t sig_len = 0;
    int ok = cJSON_IsString(b64) && cJSON_IsString(sig_hex) &&
             wally_hex_to_bytes(sig_hex->valuestring, sig, sizeof(sig), &sig_len) == WALLY_OK &&
             wally_psbt_from_base64(b64->valuestring, 0, &psbt) == WALLY_OK &&
             psbt->num_inputs > 0 && wally_tx_witness_stack_init_alloc(1, &wit) == WALLY_OK &&
             wally_tx_witness_stack_add(wit, sig, sig_len) == WALLY_OK &&
             wally_psbt_input_set_final_witness(&psbt->inputs[0], wit) == WALLY_OK &&
             wally_psbt_extract(psbt, 0, &tx) == WALLY_OK &&
             wally_tx_to_hex(tx, WALLY_TX_FLAG_USE_WITNESS, &hex) == WALLY_OK;
    if (ok) {
        static char result[PROTOCOL_MAX_PSBT_LEN + 32];
        snprintf(result, sizeof(result), "{\"hex\":\"%s\"}", hex);
        protocol_success(resp, id, result);
    } else {
        protocol_error(resp, id, PROTOCOL_ERR_PARAMS, "could not finalize");
    }
    wally_free_string(hex);
    wally_tx_free(tx);
    wally_tx_witness_stack_free(wit);
    wally_psbt_free(psbt);
}

/* The pin record lives in NVS on the device; here it is in memory. */
static bool pin_present = false;
static policy_pin_t pin_record;
static bool fail_pin_read = false;

int policy_pin_read(policy_pin_t *pin) {
    if (fail_pin_read) {
        return POLICY_ERR_STORAGE;
    }
    if (!pin_present) {
        return POLICY_ERR_NOT_FOUND;
    }
    memcpy(pin, &pin_record, sizeof(*pin));
    return 0;
}

static bool fail_next_pin_write = false;

int policy_pin_write(const policy_pin_t *pin) {
    if (fail_next_pin_write) {
        fail_next_pin_write = false;
        return POLICY_ERR_STORAGE;
    }
    memcpy(&pin_record, pin, sizeof(*pin));
    pin_present = true;
    return 0;
}

/* The display asks the user to trust a Warden key before the first policy is
 * pinned. Here the test sets the answer; unset, it refuses like a headless device. */
static bool confirm_answer = false;
static int confirm_prompts = 0;
static uint8_t confirm_last_key[32];

bool ux_confirm_warden_pin(const uint8_t pubkey[32], uint32_t timeout_ms) {
    (void)timeout_ms;
    confirm_prompts++;
    memcpy(confirm_last_key, pubkey, 32);
    return confirm_answer;
}

static int pin_reports_ok = 0;
static int pin_reports_failed = 0;

void ux_report_warden_pin(bool saved) {
    if (saved) {
        pin_reports_ok++;
    } else {
        pin_reports_failed++;
    }
}

static void handle_test_method(const char *line, int id, rpc_response_t *resp) {
    cJSON *root = cJSON_Parse(line);
    cJSON *method = root ? cJSON_GetObjectItem(root, "method") : NULL;
    cJSON *params = root ? cJSON_GetObjectItem(root, "params") : NULL;
    const char *m = cJSON_IsString(method) ? method->valuestring : "";
    if (strcmp(m, "test_set_confirm") == 0 && params) {
        confirm_answer = cJSON_IsTrue(cJSON_GetObjectItem(params, "approve"));
        protocol_success(resp, id, "{\"ok\":true}");
    } else if (strcmp(m, "test_cut_during_policy_write") == 0) {
        /* Power lost after the sector erase and before the write completes. */
        fail_next_flash_write = true;
        protocol_success(resp, id, "{\"ok\":true}");
    } else if (strcmp(m, "test_cut_before_pin_raise") == 0) {
        /* Power lost after the bundle is written and before the pin is raised. */
        fail_next_pin_write = true;
        protocol_success(resp, id, "{\"ok\":true}");
    } else if (strcmp(m, "test_boot_policy") == 0) {
        policy_raise_lagging_pin();
        protocol_success(resp, id, "{\"ok\":true}");
    } else if (strcmp(m, "test_fail_pin_read") == 0 && params) {
        fail_pin_read = cJSON_IsTrue(cJSON_GetObjectItem(params, "fail"));
        protocol_success(resp, id, "{\"ok\":true}");
    } else if (strcmp(m, "test_erase_policy_sector") == 0) {
        memset(policy_flash, 0xFF, 4096);
        protocol_success(resp, id, "{\"ok\":true}");
    } else if (strcmp(m, "test_install_legacy_bundle") == 0 && params) {
        /* A bundle stored by firmware that predates the pin record. */
        cJSON *hex = cJSON_GetObjectItem(params, "bundle");
        size_t written = 0;
        memset(policy_flash, 0xFF, 4096);
        if (cJSON_IsString(hex) &&
            wally_hex_to_bytes(hex->valuestring, policy_flash, sizeof(policy_bundle_t), &written) ==
                WALLY_OK) {
            protocol_success(resp, id, "{\"ok\":true}");
        } else {
            protocol_error(resp, id, PROTOCOL_ERR_PARAMS, "bad bundle");
        }
    } else if (strcmp(m, "test_advance_clock") == 0 && params) {
        cJSON *ms = cJSON_GetObjectItem(params, "ms");
        sign_approval_test_advance_ms(cJSON_IsNumber(ms) ? (uint32_t)ms->valuedouble : 0);
        protocol_success(resp, id, "{\"ok\":true}");
    } else if (strcmp(m, "test_corrupt_policy") == 0) {
        policy_flash[sizeof(policy_bundle_t) - 1] ^= 0x01;
        protocol_success(resp, id, "{\"ok\":true}");
    } else if (strcmp(m, "test_confirm_log") == 0) {
        char key_hex[65], result[128];
        for (int i = 0; i < 32; i++) {
            snprintf(key_hex + 2 * i, 3, "%02x", confirm_last_key[i]);
        }
        snprintf(result, sizeof(result),
                 "{\"prompts\":%d,\"last_key\":\"%s\",\"saved\":%d,\"save_failed\":%d}",
                 confirm_prompts, key_hex, pin_reports_ok, pin_reports_failed);
        protocol_success(resp, id, result);
    } else if (strcmp(m, "test_set_sighash") == 0 && params) {
        set_sighash(params, id, resp);
    } else if (strcmp(m, "test_finalize") == 0 && params) {
        finalize(params, id, resp);
    } else if (strcmp(m, "test_make_psbt") == 0 && params) {
        make_psbt(params, id, resp);
    } else {
        protocol_error(resp, id, PROTOCOL_ERR_METHOD, "Unknown method");
    }
    resp->id = id;
    cJSON_Delete(root);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    memset(policy_flash, 0xFF, sizeof(policy_flash));
    if (rng_init() != 0 || policy_init() != 0 || frost_signer_init() != 0 ||
        bitcoin_rpc_init() != 0) {
        fprintf(stderr, "device init failed\n");
        return 1;
    }
    policy_raise_lagging_pin();

    static char line[PROTOCOL_MAX_MESSAGE_LEN];
    static char out[PROTOCOL_MAX_MESSAGE_LEN];
    static rpc_request_t req;
    static rpc_response_t resp;
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (!line[0]) {
            continue;
        }
        memset(&req, 0, sizeof(req));
        memset(&resp, 0, sizeof(resp));
        int parsed = protocol_parse_request(line, &req);
        resp.id = req.id;
        frost_signer_cleanup_stale();
        if (parsed != 0) {
            protocol_error(&resp, req.id, PROTOCOL_ERR_PARSE, "Parse error");
        } else if (req.method == RPC_METHOD_UNKNOWN) {
            handle_test_method(line, req.id, &resp);
        } else {
            switch (req.method) {
            case RPC_METHOD_PING:
                protocol_success(&resp, req.id, "{\"version\":\"native\"}");
                break;
            case RPC_METHOD_IMPORT_SHARE:
                if (storage_save_share(req.group, req.share) == STORAGE_OK) {
                    protocol_success(&resp, req.id, "{\"ok\":true}");
                } else {
                    protocol_error(&resp, req.id, PROTOCOL_ERR_STORAGE, "Storage error");
                }
                break;
            case RPC_METHOD_GET_SHARE_PUBKEY:
                frost_get_pubkey(req.group, &resp);
                break;
            case RPC_METHOD_FROST_COMMIT:
                frost_commit(req.group, req.session_id, req.message, &resp);
                break;
            case RPC_METHOD_FROST_SIGN:
                frost_sign(req.group, req.session_id, req.commitments, &resp);
                break;
            case RPC_METHOD_SESSION_RESUME:
                frost_session_resume(req.session_id, &resp);
                break;
            case RPC_METHOD_BITCOIN_PARSE:
                bitcoin_rpc_parse(&req, &resp);
                break;
            case RPC_METHOD_BITCOIN_SIGN:
                bitcoin_rpc_sign(&req, &resp);
                break;
            case RPC_METHOD_POLICY_UPDATE:
                policy_handle_update(&req, &resp);
                break;
            case RPC_METHOD_POLICY_GET:
                policy_handle_get(&req, &resp);
                break;
            default:
                protocol_error(&resp, req.id, PROTOCOL_ERR_METHOD, "Not available in harness");
                break;
            }
        }
        protocol_free_request(&req);
        if (protocol_format_response(&resp, out, sizeof(out)) < 0) {
            fprintf(stdout, "{\"id\":%d,\"error\":{\"code\":-1,\"message\":\"format\"}}\n",
                    resp.id);
        } else {
            fprintf(stdout, "%s\n", out);
        }
        fflush(stdout);
    }
    return 0;
}
