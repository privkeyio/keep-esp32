#ifndef POLICY_H
#define POLICY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "protocol.h"
#include "secresult.h"

#define POLICY_VERSION       1
#define POLICY_MAX_RULES_LEN 2048
#define POLICY_SIGNATURE_LEN 64
#define POLICY_PUBKEY_LEN    32
#define POLICY_HASH_LEN      32
#define POLICY_SLOT_SIZE     2560

#define POLICY_ERR_NOT_FOUND     -1
#define POLICY_ERR_INVALID_SIG   -2
#define POLICY_ERR_STORAGE       -3
#define POLICY_ERR_VERSION       -4
#define POLICY_ERR_NO_BUNDLE     -5
#define POLICY_ERR_HASH_MISMATCH -6
#define POLICY_ERR_DENIED        -7
#define POLICY_ERR_MALFORMED     -8

typedef struct {
    uint8_t version;
    uint8_t warden_pubkey[POLICY_PUBKEY_LEN];
    uint8_t policy_hash[POLICY_HASH_LEN];
    uint32_t rules_len;
    uint8_t rules[POLICY_MAX_RULES_LEN];
    uint64_t created_at;
    uint8_t signature[POLICY_SIGNATURE_LEN];
} __attribute__((packed)) policy_bundle_t;

int policy_init(void);
int policy_save_bundle(const policy_bundle_t *bundle);
int policy_load_bundle(policy_bundle_t *bundle);
int policy_delete_bundle(void);
bool policy_has_bundle(void);
int policy_verify_signature(const policy_bundle_t *bundle);
secresult_t policy_verify_signature_secure(const policy_bundle_t *bundle);
int policy_check_hash(const policy_bundle_t *bundle, const uint8_t expected_hash[POLICY_HASH_LEN]);
secresult_t policy_check_hash_secure(const policy_bundle_t *bundle, const uint8_t expected_hash[POLICY_HASH_LEN]);

void policy_handle_update(const rpc_request_t *req, rpc_response_t *resp);
void policy_handle_get(const rpc_request_t *req, rpc_response_t *resp);

int policy_evaluate(uint64_t total_out_sats, uint64_t fee_sats);
secresult_t policy_evaluate_secure(uint64_t total_out_sats, uint64_t fee_sats);

#endif
