// SPDX-FileCopyrightText: © 2026 Privkey Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "error_codes.h"

const char *error_category_name(int code) {
    switch (ERROR_CATEGORY(code)) {
    case ERR_CAT_PROTOCOL:
        return "protocol";
    case ERR_CAT_FROST:
        return "frost";
    case ERR_CAT_DKG:
        return "dkg";
    case ERR_CAT_STORAGE:
        return "storage";
    case ERR_CAT_POLICY:
        return "policy";
    case ERR_CAT_SESSION:
        return "session";
    case ERR_CAT_CRYPTO:
        return "crypto";
    case ERR_CAT_PIN:
        return "pin";
    case ERR_CAT_SE:
        return "secure_element";
    case ERR_CAT_PSBT:
        return "psbt";
    case ERR_CAT_NOSTR:
        return "nostr";
    default:
        return "unknown";
    }
}

const char *error_name(int code) {
    switch (code) {
    case ERR_PROTOCOL_PARSE:
        return "PROTOCOL_PARSE";
    case ERR_PROTOCOL_METHOD:
        return "PROTOCOL_METHOD";
    case ERR_PROTOCOL_PARAMS:
        return "PROTOCOL_PARAMS";
    case ERR_PROTOCOL_INTERNAL:
        return "PROTOCOL_INTERNAL";

    case ERR_FROST_NO_SHARE:
        return "FROST_NO_SHARE";
    case ERR_FROST_INVALID_SESSION:
        return "FROST_INVALID_SESSION";
    case ERR_FROST_NONCE_REUSE:
        return "FROST_NONCE_REUSE";
    case ERR_FROST_BAD_COMMITMENT:
        return "FROST_BAD_COMMITMENT";
    case ERR_FROST_AGGREGATION:
        return "FROST_AGGREGATION";
    case ERR_FROST_SIGN_FAILED:
        return "FROST_SIGN_FAILED";
    case ERR_FROST_THRESHOLD:
        return "FROST_THRESHOLD";
    case ERR_FROST_PARSE:
        return "FROST_PARSE";
    case ERR_FROST_OVERFLOW:
        return "FROST_OVERFLOW";

    case ERR_DKG_INVALID_STATE:
        return "DKG_INVALID_STATE";
    case ERR_DKG_DUPLICATE_SHARE:
        return "DKG_DUPLICATE_SHARE";
    case ERR_DKG_VERIFICATION:
        return "DKG_VERIFICATION";
    case ERR_DKG_TIMEOUT:
        return "DKG_TIMEOUT";
    case ERR_DKG_INVALID_PARAMS:
        return "DKG_INVALID_PARAMS";

    case ERR_STORAGE_FULL:
        return "STORAGE_FULL";
    case ERR_STORAGE_NOT_FOUND:
        return "STORAGE_NOT_FOUND";
    case ERR_STORAGE_CORRUPT:
        return "STORAGE_CORRUPT";
    case ERR_STORAGE_DECRYPT:
        return "STORAGE_DECRYPT";
    case ERR_STORAGE_NOT_INIT:
        return "STORAGE_NOT_INIT";
    case ERR_STORAGE_CRYPTO:
        return "STORAGE_CRYPTO";
    case ERR_STORAGE_INVALID:
        return "STORAGE_INVALID";
    case ERR_STORAGE_IO:
        return "STORAGE_IO";
    case ERR_STORAGE_INVALID_DATA:
        return "STORAGE_INVALID_DATA";
    case ERR_STORAGE_INVALID_GROUP:
        return "STORAGE_INVALID_GROUP";
    case ERR_STORAGE_MIGRATION:
        return "STORAGE_MIGRATION";
    case ERR_STORAGE_ENCRYPT:
        return "STORAGE_ENCRYPT";

    case ERR_POLICY_DENIED:
        return "POLICY_DENIED";
    case ERR_POLICY_INVALID_SIG:
        return "POLICY_INVALID_SIG";
    case ERR_POLICY_EXPIRED:
        return "POLICY_EXPIRED";
    case ERR_POLICY_FEE_EXCEEDED:
        return "POLICY_FEE_EXCEEDED";
    case ERR_POLICY_NOT_FOUND:
        return "POLICY_NOT_FOUND";
    case ERR_POLICY_STORAGE:
        return "POLICY_STORAGE";
    case ERR_POLICY_VERSION:
        return "POLICY_VERSION";
    case ERR_POLICY_NO_BUNDLE:
        return "POLICY_NO_BUNDLE";
    case ERR_POLICY_HASH:
        return "POLICY_HASH";
    case ERR_POLICY_MALFORMED:
        return "POLICY_MALFORMED";

    case ERR_SESSION_INVALID_STATE:
        return "SESSION_INVALID_STATE";
    case ERR_SESSION_NOT_FOUND:
        return "SESSION_NOT_FOUND";
    case ERR_SESSION_EXPIRED:
        return "SESSION_EXPIRED";
    case ERR_SESSION_DUPLICATE:
        return "SESSION_DUPLICATE";
    case ERR_SESSION_INVALID_LEN:
        return "SESSION_INVALID_LEN";
    case ERR_SESSION_REPLAY:
        return "SESSION_REPLAY";
    case ERR_SESSION_NOT_PARTICIPANT:
        return "SESSION_NOT_PARTICIPANT";

    case ERR_CRYPTO_RNG_FAIL:
        return "CRYPTO_RNG_FAIL";
    case ERR_CRYPTO_VERIFY_FAIL:
        return "CRYPTO_VERIFY_FAIL";
    case ERR_CRYPTO_SIGN_FAIL:
        return "CRYPTO_SIGN_FAIL";
    case ERR_CRYPTO_HASH_FAIL:
        return "CRYPTO_HASH_FAIL";

    case ERR_PIN_REQUIRED:
        return "PIN_REQUIRED";
    case ERR_PIN_INVALID:
        return "PIN_INVALID";
    case ERR_PIN_LOCKED:
        return "PIN_LOCKED";
    case ERR_PIN_MUST_WAIT:
        return "PIN_MUST_WAIT";
    case ERR_PIN_BRICKED:
        return "PIN_BRICKED";

    case ERR_SE_INVALID_PARAM:
        return "SE_INVALID_PARAM";
    case ERR_SE_NOT_PROVISIONED:
        return "SE_NOT_PROVISIONED";
    case ERR_SE_COMM_FAIL:
        return "SE_COMM_FAIL";
    case ERR_SE_LOCKED:
        return "SE_LOCKED";
    case ERR_SE_NOT_INIT:
        return "SE_NOT_INIT";

    case ERR_PSBT_PARSE:
        return "PSBT_PARSE";
    case ERR_PSBT_INVALID:
        return "PSBT_INVALID";
    case ERR_PSBT_SIGN:
        return "PSBT_SIGN";

    case ERR_NOSTR_PARSE:
        return "NOSTR_PARSE";
    case ERR_NOSTR_DECRYPT:
        return "NOSTR_DECRYPT";
    case ERR_NOSTR_SIGN:
        return "NOSTR_SIGN";
    case ERR_NOSTR_RELAY:
        return "NOSTR_RELAY";

    default:
        return "UNKNOWN";
    }
}

const char *error_to_string(int code) {
    switch (code) {
    case ERR_PROTOCOL_PARSE:
        return "Invalid JSON";
    case ERR_PROTOCOL_METHOD:
        return "Unknown method";
    case ERR_PROTOCOL_PARAMS:
        return "Invalid parameters";
    case ERR_PROTOCOL_INTERNAL:
        return "Internal error";

    case ERR_FROST_NO_SHARE:
        return "Share not found";
    case ERR_FROST_INVALID_SESSION:
        return "Invalid signing session";
    case ERR_FROST_NONCE_REUSE:
        return "Nonce reuse detected";
    case ERR_FROST_BAD_COMMITMENT:
        return "Invalid commitment";
    case ERR_FROST_AGGREGATION:
        return "Signature aggregation failed";
    case ERR_FROST_SIGN_FAILED:
        return "Signing failed";
    case ERR_FROST_THRESHOLD:
        return "Threshold not met";
    case ERR_FROST_PARSE:
        return "Failed to parse FROST data";
    case ERR_FROST_OVERFLOW:
        return "Buffer overflow";

    case ERR_DKG_INVALID_STATE:
        return "Invalid DKG state";
    case ERR_DKG_DUPLICATE_SHARE:
        return "Duplicate share received";
    case ERR_DKG_VERIFICATION:
        return "Share verification failed";
    case ERR_DKG_TIMEOUT:
        return "DKG timed out";
    case ERR_DKG_INVALID_PARAMS:
        return "Invalid DKG parameters";

    case ERR_STORAGE_FULL:
        return "Storage full";
    case ERR_STORAGE_NOT_FOUND:
        return "Not found in storage";
    case ERR_STORAGE_CORRUPT:
        return "Storage data corrupted";
    case ERR_STORAGE_DECRYPT:
        return "Decryption failed";
    case ERR_STORAGE_NOT_INIT:
        return "Storage not initialized";
    case ERR_STORAGE_CRYPTO:
        return "Storage crypto not initialized";
    case ERR_STORAGE_INVALID:
        return "Invalid storage data";
    case ERR_STORAGE_IO:
        return "Storage I/O error";
    case ERR_STORAGE_INVALID_DATA:
        return "Invalid data format";
    case ERR_STORAGE_INVALID_GROUP:
        return "Invalid group name";
    case ERR_STORAGE_MIGRATION:
        return "Migration failed";
    case ERR_STORAGE_ENCRYPT:
        return "Encryption failed";

    case ERR_POLICY_DENIED:
        return "Policy denied operation";
    case ERR_POLICY_INVALID_SIG:
        return "Invalid policy signature";
    case ERR_POLICY_EXPIRED:
        return "Policy expired";
    case ERR_POLICY_FEE_EXCEEDED:
        return "Fee exceeds policy limit";
    case ERR_POLICY_NOT_FOUND:
        return "Policy not found";
    case ERR_POLICY_STORAGE:
        return "Policy storage error";
    case ERR_POLICY_VERSION:
        return "Unsupported policy version";
    case ERR_POLICY_NO_BUNDLE:
        return "No policy bundle";
    case ERR_POLICY_HASH:
        return "Policy hash mismatch";
    case ERR_POLICY_MALFORMED:
        return "Malformed policy";

    case ERR_SESSION_INVALID_STATE:
        return "Invalid session state";
    case ERR_SESSION_NOT_FOUND:
        return "Session not found";
    case ERR_SESSION_EXPIRED:
        return "Session expired";
    case ERR_SESSION_DUPLICATE:
        return "Duplicate session";
    case ERR_SESSION_INVALID_LEN:
        return "Invalid session length";
    case ERR_SESSION_REPLAY:
        return "Session replay detected";
    case ERR_SESSION_NOT_PARTICIPANT:
        return "Not a session participant";

    case ERR_CRYPTO_RNG_FAIL:
        return "Random number generation failed";
    case ERR_CRYPTO_VERIFY_FAIL:
        return "Signature verification failed";
    case ERR_CRYPTO_SIGN_FAIL:
        return "Signing operation failed";
    case ERR_CRYPTO_HASH_FAIL:
        return "Hash computation failed";

    case ERR_PIN_REQUIRED:
        return "PIN required";
    case ERR_PIN_INVALID:
        return "Invalid PIN";
    case ERR_PIN_LOCKED:
        return "PIN locked";
    case ERR_PIN_MUST_WAIT:
        return "Too many attempts, wait required";
    case ERR_PIN_BRICKED:
        return "Device bricked";

    case ERR_SE_INVALID_PARAM:
        return "Invalid secure element parameter";
    case ERR_SE_NOT_PROVISIONED:
        return "Secure element not provisioned";
    case ERR_SE_COMM_FAIL:
        return "Secure element communication failed";
    case ERR_SE_LOCKED:
        return "Secure element locked";
    case ERR_SE_NOT_INIT:
        return "Secure element not initialized";

    case ERR_PSBT_PARSE:
        return "Failed to parse PSBT";
    case ERR_PSBT_INVALID:
        return "Invalid PSBT";
    case ERR_PSBT_SIGN:
        return "PSBT signing failed";

    case ERR_NOSTR_PARSE:
        return "Failed to parse Nostr event";
    case ERR_NOSTR_DECRYPT:
        return "Nostr decryption failed";
    case ERR_NOSTR_SIGN:
        return "Nostr signing failed";
    case ERR_NOSTR_RELAY:
        return "Nostr relay error";

    default:
        return "Unknown error";
    }
}

int error_to_jsonrpc_code(int code) {
    switch (code) {
    case ERR_PROTOCOL_PARSE:
        return -32700;
    case ERR_PROTOCOL_METHOD:
        return -32601;
    case ERR_PROTOCOL_PARAMS:
        return -32602;
    case ERR_PROTOCOL_INTERNAL:
        return -32603;
    default:
        return code;
    }
}
