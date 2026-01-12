/**
 * @file protocol.h
 * @brief JSON-RPC protocol for FROST signing.
 *
 * Parses and formats JSON-RPC 2.0 messages over serial.
 *
 * @warning String fields are bounds-checked; callers must validate semantics.
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "error_context.h"

/** @name Protocol Limits */
/** @{ */
#define PROTOCOL_MAX_MESSAGE_LEN 16384
#define PROTOCOL_MAX_GROUP_LEN 64
#define PROTOCOL_MAX_HEX_LEN 512
#define PROTOCOL_MAX_PSBT_LEN 8192
#define PROTOCOL_VERSION "0.1.2"
#define PROTOCOL_API_VERSION 1
#define PROTOCOL_MAX_PARTICIPANTS 16
#define PROTOCOL_COMMITMENT_HEX_LEN 264
#define MAX_COMMITMENTS_SIZE ((PROTOCOL_MAX_PARTICIPANTS - 1) * PROTOCOL_COMMITMENT_HEX_LEN + 1)
/** @} */

/** @name JSON-RPC Error Codes */
/** @{ */
#define PROTOCOL_ERR_PARSE       -32700  /**< Invalid JSON */
#define PROTOCOL_ERR_INTERNAL    -32603  /**< Internal error */
#define PROTOCOL_ERR_METHOD      -32601  /**< Unknown method */
#define PROTOCOL_ERR_PARAMS      -32602  /**< Invalid params */
#define PROTOCOL_ERR_SHARE       -1      /**< Share error */
#define PROTOCOL_ERR_SIGN        -2      /**< Signing error */
#define PROTOCOL_ERR_STORAGE     -3      /**< Storage error */
/** @} */

/** @brief RPC method identifiers. */
typedef enum {
    RPC_METHOD_PING = 0,
    RPC_METHOD_GET_SHARE_PUBKEY,
    RPC_METHOD_GET_SHARE_INFO,
    RPC_METHOD_FROST_COMMIT,
    RPC_METHOD_FROST_SIGN,
    RPC_METHOD_IMPORT_SHARE,
    RPC_METHOD_DELETE_SHARE,
    RPC_METHOD_LIST_SHARES,
    RPC_METHOD_DKG_INIT,
    RPC_METHOD_DKG_ROUND1,
    RPC_METHOD_DKG_ROUND1_PEER,
    RPC_METHOD_DKG_ROUND2,
    RPC_METHOD_DKG_RECEIVE_SHARE,
    RPC_METHOD_DKG_FINALIZE,
    RPC_METHOD_BITCOIN_PARSE,
    RPC_METHOD_BITCOIN_SIGN,
    RPC_METHOD_POLICY_UPDATE,
    RPC_METHOD_POLICY_GET,
    RPC_METHOD_UNKNOWN
} rpc_method_t;

/** @brief Parsed RPC request. */
typedef struct {
    int id;                                 /**< Request ID */
    rpc_method_t method;                    /**< Method type */
    char group[PROTOCOL_MAX_GROUP_LEN + 1]; /**< Group ID */
    char message[PROTOCOL_MAX_HEX_LEN + 1]; /**< Hex message */
    char share[PROTOCOL_MAX_HEX_LEN + 1];   /**< Hex share */
    char session_id[65];                    /**< Session ID */
    char commitments[MAX_COMMITMENTS_SIZE]; /**< Commitments */
    uint8_t threshold;                      /**< DKG threshold */
    uint8_t participant_count;              /**< DKG participants */
    uint8_t our_index;                      /**< Our index */
    uint8_t peer_index;                     /**< Peer index */
    char dkg_data[2048];                    /**< DKG data */
    char *psbt;                             /**< PSBT (allocated) */
    size_t input_idx;                       /**< Input index */
    char policy_bundle[5120];               /**< Policy JSON */
} rpc_request_t;

/** @brief RPC response. */
typedef struct {
    int id;                                     /**< Request ID */
    bool success;                               /**< true=result, false=error */
    int error_code;                             /**< Error code */
    char error_msg[128];                        /**< Error message */
    char result[PROTOCOL_MAX_PSBT_LEN + 256];   /**< Result JSON */
    error_context_t error_ctx;                  /**< Extended error context */
} rpc_response_t;

/**
 * @brief Parse JSON-RPC request.
 * @param json JSON string
 * @param req Output request
 * @return 0 on success, PROTOCOL_ERR_* on failure
 * @note Call protocol_free_request() after use.
 */
int protocol_parse_request(const char *json, rpc_request_t *req);

/**
 * @brief Free request fields.
 * @param req Request to free
 */
void protocol_free_request(rpc_request_t *req);

/**
 * @brief Format response as JSON-RPC.
 * @param resp Response
 * @param buf Output buffer
 * @param len Buffer size
 * @return Bytes written, negative on error
 */
int protocol_format_response(const rpc_response_t *resp, char *buf, size_t len);

/**
 * @brief Set success response.
 * @param resp Response
 * @param id Request ID
 * @param result JSON result
 */
void protocol_success(rpc_response_t *resp, int id, const char *result);

/**
 * @brief Set error response.
 * @param resp Response
 * @param id Request ID
 * @param code Error code
 * @param message Error message
 */
void protocol_error(rpc_response_t *resp, int id, int code, const char *message);
void protocol_error_ctx(rpc_response_t *resp, int id, int code, const char *message,
                        const char *file, uint16_t line, const char *func);

#define PROTOCOL_ERROR(resp, id, code, msg) \
    protocol_error_ctx((resp), (id), (code), (msg), __FILE__, __LINE__, __func__)

#endif
