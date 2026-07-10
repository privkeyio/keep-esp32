// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#ifndef FROST_COORDINATOR_H
#define FROST_COORDINATOR_H

#include "nostr_frost.h"
#include <stdbool.h>
#include <stdint.h>

#define COORDINATOR_MAX_RELAYS 4
#define COORDINATOR_MAX_GROUPS 4
#define COORDINATOR_TIMEOUT_MS 30000

// Keepalive is delegated to the websocket transport: it pings every
// WS_PING_INTERVAL_SEC and drops the connection if no pong arrives within
// WS_PONG_TIMEOUT_SEC, which surfaces here as a disconnect event.
#define WS_PING_INTERVAL_SEC 30
#define WS_PONG_TIMEOUT_SEC  10

#define WS_RECONNECT_BASE_MS      1000
#define WS_RECONNECT_MAX_MS       30000
#define WS_RECONNECT_MAX_ATTEMPTS 5
#define WS_SESSION_RECOVERY_MS    60000
#define WS_EVENT_BUFFER_SIZE      8
#define WS_SEND_TIMEOUT_MS        10000
#define WS_OP_LOCK_TIMEOUT_MS     15000

// Bounds a single inbound event and matches the transport rx buffer, so anything
// we accept arrives as one unfragmented frame. It must exceed the largest frame
// we ourselves publish (a 4096-byte event inside an ["EVENT",<subid>,...]
// envelope), otherwise a peer's max-size sign request would arrive fragmented
// and be dropped.
#define WS_RX_BUFFER_SIZE     4608
#define WS_MAX_EVENT_JSON_LEN WS_RX_BUFFER_SIZE

#define WS_MAX_SUBSCRIPTION_ID  63
#define WS_SUBSCRIPTION_ID_SIZE (WS_MAX_SUBSCRIPTION_ID + 1)

typedef enum {
    COORDINATOR_STATE_IDLE,
    COORDINATOR_STATE_CONNECTING,
    COORDINATOR_STATE_CONNECTED,
    COORDINATOR_STATE_SUBSCRIBING,
    COORDINATOR_STATE_ACTIVE,
    COORDINATOR_STATE_RECONNECTING,
    COORDINATOR_STATE_ERROR
} coordinator_state_t;

typedef struct {
    uint32_t last_event_ms;
    bool healthy;
} ws_health_t;

typedef struct {
    uint8_t attempt_count;
    uint32_t next_retry_ms;
    uint32_t last_attempt_time;
    coordinator_state_t state_before_disconnect;
    bool had_subscription;
} ws_reconnect_t;

typedef struct {
    uint8_t relay_index;
    uint32_t success_count;
    uint32_t fail_count;
} relay_health_score_t;

typedef struct {
    coordinator_state_t state;
    uint8_t connected_relays;
    uint8_t total_relays;
    uint8_t reconnect_attempts;
    bool session_active;
    relay_health_score_t relay_scores[COORDINATOR_MAX_RELAYS];
} coordinator_status_t;

typedef void (*frost_sign_request_cb)(const frost_sign_request_t *request, void *ctx);
typedef void (*frost_sign_response_cb)(const frost_sign_response_t *response, void *ctx);
typedef void (*frost_dkg_round1_cb)(const frost_dkg_round1_t *round1, void *ctx);
typedef void (*frost_dkg_round2_cb)(const frost_dkg_round2_t *round2, void *ctx);
typedef void (*frost_nip46_request_cb)(const nip46_request_t *request, void *ctx);

typedef struct {
    frost_sign_request_cb on_sign_request;
    frost_sign_response_cb on_sign_response;
    frost_dkg_round1_cb on_dkg_round1;
    frost_dkg_round2_cb on_dkg_round2;
    frost_nip46_request_cb on_nip46_request;
    void *user_ctx;
} frost_coordinator_callbacks_t;

int frost_coordinator_init(const uint8_t privkey[32]);
void frost_coordinator_deinit(void);

coordinator_state_t frost_coordinator_get_state(void);

int frost_coordinator_add_relay(const char *url);
int frost_coordinator_connect(void);
int frost_coordinator_disconnect(void);

int frost_coordinator_set_group(const frost_group_t *group);
int frost_coordinator_subscribe(const char *subscription_id);
int frost_coordinator_unsubscribe(const char *subscription_id);

int frost_coordinator_publish_sign_request(const frost_sign_request_t *request);
int frost_coordinator_publish_sign_response(const frost_sign_response_t *response);
int frost_coordinator_publish_dkg_round1(const frost_dkg_round1_t *round1);
int frost_coordinator_publish_dkg_round2(const frost_dkg_round2_t *round2,
                                         const uint8_t *recipient_pubkey);

// Callbacks run on the transport thread. Install them, and set the group, before
// frost_coordinator_connect(); neither is re-read under lock during dispatch.
void frost_coordinator_set_callbacks(const frost_coordinator_callbacks_t *callbacks);

int frost_coordinator_poll(int timeout_ms);

int frost_coordinator_get_pubkey(uint8_t pubkey[32]);

int frost_coordinator_get_status(coordinator_status_t *status);
bool frost_coordinator_is_healthy(void);

#ifdef NATIVE_TEST
void frost_coordinator_test_set_time_ms(uint32_t now_ms);
#endif

#endif
