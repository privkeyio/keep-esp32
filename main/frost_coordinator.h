#ifndef FROST_COORDINATOR_H
#define FROST_COORDINATOR_H

#include "nostr_frost.h"
#include <stdint.h>
#include <stdbool.h>

#define COORDINATOR_MAX_RELAYS 4
#define COORDINATOR_MAX_GROUPS 4
#define COORDINATOR_TIMEOUT_MS 30000

typedef enum {
    COORDINATOR_STATE_IDLE,
    COORDINATOR_STATE_CONNECTING,
    COORDINATOR_STATE_CONNECTED,
    COORDINATOR_STATE_SUBSCRIBING,
    COORDINATOR_STATE_ACTIVE,
    COORDINATOR_STATE_ERROR
} coordinator_state_t;

typedef void (*frost_sign_request_cb)(const frost_sign_request_t *request, void *ctx);
typedef void (*frost_sign_response_cb)(const frost_sign_response_t *response, void *ctx);
typedef void (*frost_dkg_round1_cb)(const frost_dkg_round1_t *round1, void *ctx);

typedef struct {
    frost_sign_request_cb on_sign_request;
    frost_sign_response_cb on_sign_response;
    frost_dkg_round1_cb on_dkg_round1;
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

void frost_coordinator_set_callbacks(const frost_coordinator_callbacks_t *callbacks);

int frost_coordinator_poll(int timeout_ms);

int frost_coordinator_get_pubkey(uint8_t pubkey[32]);

#endif
