#ifndef NOSTR_CLIENT_H
#define NOSTR_CLIENT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef void (*nostr_msg_cb)(const char *json, void *ctx);

typedef struct {
    void *ws_client;
    char relay_url[256];
    char sub_id[16];
    uint8_t privkey[32];
    uint8_t pubkey[32];
    nostr_msg_cb on_message;
    void *user_ctx;
    bool connected;
} nostr_client_t;

int nostr_client_init(nostr_client_t *client, const uint8_t *privkey);
int nostr_client_connect(nostr_client_t *client, const char *relay_url);
void nostr_client_disconnect(nostr_client_t *client);

int nostr_client_subscribe(nostr_client_t *client, const uint8_t *group_pubkey);
int nostr_client_unsubscribe(nostr_client_t *client);

int nostr_client_publish(nostr_client_t *client, const uint8_t *recipient_pubkey,
                         const char *content, bool encrypted);

void nostr_client_set_callback(nostr_client_t *client, nostr_msg_cb cb, void *ctx);

#endif
