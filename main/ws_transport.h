// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#ifndef WS_TRANSPORT_H
#define WS_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

typedef struct ws_transport *ws_transport_handle_t;

typedef enum { WS_EVT_CONNECTED, WS_EVT_DISCONNECTED, WS_EVT_DATA, WS_EVT_ERROR } ws_event_type_t;

typedef struct {
    ws_event_type_t type;
    const char *data;
    size_t len;
} ws_event_t;

// Invoked on the transport's own thread. Must not call ws_transport_destroy().
typedef void (*ws_event_cb_t)(void *user_ctx, const ws_event_t *event);

typedef struct {
    const char *url;
    uint32_t ping_interval_sec;
    uint32_t pong_timeout_sec;
    size_t rx_buffer_size;
    uint32_t network_timeout_ms;
} ws_transport_config_t;

// Creates a stopped transport. Register callbacks before ws_transport_start().
ws_transport_handle_t ws_transport_create(const ws_transport_config_t *config, ws_event_cb_t cb,
                                          void *user_ctx);

int ws_transport_start(ws_transport_handle_t handle);

// Stops the transport thread and frees the handle. Blocks until no callback is
// in flight, so callers must not hold any lock the callback also takes.
void ws_transport_destroy(ws_transport_handle_t handle);

int ws_transport_send_text(ws_transport_handle_t handle, const char *data, size_t len,
                           uint32_t timeout_ms);

#endif
