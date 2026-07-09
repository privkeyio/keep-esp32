// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#ifndef WS_TRANSPORT_MOCK_H
#define WS_TRANSPORT_MOCK_H

#include "ws_transport.h"
#include <stdbool.h>

#define WS_MOCK_MAX_HANDLES 32
#define WS_MOCK_MAX_SENDS   64

void ws_mock_reset(void);

// Fail the next `count` ws_transport_create/start calls.
void ws_mock_fail_next_starts(int count);

// Live handle for the relay created at `index` (creation order), or NULL if it
// has since been destroyed.
ws_transport_handle_t ws_mock_handle(int index);
int ws_mock_live_count(void);
int ws_mock_create_count(void);
int ws_mock_destroy_count(void);

// Drive coordinator callbacks the way a real transport thread would.
void ws_mock_fire_connected(ws_transport_handle_t h);
void ws_mock_fire_disconnected(ws_transport_handle_t h);
void ws_mock_fire_error(ws_transport_handle_t h);
void ws_mock_fire_data(ws_transport_handle_t h, const char *text);

// Everything sent on `h` since the last reset.
int ws_mock_send_count(ws_transport_handle_t h);
const char *ws_mock_sent(ws_transport_handle_t h, int i);

// Make the next `count` sends on any handle fail.
void ws_mock_fail_next_sends(int count);

// Set when a send or event targets a destroyed handle: a use-after-free that a
// real build would turn into a crash.
bool ws_mock_saw_use_after_free(void);

// Config the coordinator passed to ws_transport_create for handle `index`.
const ws_transport_config_t *ws_mock_config(int index);

#endif
