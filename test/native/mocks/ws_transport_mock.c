// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include "ws_transport_mock.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Exported by frost_coordinator.c under NATIVE_TEST. Calling into the transport
// while the coordinator holds its state lock is the deadlock this work fixed;
// assert on it at every entry point so no future edit can reintroduce it.
bool frost_coordinator_state_lock_held(void);

#define ASSERT_NO_STATE_LOCK() \
    assert(!frost_coordinator_state_lock_held() && "ws_transport call under state_mutex")

struct ws_transport {
    bool destroyed;
    bool started;
    int in_callback;
    ws_event_cb_t cb;
    void *user_ctx;
    ws_transport_config_t config;
    char url[160];
    char *sends[WS_MOCK_MAX_SENDS];
    int send_count;
    bool fire_on_destroy;
    ws_event_type_t on_destroy_event;
};

// Handles are never freed so a use-after-free stays observable instead of
// becoming undefined behaviour.
static struct ws_transport *g_handles[WS_MOCK_MAX_HANDLES];
static int g_create_count;
static int g_destroy_count;
static int g_fail_creates;
static int g_fail_starts;
static int g_fail_sends;
static bool g_use_after_free;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_idle = PTHREAD_COND_INITIALIZER;

static void lock(void) {
    pthread_mutex_lock(&g_lock);
}

static void unlock(void) {
    pthread_mutex_unlock(&g_lock);
}

void ws_mock_reset(void) {
    lock();
    for (int i = 0; i < g_create_count; i++) {
        for (int j = 0; j < g_handles[i]->send_count; j++)
            free(g_handles[i]->sends[j]);
        free(g_handles[i]);
        g_handles[i] = NULL;
    }
    g_create_count = 0;
    g_destroy_count = 0;
    g_fail_creates = 0;
    g_fail_starts = 0;
    g_fail_sends = 0;
    g_use_after_free = false;
    unlock();
}

void ws_mock_fail_next_creates(int count) {
    lock();
    g_fail_creates = count;
    unlock();
}

void ws_mock_fail_next_starts(int count) {
    lock();
    g_fail_starts = count;
    unlock();
}

void ws_mock_fire_on_destroy(ws_transport_handle_t h, ws_event_type_t type) {
    if (!h)
        return;
    lock();
    h->fire_on_destroy = true;
    h->on_destroy_event = type;
    unlock();
}

void ws_mock_fail_next_sends(int count) {
    lock();
    g_fail_sends = count;
    unlock();
}

ws_transport_handle_t ws_mock_handle(int index) {
    lock();
    ws_transport_handle_t h = NULL;
    if (index >= 0 && index < g_create_count && !g_handles[index]->destroyed)
        h = g_handles[index];
    unlock();
    return h;
}

int ws_mock_create_count(void) {
    lock();
    int n = g_create_count;
    unlock();
    return n;
}

int ws_mock_destroy_count(void) {
    lock();
    int n = g_destroy_count;
    unlock();
    return n;
}

int ws_mock_live_count(void) {
    lock();
    int n = 0;
    for (int i = 0; i < g_create_count; i++) {
        if (!g_handles[i]->destroyed)
            n++;
    }
    unlock();
    return n;
}

bool ws_mock_saw_use_after_free(void) {
    lock();
    bool v = g_use_after_free;
    unlock();
    return v;
}

const ws_transport_config_t *ws_mock_config(int index) {
    if (index < 0 || index >= ws_mock_create_count())
        return NULL;
    return &g_handles[index]->config;
}

// Delivers an event the way a transport thread would. A handle destroyed in the
// meantime simply stops delivering, matching the real client.
static void fire(ws_transport_handle_t h, ws_event_type_t type, const char *data, size_t len) {
    if (!h)
        return;
    lock();
    if (h->destroyed) {
        unlock();
        return;
    }
    h->in_callback++;
    unlock();

    ws_event_t event = {.type = type, .data = data, .len = len};
    h->cb(h->user_ctx, &event);

    lock();
    h->in_callback--;
    pthread_cond_broadcast(&g_idle);
    unlock();
}

void ws_mock_fire_connected(ws_transport_handle_t h) {
    fire(h, WS_EVT_CONNECTED, NULL, 0);
}

void ws_mock_fire_disconnected(ws_transport_handle_t h) {
    fire(h, WS_EVT_DISCONNECTED, NULL, 0);
}

void ws_mock_fire_error(ws_transport_handle_t h) {
    fire(h, WS_EVT_ERROR, NULL, 0);
}

void ws_mock_fire_data(ws_transport_handle_t h, const char *text) {
    fire(h, WS_EVT_DATA, text, strlen(text));
}

int ws_mock_send_count(ws_transport_handle_t h) {
    if (!h)
        return 0;
    lock();
    int n = h->send_count;
    unlock();
    return n;
}

const char *ws_mock_sent(ws_transport_handle_t h, int i) {
    if (!h)
        return NULL;
    lock();
    const char *s = (i >= 0 && i < h->send_count) ? h->sends[i] : NULL;
    unlock();
    return s;
}

/* ---- ws_transport.h implementation ---- */

ws_transport_handle_t ws_transport_create(const ws_transport_config_t *config, ws_event_cb_t cb,
                                          void *user_ctx) {
    ASSERT_NO_STATE_LOCK();
    if (!config || !config->url)
        return NULL;

    lock();
    if (g_create_count >= WS_MOCK_MAX_HANDLES || g_fail_creates > 0) {
        if (g_fail_creates > 0)
            g_fail_creates--;
        unlock();
        return NULL;
    }
    struct ws_transport *t = calloc(1, sizeof(*t));
    if (!t) {
        unlock();
        return NULL;
    }
    t->cb = cb;
    t->user_ctx = user_ctx;
    t->config = *config;
    snprintf(t->url, sizeof(t->url), "%s", config->url);
    t->config.url = t->url;
    g_handles[g_create_count++] = t;
    unlock();
    return t;
}

int ws_transport_start(ws_transport_handle_t handle) {
    ASSERT_NO_STATE_LOCK();
    if (!handle)
        return -1;
    lock();
    if (handle->destroyed) {
        g_use_after_free = true;
        unlock();
        return -1;
    }
    if (g_fail_starts > 0) {
        g_fail_starts--;
        unlock();
        return -1;
    }
    handle->started = true;
    unlock();
    return 0;
}

// Mirrors esp_websocket_client_stop/destroy: blocks until no event callback is
// in flight. If the caller held the coordinator's state lock, the callback
// waiting on that lock could never finish and this would hang forever.
void ws_transport_destroy(ws_transport_handle_t handle) {
    ASSERT_NO_STATE_LOCK();
    if (!handle)
        return;

    lock();
    if (handle->destroyed) {
        g_use_after_free = true;
        unlock();
        return;
    }
    bool pending = handle->fire_on_destroy;
    ws_event_type_t pending_event = handle->on_destroy_event;
    handle->fire_on_destroy = false;
    unlock();

    // The transport thread can still be delivering when teardown begins.
    if (pending) {
        ws_event_t event = {.type = pending_event, .data = NULL, .len = 0};
        handle->cb(handle->user_ctx, &event);
    }

    lock();
    handle->destroyed = true;
    while (handle->in_callback > 0)
        pthread_cond_wait(&g_idle, &g_lock);
    g_destroy_count++;
    unlock();
}

int ws_transport_send_text(ws_transport_handle_t handle, const char *data, size_t len,
                           uint32_t timeout_ms) {
    ASSERT_NO_STATE_LOCK();
    (void)timeout_ms;
    if (!handle)
        return -1;

    lock();
    if (handle->destroyed) {
        // Sending on a destroyed handle: in a real build this dereferences freed
        // memory. This is the use-after-free the op lock exists to prevent.
        g_use_after_free = true;
        unlock();
        return -1;
    }
    if (g_fail_sends > 0) {
        g_fail_sends--;
        unlock();
        return -1;
    }
    if (handle->send_count < WS_MOCK_MAX_SENDS) {
        char *copy = malloc(len + 1);
        if (copy) {
            memcpy(copy, data, len);
            copy[len] = '\0';
            handle->sends[handle->send_count++] = copy;
        }
    }
    unlock();
    return 0;
}
