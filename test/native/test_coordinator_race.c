// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

// Concurrency test for frost_coordinator. The use-after-free this exercises is
// only reachable when publish_event() sends on a handle that poll() is tearing
// down, so it needs real threads. Built with ThreadSanitizer when available.
//
// Threads mirror production: a caller thread publishing, an application thread
// polling, and a transport thread delivering connect/disconnect/data events.

#include "frost_coordinator.h"
#include "mocks/ws_transport_mock.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define ITERATIONS 4000

static atomic_bool g_stop;
static atomic_uint g_clock;

static void *publisher_thread(void *arg) {
    (void)arg;
    frost_sign_request_t req;
    memset(&req, 0, sizeof(req));
    while (!atomic_load(&g_stop))
        frost_coordinator_publish_sign_request(&req);
    return NULL;
}

static void *poller_thread(void *arg) {
    (void)arg;
    while (!atomic_load(&g_stop)) {
        // Advance the clock so reconnect backoffs elapse and poll tears handles down.
        frost_coordinator_test_set_time_ms(atomic_fetch_add(&g_clock, 250) + 250);
        frost_coordinator_poll(0);
    }
    return NULL;
}

// Stands in for the websocket client task: flaps the connection continuously.
static void *transport_thread(void *arg) {
    (void)arg;
    while (!atomic_load(&g_stop)) {
        for (int i = 0; i < ws_mock_create_count(); i++) {
            ws_transport_handle_t h = ws_mock_handle(i);
            if (!h)
                continue;
            ws_mock_fire_connected(h);
            ws_mock_fire_data(h, "[\"EVENT\",\"race\",{\"kind\":21104,\"content\":\"x\"}]");
            ws_mock_fire_disconnected(h);
        }
    }
    return NULL;
}

int main(void) {
    printf("Coordinator concurrency (publish vs reconnect teardown)\n\n");

    ws_mock_reset();
    atomic_store(&g_stop, false);
    atomic_store(&g_clock, 1);
    frost_coordinator_test_set_time_ms(1);

    uint8_t privkey[32];
    memset(privkey, 0xAB, sizeof(privkey));
    if (frost_coordinator_init(privkey) != 0)
        return 1;

    frost_group_t group;
    memset(&group, 0, sizeof(group));
    group.threshold = 2;
    group.participant_count = 3;
    frost_coordinator_set_group(&group);

    frost_coordinator_add_relay("wss://a.example");
    frost_coordinator_add_relay("wss://b.example");
    frost_coordinator_connect();
    frost_coordinator_subscribe("race");

    pthread_t pub, poll_t, transport;
    pthread_create(&pub, NULL, publisher_thread, NULL);
    pthread_create(&poll_t, NULL, poller_thread, NULL);
    pthread_create(&transport, NULL, transport_thread, NULL);

    for (int i = 0; i < ITERATIONS; i++) {
        coordinator_status_t status;
        frost_coordinator_get_status(&status);
        frost_coordinator_is_healthy();
    }

    atomic_store(&g_stop, true);
    pthread_join(pub, NULL);
    pthread_join(poll_t, NULL);
    pthread_join(transport, NULL);

    bool uaf = ws_mock_saw_use_after_free();
    frost_coordinator_deinit();

    printf("  handles created: %d, destroyed: %d, leaked: %d\n", ws_mock_create_count(),
           ws_mock_destroy_count(), ws_mock_live_count());

    if (uaf) {
        printf("  use-after-free: DETECTED\n\n=== FAILED ===\n");
        return 1;
    }
    if (ws_mock_live_count() != 0) {
        printf("  leaked live transports\n\n=== FAILED ===\n");
        return 1;
    }
    printf(
        "  use-after-free: none\n  no deadlock, no double-destroy\n\n=== All tests passed ===\n");
    return 0;
}
