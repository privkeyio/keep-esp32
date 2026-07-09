// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

// Drives the real frost_coordinator state machine against a mock websocket
// transport. Covers the acceptance criteria of the health/reconnect work plus
// the concurrency defects found in review (use-after-free on reconnect,
// dropped replays, double-counted failures).

#include "frost_coordinator.h"
#include "mocks/nostr_frost_stubs.h"
#include "mocks/ws_transport_mock.h"

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name)                 \
    do {                           \
        printf("  %s... ", #name); \
        fflush(stdout);            \
        tests_run++;               \
        if (test_##name()) {       \
            printf("PASS\n");      \
            tests_passed++;        \
        } else {                   \
            printf("FAIL\n");      \
        }                          \
    } while (0)

#define CHECK(cond)                                            \
    do {                                                       \
        if (!(cond)) {                                         \
            printf("[%s:%d: %s] ", __func__, __LINE__, #cond); \
            return false;                                      \
        }                                                      \
    } while (0)

static uint32_t g_now;

static void at(uint32_t ms) {
    g_now = ms;
    frost_coordinator_test_set_time_ms(ms);
}

static void setup(void) {
    // A test that returns early on a failed CHECK never runs teardown; reset
    // here so one failure does not cascade into every later test.
    frost_coordinator_deinit();
    ws_mock_reset();
    ns_stub_reset();
    at(1);

    uint8_t privkey[32];
    memset(privkey, 0xAB, sizeof(privkey));
    assert(frost_coordinator_init(privkey) == 0);

    frost_group_t group;
    memset(&group, 0, sizeof(group));
    group.threshold = 2;
    group.participant_count = 3;
    assert(frost_coordinator_set_group(&group) == 0);
}

static void teardown(void) {
    frost_coordinator_deinit();
}

// Brings one relay to CONNECTED and returns its handle.
static ws_transport_handle_t connect_one(const char *url) {
    assert(frost_coordinator_add_relay(url) == 0);
    assert(frost_coordinator_connect() == 0);
    ws_transport_handle_t h = ws_mock_handle(0);
    assert(h != NULL);
    ws_mock_fire_connected(h);
    return h;
}

static bool test_rejects_plaintext_and_overlong_urls(void) {
    setup();
    CHECK(frost_coordinator_add_relay("ws://relay.example") == -3);
    CHECK(frost_coordinator_add_relay("http://relay.example") == -3);
    CHECK(frost_coordinator_add_relay(NULL) == -1);

    char long_url[RELAY_URL_LEN + 16];
    memset(long_url, 'a', sizeof(long_url));
    memcpy(long_url, "wss://", 6);
    long_url[sizeof(long_url) - 1] = '\0';
    CHECK(frost_coordinator_add_relay(long_url) == -4);

    CHECK(frost_coordinator_add_relay("wss://relay.example") == 0);
    teardown();
    return true;
}

static bool test_subscription_id_bounds(void) {
    setup();
    connect_one("wss://a.example");

    char id[WS_MAX_SUBSCRIPTION_ID + 2];
    memset(id, 'x', sizeof(id));

    id[WS_MAX_SUBSCRIPTION_ID] = '\0'; /* exactly 63 chars: allowed */
    CHECK(frost_coordinator_subscribe(id) == 0);

    id[WS_MAX_SUBSCRIPTION_ID] = 'x';
    id[WS_MAX_SUBSCRIPTION_ID + 1] = '\0'; /* 64 chars: rejected, never truncated */
    CHECK(frost_coordinator_subscribe(id) == -2);

    CHECK(frost_coordinator_subscribe("bad\"quote") == -2);
    CHECK(frost_coordinator_subscribe("bad\nnewline") == -2);
    CHECK(frost_coordinator_subscribe("") == -2);
    teardown();
    return true;
}

static bool test_keepalive_is_delegated_to_transport(void) {
    setup();
    connect_one("wss://a.example");

    const ws_transport_config_t *cfg = ws_mock_config(0);
    CHECK(cfg != NULL);
    CHECK(cfg->ping_interval_sec == WS_PING_INTERVAL_SEC);
    CHECK(cfg->pong_timeout_sec == WS_PONG_TIMEOUT_SEC);
    CHECK(cfg->rx_buffer_size == WS_RX_BUFFER_SIZE);

    // The coordinator must not hand-roll pings on the wire.
    frost_coordinator_poll(0);
    at(g_now + WS_PING_INTERVAL_SEC * 1000 + 1);
    frost_coordinator_poll(0);
    CHECK(ws_mock_send_count(ws_mock_handle(0)) == 0);
    teardown();
    return true;
}

static bool test_connected_relay_reports_healthy(void) {
    setup();
    connect_one("wss://a.example");
    CHECK(frost_coordinator_is_healthy());

    coordinator_status_t status;
    CHECK(frost_coordinator_get_status(&status) == 0);
    CHECK(status.total_relays == 1);
    CHECK(status.connected_relays == 1);
    CHECK(status.relay_scores[0].success_count == 1);
    CHECK(status.relay_scores[0].fail_count == 0);

    ws_mock_fire_disconnected(ws_mock_handle(0));
    CHECK(!frost_coordinator_is_healthy());
    teardown();
    return true;
}

static bool test_exponential_backoff_schedule(void) {
    setup();
    ws_transport_handle_t h = connect_one("wss://a.example");

    at(1000);
    ws_mock_fire_disconnected(h);

    // Retry waits are 1s, 2s, 4s, 8s, 16s. Nothing fires early.
    const uint32_t waits[] = {1000, 2000, 4000, 8000, 16000};
    uint32_t t = 1000;
    for (int i = 0; i < 5; i++) {
        at(t + waits[i] - 1);
        frost_coordinator_poll(0);
        CHECK(ws_mock_create_count() == i + 1);

        at(t + waits[i]);
        frost_coordinator_poll(0);
        CHECK(ws_mock_create_count() == i + 2);

        t += waits[i];
        ws_mock_fire_error(ws_mock_handle(i + 1));
    }

    CHECK(!ws_mock_saw_use_after_free());
    teardown();
    return true;
}

static bool test_gives_up_after_max_attempts(void) {
    setup();
    ws_transport_handle_t h = connect_one("wss://a.example");

    at(1000);
    ws_mock_fire_disconnected(h);

    const uint32_t waits[] = {1000, 2000, 4000, 8000, 16000};
    uint32_t t = 1000;
    for (int i = 0; i < 5; i++) {
        t += waits[i];
        at(t);
        frost_coordinator_poll(0);
        ws_mock_fire_error(ws_mock_handle(i + 1));
    }

    CHECK(ws_mock_create_count() == 1 + WS_RECONNECT_MAX_ATTEMPTS);

    // Sixth attempt never happens; the relay is parked in ERROR.
    at(t + 1);
    frost_coordinator_poll(0);
    CHECK(ws_mock_create_count() == 1 + WS_RECONNECT_MAX_ATTEMPTS);

    // Giving up must not strand the last transport: it is destroyed, not leaked.
    CHECK(ws_mock_live_count() == 0);
    CHECK(ws_mock_destroy_count() == 1 + WS_RECONNECT_MAX_ATTEMPTS);
    CHECK(!ws_mock_saw_use_after_free());
    teardown();
    return true;
}

static bool test_session_recovery_timeout_fails_session(void) {
    setup();
    ws_transport_handle_t h = connect_one("wss://a.example");
    CHECK(frost_coordinator_subscribe("sub1") == 0);

    at(1000);
    ws_mock_fire_disconnected(h);

    at(1000 + WS_SESSION_RECOVERY_MS);
    CHECK(frost_coordinator_poll(0) >= 0);
    CHECK(frost_coordinator_get_state() != COORDINATOR_STATE_ERROR);

    at(1000 + WS_SESSION_RECOVERY_MS + 1);
    CHECK(frost_coordinator_poll(0) == -1);
    CHECK(frost_coordinator_get_state() == COORDINATOR_STATE_ERROR);
    teardown();
    return true;
}

// A disconnect at uptime 0 must still arm the recovery timer.
static bool test_session_timeout_armed_at_time_zero(void) {
    setup();
    ws_transport_handle_t h = connect_one("wss://a.example");

    at(0);
    ws_mock_fire_disconnected(h);

    at(WS_SESSION_RECOVERY_MS + 1);
    CHECK(frost_coordinator_poll(0) == -1);
    CHECK(frost_coordinator_get_state() == COORDINATOR_STATE_ERROR);
    teardown();
    return true;
}

static bool test_buffers_and_replays_in_order(void) {
    setup();
    ws_transport_handle_t h = connect_one("wss://a.example");

    at(1000);
    ws_mock_fire_disconnected(h);

    frost_sign_request_t req;
    memset(&req, 0, sizeof(req));
    for (int i = 0; i < 3; i++)
        CHECK(frost_coordinator_publish_sign_request(&req) == 0);

    // Nothing reached the old handle.
    CHECK(ws_mock_send_count(ws_mock_handle(0)) == 0);

    at(2000);
    frost_coordinator_poll(0);
    ws_transport_handle_t h1 = ws_mock_handle(1);
    CHECK(h1 != NULL);
    ws_mock_fire_connected(h1);

    at(2100);
    frost_coordinator_poll(0);

    CHECK(ws_mock_send_count(h1) == 3);
    for (int i = 0; i < 3; i++)
        CHECK(strstr(ws_mock_sent(h1, i), "\"EVENT\"") != NULL);
    CHECK(!ws_mock_saw_use_after_free());
    teardown();
    return true;
}

static bool test_buffer_overwrites_oldest(void) {
    setup();
    ws_transport_handle_t h = connect_one("wss://a.example");
    at(1000);
    ws_mock_fire_disconnected(h);

    frost_sign_request_t req;
    memset(&req, 0, sizeof(req));
    for (int i = 0; i < WS_EVENT_BUFFER_SIZE + 4; i++)
        CHECK(frost_coordinator_publish_sign_request(&req) == 0);

    at(2000);
    frost_coordinator_poll(0);
    ws_transport_handle_t h1 = ws_mock_handle(1);
    ws_mock_fire_connected(h1);
    at(2100);
    frost_coordinator_poll(0);

    CHECK(ws_mock_send_count(h1) == WS_EVENT_BUFFER_SIZE);
    teardown();
    return true;
}

// A replay that fails to send must stay buffered, not vanish.
static bool test_failed_replay_is_requeued(void) {
    setup();
    ws_transport_handle_t h = connect_one("wss://a.example");
    at(1000);
    ws_mock_fire_disconnected(h);

    frost_sign_request_t req;
    memset(&req, 0, sizeof(req));
    CHECK(frost_coordinator_publish_sign_request(&req) == 0);

    at(2000);
    frost_coordinator_poll(0);
    ws_transport_handle_t h1 = ws_mock_handle(1);
    ws_mock_fire_connected(h1);

    ws_mock_fail_next_sends(1);
    at(2100);
    frost_coordinator_poll(0);
    CHECK(ws_mock_send_count(h1) == 0);

    // Still buffered: the next poll delivers it.
    at(2200);
    frost_coordinator_poll(0);
    CHECK(ws_mock_send_count(h1) == 1);
    teardown();
    return true;
}

static bool test_resubscribes_after_reconnect(void) {
    setup();
    ws_transport_handle_t h = connect_one("wss://a.example");
    CHECK(frost_coordinator_subscribe("sub1") == 0);
    CHECK(ws_mock_send_count(h) == 1);
    CHECK(strstr(ws_mock_sent(h, 0), "\"REQ\"") != NULL);

    at(1000);
    ws_mock_fire_disconnected(h);
    at(2000);
    frost_coordinator_poll(0);

    ws_transport_handle_t h1 = ws_mock_handle(1);
    CHECK(h1 != NULL);
    ws_mock_fire_connected(h1);

    at(2100);
    frost_coordinator_poll(0);

    CHECK(ws_mock_send_count(h1) == 1);
    CHECK(strstr(ws_mock_sent(h1, 0), "\"REQ\"") != NULL);
    CHECK(strstr(ws_mock_sent(h1, 0), "sub1") != NULL);
    teardown();
    return true;
}

// A resubscribe whose REQ fails to send must be retried, not silently dropped.
static bool test_failed_resubscribe_is_retried(void) {
    setup();
    ws_transport_handle_t h = connect_one("wss://a.example");
    CHECK(frost_coordinator_subscribe("sub1") == 0);

    at(1000);
    ws_mock_fire_disconnected(h);
    at(2000);
    frost_coordinator_poll(0);

    ws_transport_handle_t h1 = ws_mock_handle(1);
    CHECK(h1 != NULL);
    ws_mock_fire_connected(h1);

    ws_mock_fail_next_sends(1);
    at(2100);
    frost_coordinator_poll(0);
    CHECK(ws_mock_send_count(h1) == 0);

    at(2200);
    frost_coordinator_poll(0);
    CHECK(ws_mock_send_count(h1) == 1);
    CHECK(strstr(ws_mock_sent(h1, 0), "\"REQ\"") != NULL);
    teardown();
    return true;
}

// ERROR and DISCONNECTED both fire for one failure; it must count once.
static bool test_failure_counted_once(void) {
    setup();
    ws_transport_handle_t h = connect_one("wss://a.example");

    at(1000);
    ws_mock_fire_error(h);
    ws_mock_fire_disconnected(h);

    coordinator_status_t status;
    CHECK(frost_coordinator_get_status(&status) == 0);
    CHECK(status.relay_scores[0].fail_count == 1);
    teardown();
    return true;
}

// Reconnect destroys the stale handle; nothing may touch it afterwards.
static bool test_reconnect_has_no_use_after_free(void) {
    setup();
    ws_transport_handle_t h = connect_one("wss://a.example");
    CHECK(frost_coordinator_subscribe("sub1") == 0);

    at(1000);
    ws_mock_fire_disconnected(h);

    frost_sign_request_t req;
    memset(&req, 0, sizeof(req));
    CHECK(frost_coordinator_publish_sign_request(&req) == 0);

    at(2000);
    frost_coordinator_poll(0);
    CHECK(ws_mock_destroy_count() == 1);
    CHECK(ws_mock_handle(0) == NULL);

    ws_transport_handle_t h1 = ws_mock_handle(1);
    ws_mock_fire_connected(h1);
    at(2100);
    frost_coordinator_poll(0);

    // Publishing after teardown of the old handle targets only the live one.
    CHECK(frost_coordinator_publish_sign_request(&req) >= 0);
    CHECK(!ws_mock_saw_use_after_free());

    teardown();
    CHECK(ws_mock_live_count() == 0);
    CHECK(!ws_mock_saw_use_after_free());
    return true;
}

static int g_sign_requests_seen;

static void on_sign_request(const frost_sign_request_t *request, void *ctx) {
    (void)request;
    (void)ctx;
    g_sign_requests_seen++;
}

static bool test_inbound_event_dispatches_callback(void) {
    setup();
    ws_transport_handle_t h = connect_one("wss://a.example");
    CHECK(frost_coordinator_subscribe("sub1") == 0);

    g_sign_requests_seen = 0;
    frost_coordinator_callbacks_t cbs;
    memset(&cbs, 0, sizeof(cbs));
    cbs.on_sign_request = on_sign_request;
    frost_coordinator_set_callbacks(&cbs);

    ws_mock_fire_data(h, "[\"EVENT\",\"sub1\",{\"kind\":21104,\"content\":\"x\"}]");
    CHECK(ns_stub_counts.parse_sign_request == 1);
    CHECK(g_sign_requests_seen == 1);

    // Wrong kind: no sign-request callback.
    ws_mock_fire_data(h, "[\"EVENT\",\"sub1\",{\"kind\":21105,\"content\":\"x\"}]");
    CHECK(g_sign_requests_seen == 1);

    // Malformed and non-EVENT frames are ignored without crashing or dispatching.
    ws_mock_fire_data(h, "not json");
    ws_mock_fire_data(h, "[\"NOTICE\",\"hi\"]");
    ws_mock_fire_data(h, "[\"EVENT\",\"sub1\"]");
    ws_mock_fire_data(h, "[\"EVENT\",\"sub1\",{\"no_kind\":1}]");
    ws_mock_fire_data(h, "[]");
    CHECK(g_sign_requests_seen == 1);

    // A relay is untrusted: an event tagged with a subscription we never opened
    // must never reach a callback.
    ws_mock_fire_data(h, "[\"EVENT\",\"other\",{\"kind\":21104,\"content\":\"x\"}]");
    ws_mock_fire_data(h, "[\"EVENT\",42,{\"kind\":21104,\"content\":\"x\"}]");
    CHECK(g_sign_requests_seen == 1);
    CHECK(!ws_mock_saw_use_after_free());
    teardown();
    return true;
}

static bool test_disconnect_destroys_all_handles(void) {
    setup();
    CHECK(frost_coordinator_add_relay("wss://a.example") == 0);
    CHECK(frost_coordinator_add_relay("wss://b.example") == 0);
    CHECK(frost_coordinator_connect() == 0);
    CHECK(ws_mock_create_count() == 2);

    ws_mock_fire_connected(ws_mock_handle(0));
    ws_mock_fire_connected(ws_mock_handle(1));

    CHECK(frost_coordinator_disconnect() == 0);
    CHECK(ws_mock_destroy_count() == 2);
    CHECK(ws_mock_live_count() == 0);
    CHECK(frost_coordinator_get_state() == COORDINATOR_STATE_IDLE);
    CHECK(!ws_mock_saw_use_after_free());
    teardown();
    return true;
}

static bool test_failed_create_schedules_retry(void) {
    setup();
    CHECK(frost_coordinator_add_relay("wss://a.example") == 0);
    ws_mock_fail_next_creates(1);
    CHECK(frost_coordinator_connect() == 0);
    CHECK(ws_mock_create_count() == 0);

    // Transport creation failed, so the relay must be queued for retry.
    at(1 + 1000);
    frost_coordinator_poll(0);
    CHECK(ws_mock_create_count() == 1);
    teardown();
    return true;
}

// A transport that is created but fails to start must be destroyed, not leaked.
static bool test_failed_start_cleans_up_and_retries(void) {
    setup();
    CHECK(frost_coordinator_add_relay("wss://a.example") == 0);
    ws_mock_fail_next_starts(1);
    CHECK(frost_coordinator_connect() == 0);
    CHECK(ws_mock_create_count() == 1);
    CHECK(ws_mock_destroy_count() == 1);
    CHECK(ws_mock_live_count() == 0);

    at(1 + 1000);
    frost_coordinator_poll(0);
    CHECK(ws_mock_create_count() == 2);
    CHECK(!ws_mock_saw_use_after_free());
    teardown();
    return true;
}

// An event still in flight when a stale transport is torn down must not mutate
// the relay we have already detached it from.
static bool test_detached_transport_event_ignored(void) {
    setup();
    ws_transport_handle_t h = connect_one("wss://a.example");

    at(1000);
    ws_mock_fire_disconnected(h);

    coordinator_status_t status;
    CHECK(frost_coordinator_get_status(&status) == 0);
    CHECK(status.relay_scores[0].fail_count == 1);

    // The doomed transport delivers one last DISCONNECTED during destroy().
    ws_mock_fire_on_destroy(h, WS_EVT_DISCONNECTED);
    at(2000);
    frost_coordinator_poll(0);

    CHECK(frost_coordinator_get_status(&status) == 0);
    CHECK(status.relay_scores[0].fail_count == 1);
    CHECK(!ws_mock_saw_use_after_free());
    teardown();
    return true;
}

// Every connected send failing must buffer the event, not drop it.
static bool test_publish_buffers_when_all_sends_fail(void) {
    setup();
    ws_transport_handle_t h = connect_one("wss://a.example");

    frost_sign_request_t req;
    memset(&req, 0, sizeof(req));
    ws_mock_fail_next_sends(1);
    CHECK(frost_coordinator_publish_sign_request(&req) == 0);
    CHECK(ws_mock_send_count(h) == 0);

    at(100);
    frost_coordinator_poll(0);
    CHECK(ws_mock_send_count(h) == 1);
    CHECK(strstr(ws_mock_sent(h, 0), "\"EVENT\"") != NULL);
    teardown();
    return true;
}

// A REQ that fails during the initial subscribe must be retried by poll().
static bool test_failed_initial_subscribe_is_retried(void) {
    setup();
    ws_transport_handle_t h = connect_one("wss://a.example");

    ws_mock_fail_next_sends(1);
    CHECK(frost_coordinator_subscribe("sub1") == 0);
    CHECK(ws_mock_send_count(h) == 0);

    at(100);
    frost_coordinator_poll(0);
    CHECK(ws_mock_send_count(h) == 1);
    CHECK(strstr(ws_mock_sent(h, 0), "\"REQ\"") != NULL);
    teardown();
    return true;
}

// Replay must not let a later event overtake one that failed to send.
static bool test_replay_stops_at_first_failure(void) {
    setup();
    ws_transport_handle_t h = connect_one("wss://a.example");
    at(1000);
    ws_mock_fire_disconnected(h);

    frost_sign_request_t req;
    memset(&req, 0, sizeof(req));
    CHECK(frost_coordinator_publish_sign_request(&req) == 0);
    CHECK(frost_coordinator_publish_sign_request(&req) == 0);

    at(2000);
    frost_coordinator_poll(0);
    ws_transport_handle_t h1 = ws_mock_handle(1);
    CHECK(h1 != NULL);
    ws_mock_fire_connected(h1);

    // First replay fails: the second must stay queued behind it.
    ws_mock_fail_next_sends(1);
    at(2100);
    frost_coordinator_poll(0);
    CHECK(ws_mock_send_count(h1) == 0);

    at(2200);
    frost_coordinator_poll(0);
    CHECK(ws_mock_send_count(h1) == 2);
    teardown();
    return true;
}

int main(void) {
    printf("Coordinator WebSocket Health & Reconnection\n\n");

    printf("Input validation:\n");
    TEST(rejects_plaintext_and_overlong_urls);
    TEST(subscription_id_bounds);

    printf("\nHealth monitoring:\n");
    TEST(keepalive_is_delegated_to_transport);
    TEST(connected_relay_reports_healthy);
    TEST(failure_counted_once);

    printf("\nReconnection:\n");
    TEST(exponential_backoff_schedule);
    TEST(gives_up_after_max_attempts);
    TEST(failed_create_schedules_retry);
    TEST(failed_start_cleans_up_and_retries);
    TEST(resubscribes_after_reconnect);
    TEST(failed_resubscribe_is_retried);
    TEST(failed_initial_subscribe_is_retried);
    TEST(detached_transport_event_ignored);

    printf("\nSession recovery:\n");
    TEST(session_recovery_timeout_fails_session);
    TEST(session_timeout_armed_at_time_zero);

    printf("\nEvent buffering:\n");
    TEST(buffers_and_replays_in_order);
    TEST(buffer_overwrites_oldest);
    TEST(failed_replay_is_requeued);
    TEST(replay_stops_at_first_failure);
    TEST(publish_buffers_when_all_sends_fail);

    printf("\nMemory safety:\n");
    TEST(reconnect_has_no_use_after_free);
    TEST(disconnect_destroys_all_handles);
    TEST(inbound_event_dispatches_callback);

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    if (tests_passed != tests_run) {
        printf("=== FAILURES ===\n");
        return 1;
    }
    printf("=== All tests passed ===\n");
    return 0;
}
