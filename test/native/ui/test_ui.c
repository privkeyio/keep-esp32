// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include "ui_harness.h"
#include "ux_display.h"
#include "ux_interface.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static int failures = 0;
static const char *shot_dir = NULL;

#define TEST(name) printf("  TEST: %s\n", name)
#define CHECK(cond, msg)                   \
    do {                                   \
        if (!(cond)) {                     \
            printf("    FAIL: %s\n", msg); \
            failures++;                    \
            abandon_call();                \
            return;                        \
        }                                  \
    } while (0)
#define PASS() printf("    PASS\n")

#define PIN_TIMEOUT_MS 120000

static ui_call_t *active_call = NULL;

/* Lets a prompt that was never answered time out, so a failed check cannot leave a
 * thread waiting on the shared decision semaphore, and a missed tap fails instead of
 * hanging the run. */
static bool drain_call(ui_call_t *call) {
    for (int i = 0; i < 3 && !ui_settle(ui_call_done, call); i++) {
        ui_run(PIN_TIMEOUT_MS + 1000);
    }
    if (!ui_call_done(call)) {
        printf("    FAIL: a prompt never returned\n");
        exit(1);
    }
    return (intptr_t)ui_call_join(call) != 0;
}

static void abandon_call(void) {
    if (active_call) {
        drain_call(active_call);
        active_call = NULL;
    }
}

static void shot(const char *name) {
    if (!shot_dir) {
        return;
    }
    char path[512];
    snprintf(path, sizeof(path), "%s/%s.png", shot_dir, name);
    ui_screenshot(path);
}

static const uint8_t WARDEN_KEY[32] = {
    0xc9, 0x38, 0xa3, 0x5e, 0x72, 0xc2, 0xf9, 0x49, 0xaf, 0xc3, 0x18, 0xde, 0x6f, 0x13, 0x59, 0xf7,
    0xc4, 0x9b, 0x5f, 0xe3, 0x2a, 0x45, 0x0b, 0x9d, 0xa4, 0x45, 0x65, 0x12, 0xbc, 0x22, 0x10, 0x18};

static void *confirm_pin(void *arg) {
    (void)arg;
    return (void *)(intptr_t)ux_confirm_warden_pin(WARDEN_KEY, PIN_TIMEOUT_MS);
}

static bool in_state(void *state) {
    return ui_get_state() == *(ui_state_t *)state;
}

static bool settle_state(ui_state_t state) {
    return ui_settle(in_state, &state);
}

static bool finish(ui_call_t *call) {
    if (!ui_settle(ui_call_done, call)) {
        printf("    FAIL: the prompt did not answer\n");
        failures++;
    }
    bool approved = drain_call(call);
    active_call = NULL;
    ui_run(50);
    return approved;
}

static ui_call_t *start_prompt(void) {
    ux_get_backend()->show_idle("keep", false, 1);
    ui_run(1000);
    active_call = ui_call_start(confirm_pin, NULL);
    if (!settle_state(UI_STATE_CONFIRM_PIN) || !ui_settle(ui_sem_waiting, NULL)) {
        abandon_call();
        return NULL;
    }
    return active_call;
}

static void test_reject_shows_result_until_ok(void) {
    TEST("Reject shows why the policy was refused, until OK is tapped");
    ui_call_t *call = start_prompt();
    CHECK(call, "the prompt did not appear");
    ui_run(1000);
    shot("01_prompt");
    CHECK(ui_tap_text("Reject"), "no Reject button");
    CHECK(!finish(call), "a rejected key was trusted");
    CHECK(ui_get_state() == UI_STATE_ERROR && ui_has_text("Key rejected"),
          "Reject did not say the key was rejected");
    ui_run(1000);
    shot("02_rejected");
    ui_run(30000);
    CHECK(ui_get_state() == UI_STATE_ERROR, "the result vanished without being acknowledged");
    CHECK(ui_tap_text("OK"), "no OK button");
    CHECK(ui_get_state() == UI_STATE_IDLE && ui_has_text("No policy"),
          "OK did not return to the home screen");
    PASS();
}

static void test_bounce_cannot_skip_result(void) {
    TEST("a second contact right after Reject cannot dismiss the result unseen");
    ui_call_t *call = start_prompt();
    CHECK(call, "the prompt did not appear");
    ui_run(1000);
    int x, y;
    CHECK(ui_find_text("Reject", &x, &y), "no Reject button");
    ui_tap(x, y);
    finish(call);
    ui_tap(x, y);
    ui_run(100);
    CHECK(ui_get_state() == UI_STATE_ERROR, "the bounce dismissed the result");
    ui_run(1000);
    CHECK(ui_tap_text("OK") && ui_get_state() == UI_STATE_IDLE,
          "a deliberate tap after the guard did not dismiss");
    PASS();
}

static void test_early_tap_cannot_trust(void) {
    TEST("a tap landing as the prompt appears cannot trust the key");
    ui_call_t *call = start_prompt();
    CHECK(call, "the prompt did not appear");
    int x, y;
    CHECK(ui_find_text("Trust", &x, &y), "no Trust button");
    ui_tap(x, y);
    ui_run(100);
    CHECK(!ui_call_done(call), "a tap during the guard trusted the key");
    ui_press(x, y);
    ui_run(1000);
    ui_release();
    ui_run(100);
    CHECK(!ui_call_done(call), "a press begun during the guard and released later trusted the key");
    ui_tap(x, y);
    CHECK(finish(call), "a deliberate Trust after the guard was not accepted");
    PASS();
}

static void test_trust_reports_and_returns_home(void) {
    TEST("Trust confirms the pin and the home screen then shows the policy");
    ui_call_t *call = start_prompt();
    CHECK(call, "the prompt did not appear");
    ui_run(1000);
    CHECK(ui_tap_text("Trust"), "no Trust button");
    CHECK(finish(call), "Trust was not accepted");
    ux_report_warden_pin(true);
    ui_run(1000);
    shot("03_trusted");
    CHECK(ui_get_state() == UI_STATE_SUCCESS && ui_has_text("Key trusted"),
          "no confirmation that the key was trusted");
    CHECK(ui_tap_text("Done"), "no Done button");
    ui_run(1000);
    shot("04_home_with_policy");
    CHECK(ui_get_state() == UI_STATE_IDLE && ui_has_text("Policy v1") && !ui_has_text("No policy"),
          "the home screen did not show the installed policy");
    PASS();
}

static void test_timeout_says_so(void) {
    TEST("an unanswered prompt times out and says so");
    ui_call_t *call = start_prompt();
    CHECK(call, "the prompt did not appear");
    ui_run(PIN_TIMEOUT_MS - 1000);
    CHECK(!ui_call_done(call), "the prompt gave up early");
    ui_run(2000);
    CHECK(!finish(call), "a timed out prompt trusted the key");
    ui_run(1000);
    shot("05_timed_out");
    CHECK(ui_get_state() == UI_STATE_ERROR && ui_has_text("Timed out"), "no timeout message");
    PASS();
}

static void test_save_failure_says_so(void) {
    TEST("a failed save is reported and leaves the home screen without a policy");
    ux_get_backend()->show_idle("keep", false, 1);
    ux_report_warden_pin(false);
    ui_run(1000);
    shot("06_not_saved");
    CHECK(ui_get_state() == UI_STATE_ERROR && ui_has_text("Not saved"), "no save failure message");
    CHECK(ui_tap_text("OK") && ui_has_text("No policy"), "the home screen claimed a policy");
    PASS();
}

static int tx_decision = -1;

static void tx_cb(bool approved, void *user_data) {
    (void)user_data;
    tx_decision = approved;
}

static void test_transaction_prompt_guarded(void) {
    TEST("the transaction prompt ignores taps as it appears");
    ux_tx_info_t tx = {.amount_sats = 50000,
                       .fee_sats = 500,
                       .destination = "bc1qexample",
                       .input_count = 1,
                       .output_count = 2,
                       .threshold = 2,
                       .total_signers = 3};
    tx_decision = -1;
    ux_get_backend()->confirm_transaction(&tx, tx_cb, NULL);
    CHECK(ui_tap_text("Approve"), "no Approve button");
    ui_run(100);
    CHECK(tx_decision == -1, "a tap during the guard approved the transaction");
    ui_run(1000);
    shot("07_transaction");
    CHECK(ui_tap_text("Approve") && tx_decision == 1, "a deliberate Approve was ignored");
    PASS();
}

int main(int argc, char **argv) {
    shot_dir = argc > 1 ? argv[1] : getenv("UI_SHOT_DIR");
    printf("=== UI Tests ===\n\n");
    if (ux_init() != 0 || ux_set_backend("display") != 0) {
        printf("display backend unavailable\n");
        return 1;
    }
    test_reject_shows_result_until_ok();
    test_bounce_cannot_skip_result();
    test_early_tap_cannot_trust();
    test_trust_reports_and_returns_home();
    test_timeout_says_so();
    test_save_failure_says_so();
    test_transaction_prompt_guarded();
    printf("\n%s\n", failures ? "FAILED" : "All UI tests passed");
    return failures ? 1 : 0;
}
