// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifdef CONFIG_KEEP_DISPLAY_ENABLED

#include "ux_display.h"
#include "ux_interface.h"
#include "bsp/esp-bsp.h"
#include "lvgl.h"
#include "esp_log.h"
#include <stdio.h>
#include <string.h>

#define TAG "ux_display"

#define SCREEN_WIDTH  320
#define SCREEN_HEIGHT 240

#define COLOR_BG        lv_color_hex(0x1a1a2e)
#define COLOR_PRIMARY   lv_color_hex(0x16213e)
#define COLOR_ACCENT    lv_color_hex(0xe94560)
#define COLOR_SUCCESS   lv_color_hex(0x4ecca3)
#define COLOR_WARNING   lv_color_hex(0xf39c12)
#define COLOR_TEXT      lv_color_hex(0xeaeaea)

static ui_state_t current_state = UI_STATE_IDLE;
static ux_decision_cb_t pending_callback = NULL;
static void *pending_user_data = NULL;
static lv_obj_t *current_screen = NULL;
static lv_obj_t *signing_bar = NULL;
static lv_obj_t *signing_label = NULL;

static void create_idle_screen(const char *device_name, bool policy_loaded, uint32_t policy_version);
static void create_scanning_screen(void);
static void create_transaction_screen(const ux_tx_info_t *tx);
static void create_signing_screen(int current, int total);
static void create_qr_screen(const char *data, size_t len);
static void create_error_screen(const char *title, const char *message);
static void create_success_screen(const char *message);

static int display_init(void) {
    bsp_display_start();
    bsp_display_backlight_on();
    ESP_LOGI(TAG, "Display UX backend initialized (LVGL + CoreS3 BSP)");
    return 0;
}

static void display_deinit(void) {
    bsp_display_backlight_off();
}

static void clear_screen(void) {
    if (current_screen) {
        lv_obj_del(current_screen);
        current_screen = NULL;
    }
    signing_bar = NULL;
    signing_label = NULL;
}

static void display_show_idle(const char *device_name, bool policy_loaded, uint32_t policy_version) {
    bsp_display_lock(0);
    clear_screen();
    create_idle_screen(device_name, policy_loaded, policy_version);
    current_state = UI_STATE_IDLE;
    bsp_display_unlock();
}

static void display_show_scanning(void) {
    bsp_display_lock(0);
    clear_screen();
    create_scanning_screen();
    current_state = UI_STATE_SCANNING;
    bsp_display_unlock();
}

static void display_show_signing(int current, int total) {
    bsp_display_lock(0);

    if (current_state != UI_STATE_SIGNING) {
        clear_screen();
        create_signing_screen(current, total);
        current_state = UI_STATE_SIGNING;
    } else if (signing_bar && signing_label) {
        lv_bar_set_value(signing_bar, (current * 100) / total, LV_ANIM_ON);
        char progress_str[32];
        snprintf(progress_str, sizeof(progress_str), "Input %d of %d", current, total);
        lv_label_set_text(signing_label, progress_str);
    }

    bsp_display_unlock();
}

static void display_show_success(const char *message) {
    bsp_display_lock(0);
    clear_screen();
    create_success_screen(message);
    current_state = UI_STATE_SUCCESS;
    bsp_display_unlock();
}

static void display_show_error(const char *title, const char *message) {
    bsp_display_lock(0);
    clear_screen();
    create_error_screen(title, message);
    current_state = UI_STATE_ERROR;
    bsp_display_unlock();
}

static void approve_btn_cb(lv_event_t *e) {
    (void)e;
    if (pending_callback) {
        ux_decision_cb_t cb = pending_callback;
        void *data = pending_user_data;
        pending_callback = NULL;
        pending_user_data = NULL;
        cb(true, data);
    }
}

static void reject_btn_cb(lv_event_t *e) {
    (void)e;
    if (pending_callback) {
        ux_decision_cb_t cb = pending_callback;
        void *data = pending_user_data;
        pending_callback = NULL;
        pending_user_data = NULL;
        cb(false, data);
    }
}

static void display_confirm_transaction(const ux_tx_info_t *tx,
                                         ux_decision_cb_t cb, void *user_data) {
    pending_callback = cb;
    pending_user_data = user_data;

    bsp_display_lock(0);
    clear_screen();
    create_transaction_screen(tx);
    current_state = UI_STATE_CONFIRM_TX;
    bsp_display_unlock();
}

static void display_show_qr(const char *data, size_t len) {
    bsp_display_lock(0);
    clear_screen();
    create_qr_screen(data, len);
    current_state = UI_STATE_SHOW_QR;
    bsp_display_unlock();
}

static int display_scan_qr(char *data, size_t max_len, uint32_t timeout_ms) {
    (void)data;
    (void)max_len;
    (void)timeout_ms;
    ESP_LOGW(TAG, "QR scanning requires Phase 7.2 (qr_scanner)");
    return -1;
}

static bool display_wait_any_input(uint32_t timeout_ms) {
    TickType_t start = xTaskGetTickCount();
    TickType_t timeout = pdMS_TO_TICKS(timeout_ms);

    while ((xTaskGetTickCount() - start) < timeout) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    return false;
}

static bool display_is_available(void) {
    return true;
}

ui_state_t ui_get_state(void) {
    return current_state;
}

static void create_idle_screen(const char *device_name, bool policy_loaded, uint32_t policy_version) {
    current_screen = lv_obj_create(lv_scr_act());
    lv_obj_set_size(current_screen, SCREEN_WIDTH, SCREEN_HEIGHT);
    lv_obj_set_style_bg_color(current_screen, COLOR_BG, 0);
    lv_obj_set_style_border_width(current_screen, 0, 0);
    lv_obj_set_style_pad_all(current_screen, 0, 0);
    lv_obj_center(current_screen);

    lv_obj_t *header = lv_obj_create(current_screen);
    lv_obj_set_size(header, SCREEN_WIDTH, 50);
    lv_obj_set_style_bg_color(header, COLOR_PRIMARY, 0);
    lv_obj_set_style_border_width(header, 0, 0);
    lv_obj_align(header, LV_ALIGN_TOP_MID, 0, 0);

    lv_obj_t *title = lv_label_create(header);
    lv_label_set_text(title, "KEEP SIGNER");
    lv_obj_set_style_text_color(title, COLOR_TEXT, 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_24, 0);
    lv_obj_center(title);

    lv_obj_t *name_label = lv_label_create(current_screen);
    lv_label_set_text(name_label, device_name);
    lv_obj_set_style_text_color(name_label, COLOR_TEXT, 0);
    lv_obj_set_style_text_font(name_label, &lv_font_montserrat_16, 0);
    lv_obj_align(name_label, LV_ALIGN_TOP_MID, 0, 70);

    lv_obj_t *policy_label = lv_label_create(current_screen);
    if (policy_loaded) {
        char policy_str[32];
        snprintf(policy_str, sizeof(policy_str), "Policy v%lu active", (unsigned long)policy_version);
        lv_label_set_text(policy_label, policy_str);
        lv_obj_set_style_text_color(policy_label, COLOR_SUCCESS, 0);
    } else {
        lv_label_set_text(policy_label, "No policy loaded");
        lv_obj_set_style_text_color(policy_label, COLOR_WARNING, 0);
    }
    lv_obj_set_style_text_font(policy_label, &lv_font_montserrat_12, 0);
    lv_obj_align(policy_label, LV_ALIGN_TOP_MID, 0, 95);

    lv_obj_t *scan_btn = lv_btn_create(current_screen);
    lv_obj_set_size(scan_btn, 200, 60);
    lv_obj_align(scan_btn, LV_ALIGN_CENTER, 0, 20);
    lv_obj_set_style_bg_color(scan_btn, COLOR_ACCENT, 0);

    lv_obj_t *scan_label = lv_label_create(scan_btn);
    lv_label_set_text(scan_label, "SCAN QR");
    lv_obj_set_style_text_font(scan_label, &lv_font_montserrat_16, 0);
    lv_obj_center(scan_label);

    lv_obj_t *footer = lv_label_create(current_screen);
    lv_label_set_text(footer, "FROST Threshold Signer");
    lv_obj_set_style_text_color(footer, lv_color_hex(0x888888), 0);
    lv_obj_set_style_text_font(footer, &lv_font_montserrat_12, 0);
    lv_obj_align(footer, LV_ALIGN_BOTTOM_MID, 0, -10);
}

static void create_scanning_screen(void) {
    current_screen = lv_obj_create(lv_scr_act());
    lv_obj_set_size(current_screen, SCREEN_WIDTH, SCREEN_HEIGHT);
    lv_obj_set_style_bg_color(current_screen, COLOR_BG, 0);
    lv_obj_set_style_border_width(current_screen, 0, 0);
    lv_obj_center(current_screen);

    lv_obj_t *spinner = lv_spinner_create(current_screen);
    lv_obj_set_size(spinner, 80, 80);
    lv_obj_align(spinner, LV_ALIGN_CENTER, 0, -20);

    lv_obj_t *label = lv_label_create(current_screen);
    lv_label_set_text(label, "Scanning...");
    lv_obj_set_style_text_color(label, COLOR_TEXT, 0);
    lv_obj_set_style_text_font(label, &lv_font_montserrat_24, 0);
    lv_obj_align(label, LV_ALIGN_CENTER, 0, 50);

    lv_obj_t *hint = lv_label_create(current_screen);
    lv_label_set_text(hint, "Point camera at QR code");
    lv_obj_set_style_text_color(hint, lv_color_hex(0x888888), 0);
    lv_obj_set_style_text_font(hint, &lv_font_montserrat_12, 0);
    lv_obj_align(hint, LV_ALIGN_CENTER, 0, 80);
}

static void create_transaction_screen(const ux_tx_info_t *tx) {
    current_screen = lv_obj_create(lv_scr_act());
    lv_obj_set_size(current_screen, SCREEN_WIDTH, SCREEN_HEIGHT);
    lv_obj_set_style_bg_color(current_screen, COLOR_BG, 0);
    lv_obj_set_style_pad_all(current_screen, 0, 0);
    lv_obj_set_style_border_width(current_screen, 0, 0);
    lv_obj_center(current_screen);

    lv_obj_t *header = lv_obj_create(current_screen);
    lv_obj_set_size(header, SCREEN_WIDTH, 40);
    lv_obj_set_style_bg_color(header, COLOR_WARNING, 0);
    lv_obj_set_style_border_width(header, 0, 0);
    lv_obj_align(header, LV_ALIGN_TOP_MID, 0, 0);

    lv_obj_t *title = lv_label_create(header);
    lv_label_set_text(title, "CONFIRM TRANSACTION");
    lv_obj_set_style_text_color(title, COLOR_BG, 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_16, 0);
    lv_obj_center(title);

    char amount_str[32];
    if (tx->amount_sats >= 100000000) {
        snprintf(amount_str, sizeof(amount_str), "%.8f BTC",
                 tx->amount_sats / 100000000.0);
    } else {
        snprintf(amount_str, sizeof(amount_str), "%llu sats",
                 (unsigned long long)tx->amount_sats);
    }

    lv_obj_t *amount_label = lv_label_create(current_screen);
    lv_label_set_text(amount_label, amount_str);
    lv_obj_set_style_text_color(amount_label, COLOR_TEXT, 0);
    lv_obj_set_style_text_font(amount_label, &lv_font_montserrat_32, 0);
    lv_obj_align(amount_label, LV_ALIGN_TOP_MID, 0, 50);

    lv_obj_t *to_label = lv_label_create(current_screen);
    lv_label_set_text(to_label, "To:");
    lv_obj_set_style_text_color(to_label, lv_color_hex(0x888888), 0);
    lv_obj_align(to_label, LV_ALIGN_TOP_LEFT, 10, 90);

    lv_obj_t *dest_label = lv_label_create(current_screen);
    lv_label_set_text(dest_label, tx->destination);
    lv_obj_set_style_text_color(dest_label, COLOR_TEXT, 0);
    lv_obj_set_style_text_font(dest_label, &lv_font_montserrat_12, 0);
    lv_obj_align(dest_label, LV_ALIGN_TOP_LEFT, 10, 108);

    if (tx->destination_label[0]) {
        lv_obj_t *label_label = lv_label_create(current_screen);
        lv_label_set_text(label_label, tx->destination_label);
        lv_obj_set_style_text_color(label_label, COLOR_SUCCESS, 0);
        lv_obj_align(label_label, LV_ALIGN_TOP_LEFT, 10, 125);
    }

    char fee_str[32];
    snprintf(fee_str, sizeof(fee_str), "Fee: %llu sats",
             (unsigned long long)tx->fee_sats);
    lv_obj_t *fee_label = lv_label_create(current_screen);
    lv_label_set_text(fee_label, fee_str);
    lv_obj_set_style_text_color(fee_label, COLOR_TEXT, 0);
    lv_obj_align(fee_label, LV_ALIGN_TOP_LEFT, 10, 145);

    lv_obj_t *policy_label = lv_label_create(current_screen);
    if (tx->policy_approved) {
        lv_label_set_text(policy_label, "Policy: APPROVED");
        lv_obj_set_style_text_color(policy_label, COLOR_SUCCESS, 0);
    } else {
        lv_label_set_text(policy_label, tx->policy_note ? tx->policy_note : "Policy: DENIED");
        lv_obj_set_style_text_color(policy_label, COLOR_ACCENT, 0);
    }
    lv_obj_align(policy_label, LV_ALIGN_TOP_LEFT, 10, 165);

    lv_obj_t *approve_btn = lv_btn_create(current_screen);
    lv_obj_set_size(approve_btn, 140, 45);
    lv_obj_align(approve_btn, LV_ALIGN_BOTTOM_LEFT, 10, -10);
    lv_obj_set_style_bg_color(approve_btn, COLOR_SUCCESS, 0);
    lv_obj_add_event_cb(approve_btn, approve_btn_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *approve_label = lv_label_create(approve_btn);
    lv_label_set_text(approve_label, "APPROVE");
    lv_obj_center(approve_label);

    lv_obj_t *reject_btn = lv_btn_create(current_screen);
    lv_obj_set_size(reject_btn, 140, 45);
    lv_obj_align(reject_btn, LV_ALIGN_BOTTOM_RIGHT, -10, -10);
    lv_obj_set_style_bg_color(reject_btn, COLOR_ACCENT, 0);
    lv_obj_add_event_cb(reject_btn, reject_btn_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *reject_label = lv_label_create(reject_btn);
    lv_label_set_text(reject_label, "REJECT");
    lv_obj_center(reject_label);
}

static void create_signing_screen(int current, int total) {
    current_screen = lv_obj_create(lv_scr_act());
    lv_obj_set_size(current_screen, SCREEN_WIDTH, SCREEN_HEIGHT);
    lv_obj_set_style_bg_color(current_screen, COLOR_BG, 0);
    lv_obj_set_style_border_width(current_screen, 0, 0);
    lv_obj_center(current_screen);

    lv_obj_t *title = lv_label_create(current_screen);
    lv_label_set_text(title, "Signing...");
    lv_obj_set_style_text_color(title, COLOR_TEXT, 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_24, 0);
    lv_obj_align(title, LV_ALIGN_CENTER, 0, -40);

    signing_label = lv_label_create(current_screen);
    char progress_str[32];
    snprintf(progress_str, sizeof(progress_str), "Input %d of %d", current, total);
    lv_label_set_text(signing_label, progress_str);
    lv_obj_set_style_text_color(signing_label, COLOR_WARNING, 0);
    lv_obj_align(signing_label, LV_ALIGN_CENTER, 0, 0);

    signing_bar = lv_bar_create(current_screen);
    lv_obj_set_size(signing_bar, 250, 20);
    lv_obj_align(signing_bar, LV_ALIGN_CENTER, 0, 40);
    lv_bar_set_range(signing_bar, 0, 100);
    lv_bar_set_value(signing_bar, (current * 100) / total, LV_ANIM_OFF);
}

static void create_qr_screen(const char *data, size_t len) {
    current_screen = lv_obj_create(lv_scr_act());
    lv_obj_set_size(current_screen, SCREEN_WIDTH, SCREEN_HEIGHT);
    lv_obj_set_style_bg_color(current_screen, lv_color_white(), 0);
    lv_obj_set_style_border_width(current_screen, 0, 0);
    lv_obj_center(current_screen);

    lv_obj_t *title = lv_label_create(current_screen);
    lv_label_set_text(title, "Scan with wallet");
    lv_obj_set_style_text_color(title, COLOR_BG, 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_12, 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 5);

    lv_obj_t *qr = lv_qrcode_create(current_screen);
    lv_qrcode_set_size(qr, 180);
    lv_qrcode_set_dark_color(qr, lv_color_black());
    lv_qrcode_set_light_color(qr, lv_color_white());
    lv_qrcode_update(qr, data, len);
    lv_obj_align(qr, LV_ALIGN_CENTER, 0, 0);

    lv_obj_t *hint = lv_label_create(current_screen);
    lv_label_set_text(hint, "Tap to continue");
    lv_obj_set_style_text_color(hint, lv_color_hex(0x888888), 0);
    lv_obj_set_style_text_font(hint, &lv_font_montserrat_12, 0);
    lv_obj_align(hint, LV_ALIGN_BOTTOM_MID, 0, -10);
}

static void create_error_screen(const char *title, const char *message) {
    current_screen = lv_obj_create(lv_scr_act());
    lv_obj_set_size(current_screen, SCREEN_WIDTH, SCREEN_HEIGHT);
    lv_obj_set_style_bg_color(current_screen, COLOR_BG, 0);
    lv_obj_set_style_border_width(current_screen, 0, 0);
    lv_obj_center(current_screen);

    lv_obj_t *header = lv_obj_create(current_screen);
    lv_obj_set_size(header, SCREEN_WIDTH, 50);
    lv_obj_set_style_bg_color(header, COLOR_ACCENT, 0);
    lv_obj_set_style_border_width(header, 0, 0);
    lv_obj_align(header, LV_ALIGN_TOP_MID, 0, 0);

    lv_obj_t *title_label = lv_label_create(header);
    lv_label_set_text(title_label, title);
    lv_obj_set_style_text_color(title_label, COLOR_TEXT, 0);
    lv_obj_set_style_text_font(title_label, &lv_font_montserrat_16, 0);
    lv_obj_center(title_label);

    lv_obj_t *msg_label = lv_label_create(current_screen);
    lv_label_set_text(msg_label, message);
    lv_obj_set_style_text_color(msg_label, COLOR_TEXT, 0);
    lv_obj_set_style_text_align(msg_label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_width(msg_label, 280);
    lv_obj_align(msg_label, LV_ALIGN_CENTER, 0, 0);

    lv_obj_t *hint = lv_label_create(current_screen);
    lv_label_set_text(hint, "Tap to continue");
    lv_obj_set_style_text_color(hint, lv_color_hex(0x888888), 0);
    lv_obj_align(hint, LV_ALIGN_BOTTOM_MID, 0, -20);
}

static void create_success_screen(const char *message) {
    current_screen = lv_obj_create(lv_scr_act());
    lv_obj_set_size(current_screen, SCREEN_WIDTH, SCREEN_HEIGHT);
    lv_obj_set_style_bg_color(current_screen, COLOR_BG, 0);
    lv_obj_set_style_border_width(current_screen, 0, 0);
    lv_obj_center(current_screen);

    lv_obj_t *header = lv_obj_create(current_screen);
    lv_obj_set_size(header, SCREEN_WIDTH, 50);
    lv_obj_set_style_bg_color(header, COLOR_SUCCESS, 0);
    lv_obj_set_style_border_width(header, 0, 0);
    lv_obj_align(header, LV_ALIGN_TOP_MID, 0, 0);

    lv_obj_t *title = lv_label_create(header);
    lv_label_set_text(title, "SUCCESS");
    lv_obj_set_style_text_color(title, COLOR_BG, 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_24, 0);
    lv_obj_center(title);

    lv_obj_t *check = lv_label_create(current_screen);
    lv_label_set_text(check, LV_SYMBOL_OK);
    lv_obj_set_style_text_color(check, COLOR_SUCCESS, 0);
    lv_obj_set_style_text_font(check, &lv_font_montserrat_32, 0);
    lv_obj_align(check, LV_ALIGN_CENTER, 0, -10);

    lv_obj_t *msg_label = lv_label_create(current_screen);
    lv_label_set_text(msg_label, message);
    lv_obj_set_style_text_color(msg_label, COLOR_TEXT, 0);
    lv_obj_align(msg_label, LV_ALIGN_CENTER, 0, 40);

    lv_obj_t *hint = lv_label_create(current_screen);
    lv_label_set_text(hint, "Tap to continue");
    lv_obj_set_style_text_color(hint, lv_color_hex(0x888888), 0);
    lv_obj_align(hint, LV_ALIGN_BOTTOM_MID, 0, -20);
}

const ux_backend_t ux_display_backend = {
    .name = "display",
    .init = display_init,
    .deinit = display_deinit,
    .show_idle = display_show_idle,
    .show_scanning = display_show_scanning,
    .show_signing = display_show_signing,
    .show_success = display_show_success,
    .show_error = display_show_error,
    .confirm_transaction = display_confirm_transaction,
    .show_qr = display_show_qr,
    .scan_qr = display_scan_qr,
    .wait_any_input = display_wait_any_input,
    .is_available = display_is_available,
};

#endif
