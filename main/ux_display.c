// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include "ux_display.h"
#include "ux_interface.h"
#include "touch_input.h"
#include "bsp/esp-bsp.h"
#include "lvgl.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include <stdio.h>
#include <string.h>

#define TAG "ux_display"

#define SCREEN_WIDTH  320
#define SCREEN_HEIGHT 240

#define COLOR_BG      lv_color_hex(0x0d1117)
#define COLOR_SURFACE lv_color_hex(0x161b22)
#define COLOR_ACCENT  lv_color_hex(0x58a6ff)
#define COLOR_DANGER  lv_color_hex(0xf85149)
#define COLOR_SUCCESS lv_color_hex(0x3fb950)
#define COLOR_WARNING lv_color_hex(0xd29922)
#define COLOR_TEXT    lv_color_hex(0xf0f6fc)
#define COLOR_MUTED   lv_color_hex(0x8b949e)

static ui_state_t current_state = UI_STATE_IDLE;
static ux_decision_cb_t pending_callback = NULL;
static void *pending_user_data = NULL;
static lv_obj_t *current_screen = NULL;
static lv_obj_t *signing_bar = NULL;
static lv_obj_t *signing_label = NULL;

static void create_idle_screen(const char *device_name, bool policy_loaded,
                               uint32_t policy_version);
static void create_scanning_screen(void);
static void create_transaction_screen(const ux_tx_info_t *tx);
static void create_signing_screen(int current, int total);
static void create_qr_screen(const char *data, size_t len);
static void create_error_screen(const char *title, const char *message);
static void create_success_screen(const char *message);

static int display_init(void) {
    bsp_display_cfg_t cfg = {.lvgl_port_cfg = ESP_LVGL_PORT_INIT_CONFIG(),
                             .buffer_size = SCREEN_WIDTH * 20,
                             .double_buffer = false,
                             .flags = {
                                 .buff_dma = true,
                                 .buff_spiram = false,
                             }};
    cfg.lvgl_port_cfg.task_affinity = 1;

    lv_display_t *disp = bsp_display_start_with_config(&cfg);
    if (disp == NULL) {
        ESP_LOGE(TAG, "Failed to initialize display");
        return -1;
    }

    bsp_display_backlight_on();
    ESP_LOGI(TAG, "Display UX backend initialized (LVGL + CoreS3 BSP)");
    return 0;
}

static void display_deinit(void) {
    bsp_display_backlight_off();
}

static void clear_screen(void) {
    pending_callback = NULL;
    pending_user_data = NULL;

    if (current_screen) {
        lv_obj_del(current_screen);
        current_screen = NULL;
    }
    signing_bar = NULL;
    signing_label = NULL;
}

static void display_show_idle(const char *device_name, bool policy_loaded,
                              uint32_t policy_version) {
    bsp_display_lock(portMAX_DELAY);
    clear_screen();
    create_idle_screen(device_name, policy_loaded, policy_version);
    current_state = UI_STATE_IDLE;
    bsp_display_unlock();
}

static void display_show_scanning(void) {
    bsp_display_lock(portMAX_DELAY);
    clear_screen();
    create_scanning_screen();
    current_state = UI_STATE_SCANNING;
    bsp_display_unlock();
}

static void display_show_signing(int current, int total) {
    bsp_display_lock(portMAX_DELAY);

    if (total <= 0) {
        total = 1;
    }
    if (current < 0) {
        current = 0;
    } else if (current > total) {
        current = total;
    }

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
    bsp_display_lock(portMAX_DELAY);
    clear_screen();
    create_success_screen(message);
    current_state = UI_STATE_SUCCESS;
    bsp_display_unlock();
}

static void display_show_error(const char *title, const char *message) {
    bsp_display_lock(portMAX_DELAY);
    clear_screen();
    create_error_screen(title, message);
    current_state = UI_STATE_ERROR;
    bsp_display_unlock();
}

static void invoke_pending_callback(bool approved) {
    if (!pending_callback) {
        return;
    }
    ux_decision_cb_t cb = pending_callback;
    void *data = pending_user_data;
    pending_callback = NULL;
    pending_user_data = NULL;
    cb(approved, data);
}

static void approve_btn_cb(lv_event_t *e) {
    (void)e;
    invoke_pending_callback(true);
}

static void reject_btn_cb(lv_event_t *e) {
    (void)e;
    invoke_pending_callback(false);
}

static void display_confirm_transaction(const ux_tx_info_t *tx, ux_decision_cb_t cb,
                                        void *user_data) {
    bsp_display_lock(portMAX_DELAY);
    clear_screen();
    pending_callback = cb;
    pending_user_data = user_data;
    create_transaction_screen(tx);
    current_state = UI_STATE_CONFIRM_TX;
    bsp_display_unlock();
}

static void display_show_qr(const char *data, size_t len) {
    if (data == NULL || len == 0) {
        return;
    }
    bsp_display_lock(portMAX_DELAY);
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
        touch_point_t point;
        if (touch_poll(&point) && point.pressed) {
            return true;
        }
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

static void scan_btn_cb(lv_event_t *e) {
    (void)e;
}

static void create_idle_screen(const char *device_name, bool policy_loaded,
                               uint32_t policy_version) {
    current_screen = lv_obj_create(lv_scr_act());
    lv_obj_set_size(current_screen, SCREEN_WIDTH, SCREEN_HEIGHT);
    lv_obj_set_style_bg_color(current_screen, COLOR_BG, 0);
    lv_obj_set_style_border_width(current_screen, 0, 0);
    lv_obj_set_style_pad_all(current_screen, 0, 0);
    lv_obj_center(current_screen);

    lv_obj_t *title = lv_label_create(current_screen);
    lv_label_set_text(title, "KEEP");
    lv_obj_set_style_text_color(title, COLOR_TEXT, 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_32, 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 30);

    lv_obj_t *subtitle = lv_label_create(current_screen);
    lv_label_set_text(subtitle, "FROST Threshold Signer");
    lv_obj_set_style_text_color(subtitle, COLOR_MUTED, 0);
    lv_obj_set_style_text_font(subtitle, &lv_font_montserrat_12, 0);
    lv_obj_align(subtitle, LV_ALIGN_TOP_MID, 0, 65);

    lv_obj_t *status_container = lv_obj_create(current_screen);
    lv_obj_set_size(status_container, 280, 36);
    lv_obj_set_style_bg_color(status_container, COLOR_SURFACE, 0);
    lv_obj_set_style_border_width(status_container, 0, 0);
    lv_obj_set_style_radius(status_container, 8, 0);
    lv_obj_set_style_pad_all(status_container, 8, 0);
    lv_obj_align(status_container, LV_ALIGN_TOP_MID, 0, 90);

    lv_obj_t *policy_label = lv_label_create(status_container);
    if (policy_loaded) {
        char policy_str[48];
        snprintf(policy_str, sizeof(policy_str), "Policy v%lu", (unsigned long)policy_version);
        lv_label_set_text(policy_label, policy_str);
        lv_obj_set_style_text_color(policy_label, COLOR_SUCCESS, 0);
    } else {
        lv_label_set_text(policy_label, "No policy");
        lv_obj_set_style_text_color(policy_label, COLOR_WARNING, 0);
    }
    lv_obj_set_style_text_font(policy_label, &lv_font_montserrat_12, 0);
    lv_obj_center(policy_label);

    lv_obj_t *scan_btn = lv_btn_create(current_screen);
    lv_obj_set_size(scan_btn, 200, 50);
    lv_obj_align(scan_btn, LV_ALIGN_CENTER, 0, 30);
    lv_obj_set_style_bg_color(scan_btn, COLOR_ACCENT, 0);
    lv_obj_set_style_radius(scan_btn, 8, 0);
    lv_obj_add_event_cb(scan_btn, scan_btn_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *scan_label = lv_label_create(scan_btn);
    lv_label_set_text(scan_label, "Scan QR");
    lv_obj_set_style_text_font(scan_label, &lv_font_montserrat_16, 0);
    lv_obj_center(scan_label);

    lv_obj_t *device_label = lv_label_create(current_screen);
    lv_label_set_text(device_label, device_name ? device_name : "Unknown Device");
    lv_obj_set_style_text_color(device_label, COLOR_MUTED, 0);
    lv_obj_set_style_text_font(device_label, &lv_font_montserrat_12, 0);
    lv_obj_align(device_label, LV_ALIGN_BOTTOM_MID, 0, -15);
}

static void create_scanning_screen(void) {
    current_screen = lv_obj_create(lv_scr_act());
    lv_obj_set_size(current_screen, SCREEN_WIDTH, SCREEN_HEIGHT);
    lv_obj_set_style_bg_color(current_screen, COLOR_BG, 0);
    lv_obj_set_style_border_width(current_screen, 0, 0);
    lv_obj_center(current_screen);

    lv_obj_t *spinner = lv_spinner_create(current_screen);
    lv_obj_set_size(spinner, 60, 60);
    lv_obj_align(spinner, LV_ALIGN_CENTER, 0, -30);

    lv_obj_t *label = lv_label_create(current_screen);
    lv_label_set_text(label, "Scanning");
    lv_obj_set_style_text_color(label, COLOR_TEXT, 0);
    lv_obj_set_style_text_font(label, &lv_font_montserrat_24, 0);
    lv_obj_align(label, LV_ALIGN_CENTER, 0, 40);

    lv_obj_t *hint = lv_label_create(current_screen);
    lv_label_set_text(hint, "Point camera at QR code");
    lv_obj_set_style_text_color(hint, COLOR_MUTED, 0);
    lv_obj_set_style_text_font(hint, &lv_font_montserrat_12, 0);
    lv_obj_align(hint, LV_ALIGN_CENTER, 0, 70);
}

static void create_transaction_screen(const ux_tx_info_t *tx) {
    current_screen = lv_obj_create(lv_scr_act());
    lv_obj_set_size(current_screen, SCREEN_WIDTH, SCREEN_HEIGHT);
    lv_obj_set_style_bg_color(current_screen, COLOR_BG, 0);
    lv_obj_set_style_pad_all(current_screen, 0, 0);
    lv_obj_set_style_border_width(current_screen, 0, 0);
    lv_obj_center(current_screen);

    bool high_fee = tx->amount_sats > 0 && tx->fee_sats > tx->amount_sats / 10;
    int y_pos = 8;

    lv_obj_t *title = lv_label_create(current_screen);
    lv_label_set_text(title, "Confirm Transaction");
    lv_obj_set_style_text_color(title, COLOR_TEXT, 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_16, 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, y_pos);
    y_pos += 28;

    char amount_str[32];
    if (tx->amount_sats >= 100000000) {
        snprintf(amount_str, sizeof(amount_str), "%.8f BTC", tx->amount_sats / 100000000.0);
    } else if (tx->amount_sats >= 1000000) {
        snprintf(amount_str, sizeof(amount_str), "%.2f M sats", tx->amount_sats / 1000000.0);
    } else if (tx->amount_sats >= 1000) {
        snprintf(amount_str, sizeof(amount_str), "%.1f K sats", tx->amount_sats / 1000.0);
    } else {
        snprintf(amount_str, sizeof(amount_str), "%llu sats", (unsigned long long)tx->amount_sats);
    }

    lv_obj_t *amount_label = lv_label_create(current_screen);
    lv_label_set_text(amount_label, amount_str);
    lv_obj_set_style_text_color(amount_label, COLOR_TEXT, 0);
    lv_obj_set_style_text_font(amount_label, &lv_font_montserrat_24, 0);
    lv_obj_align(amount_label, LV_ALIGN_TOP_MID, 0, y_pos);
    y_pos += 32;

    lv_obj_t *dest_box = lv_obj_create(current_screen);
    lv_obj_set_size(dest_box, 300, tx->destination_label[0] ? 48 : 36);
    lv_obj_set_style_bg_color(dest_box, COLOR_SURFACE, 0);
    lv_obj_set_style_border_width(dest_box, 0, 0);
    lv_obj_set_style_radius(dest_box, 6, 0);
    lv_obj_set_style_pad_all(dest_box, 6, 0);
    lv_obj_align(dest_box, LV_ALIGN_TOP_MID, 0, y_pos);

    lv_obj_t *to_label = lv_label_create(dest_box);
    lv_label_set_text(to_label, "To");
    lv_obj_set_style_text_color(to_label, COLOR_MUTED, 0);
    lv_obj_set_style_text_font(to_label, &lv_font_montserrat_12, 0);
    lv_obj_align(to_label, LV_ALIGN_TOP_LEFT, 0, 0);

    lv_obj_t *dest_label = lv_label_create(dest_box);
    lv_label_set_text(dest_label, tx->destination[0] ? tx->destination : "(none)");
    lv_obj_set_style_text_color(dest_label, COLOR_TEXT, 0);
    lv_obj_set_style_text_font(dest_label, &lv_font_montserrat_12, 0);
    lv_obj_set_width(dest_label, 260);
    lv_label_set_long_mode(dest_label, LV_LABEL_LONG_SCROLL_CIRCULAR);
    lv_obj_align(dest_label, LV_ALIGN_TOP_LEFT, 20, 0);

    if (tx->destination_label[0]) {
        lv_obj_t *label_tag = lv_label_create(dest_box);
        lv_label_set_text(label_tag, tx->destination_label);
        lv_obj_set_style_text_color(label_tag, COLOR_SUCCESS, 0);
        lv_obj_set_style_text_font(label_tag, &lv_font_montserrat_12, 0);
        lv_obj_align(label_tag, LV_ALIGN_BOTTOM_LEFT, 0, 0);
    }
    y_pos += (tx->destination_label[0] ? 52 : 40);

    lv_obj_t *details_box = lv_obj_create(current_screen);
    lv_obj_set_size(details_box, 300, 50);
    lv_obj_set_style_bg_color(details_box, COLOR_SURFACE, 0);
    lv_obj_set_style_border_width(details_box, 0, 0);
    lv_obj_set_style_radius(details_box, 6, 0);
    lv_obj_set_style_pad_all(details_box, 6, 0);
    lv_obj_align(details_box, LV_ALIGN_TOP_MID, 0, y_pos);

    char fee_str[32];
    snprintf(fee_str, sizeof(fee_str), "%llu sats", (unsigned long long)tx->fee_sats);
    lv_obj_t *fee_title = lv_label_create(details_box);
    lv_label_set_text(fee_title, "Fee");
    lv_obj_set_style_text_color(fee_title, COLOR_MUTED, 0);
    lv_obj_set_style_text_font(fee_title, &lv_font_montserrat_12, 0);
    lv_obj_align(fee_title, LV_ALIGN_TOP_LEFT, 0, 0);

    lv_obj_t *fee_val = lv_label_create(details_box);
    lv_label_set_text(fee_val, fee_str);
    lv_obj_set_style_text_color(fee_val, high_fee ? COLOR_WARNING : COLOR_TEXT, 0);
    lv_obj_set_style_text_font(fee_val, &lv_font_montserrat_12, 0);
    lv_obj_align(fee_val, LV_ALIGN_TOP_LEFT, 30, 0);

    if (tx->threshold > 0) {
        char frost_str[24];
        snprintf(frost_str, sizeof(frost_str), "%d-of-%d", tx->threshold, tx->total_signers);
        lv_obj_t *frost_title = lv_label_create(details_box);
        lv_label_set_text(frost_title, "FROST");
        lv_obj_set_style_text_color(frost_title, COLOR_MUTED, 0);
        lv_obj_set_style_text_font(frost_title, &lv_font_montserrat_12, 0);
        lv_obj_align(frost_title, LV_ALIGN_TOP_RIGHT, -60, 0);

        lv_obj_t *frost_val = lv_label_create(details_box);
        lv_label_set_text(frost_val, frost_str);
        lv_obj_set_style_text_color(frost_val, COLOR_ACCENT, 0);
        lv_obj_set_style_text_font(frost_val, &lv_font_montserrat_12, 0);
        lv_obj_align(frost_val, LV_ALIGN_TOP_RIGHT, 0, 0);
    }

    lv_obj_t *policy_ind = lv_label_create(details_box);
    lv_label_set_text(policy_ind, tx->policy_approved ? "Policy OK" : "Policy denied");
    lv_obj_set_style_text_color(policy_ind, tx->policy_approved ? COLOR_SUCCESS : COLOR_DANGER, 0);
    lv_obj_set_style_text_font(policy_ind, &lv_font_montserrat_12, 0);
    lv_obj_align(policy_ind, LV_ALIGN_BOTTOM_LEFT, 0, 0);

    if (tx->is_external) {
        lv_obj_t *ext_warn = lv_label_create(details_box);
        lv_label_set_text(ext_warn, "External");
        lv_obj_set_style_text_color(ext_warn, COLOR_WARNING, 0);
        lv_obj_set_style_text_font(ext_warn, &lv_font_montserrat_12, 0);
        lv_obj_align(ext_warn, LV_ALIGN_BOTTOM_RIGHT, 0, 0);
    }
    y_pos += 54;

    if (high_fee) {
        lv_obj_t *warn_label = lv_label_create(current_screen);
        lv_label_set_text(warn_label, "High fee (>10%)");
        lv_obj_set_style_text_color(warn_label, COLOR_WARNING, 0);
        lv_obj_set_style_text_font(warn_label, &lv_font_montserrat_12, 0);
        lv_obj_align(warn_label, LV_ALIGN_TOP_MID, 0, y_pos);
    }

    lv_obj_t *reject_btn = lv_btn_create(current_screen);
    lv_obj_set_size(reject_btn, 145, 42);
    lv_obj_align(reject_btn, LV_ALIGN_BOTTOM_LEFT, 10, -8);
    lv_obj_set_style_bg_color(reject_btn, COLOR_SURFACE, 0);
    lv_obj_set_style_radius(reject_btn, 6, 0);
    lv_obj_add_event_cb(reject_btn, reject_btn_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *reject_label = lv_label_create(reject_btn);
    lv_label_set_text(reject_label, "Reject");
    lv_obj_set_style_text_color(reject_label, COLOR_DANGER, 0);
    lv_obj_center(reject_label);

    lv_obj_t *approve_btn = lv_btn_create(current_screen);
    lv_obj_set_size(approve_btn, 145, 42);
    lv_obj_align(approve_btn, LV_ALIGN_BOTTOM_RIGHT, -10, -8);
    lv_obj_set_style_bg_color(approve_btn, COLOR_SUCCESS, 0);
    lv_obj_set_style_radius(approve_btn, 6, 0);
    lv_obj_add_event_cb(approve_btn, approve_btn_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *approve_label = lv_label_create(approve_btn);
    lv_label_set_text(approve_label, "Approve");
    lv_obj_center(approve_label);
}

static void create_signing_screen(int current, int total) {
    current_screen = lv_obj_create(lv_scr_act());
    lv_obj_set_size(current_screen, SCREEN_WIDTH, SCREEN_HEIGHT);
    lv_obj_set_style_bg_color(current_screen, COLOR_BG, 0);
    lv_obj_set_style_border_width(current_screen, 0, 0);
    lv_obj_center(current_screen);

    lv_obj_t *title = lv_label_create(current_screen);
    lv_label_set_text(title, "Signing");
    lv_obj_set_style_text_color(title, COLOR_TEXT, 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_24, 0);
    lv_obj_align(title, LV_ALIGN_CENTER, 0, -50);

    int progress = (total > 0) ? (current * 100) / total : 0;

    signing_bar = lv_bar_create(current_screen);
    lv_obj_set_size(signing_bar, 260, 12);
    lv_obj_align(signing_bar, LV_ALIGN_CENTER, 0, 0);
    lv_obj_set_style_bg_color(signing_bar, COLOR_SURFACE, LV_PART_MAIN);
    lv_obj_set_style_bg_color(signing_bar, COLOR_ACCENT, LV_PART_INDICATOR);
    lv_obj_set_style_radius(signing_bar, 6, LV_PART_MAIN);
    lv_obj_set_style_radius(signing_bar, 6, LV_PART_INDICATOR);
    lv_bar_set_range(signing_bar, 0, 100);
    lv_bar_set_value(signing_bar, progress, LV_ANIM_OFF);

    signing_label = lv_label_create(current_screen);
    char progress_str[32];
    snprintf(progress_str, sizeof(progress_str), "Input %d of %d", current, total);
    lv_label_set_text(signing_label, progress_str);
    lv_obj_set_style_text_color(signing_label, COLOR_MUTED, 0);
    lv_obj_set_style_text_font(signing_label, &lv_font_montserrat_12, 0);
    lv_obj_align(signing_label, LV_ALIGN_CENTER, 0, 30);
}

static void create_qr_screen(const char *data, size_t len) {
    current_screen = lv_obj_create(lv_scr_act());
    lv_obj_set_size(current_screen, SCREEN_WIDTH, SCREEN_HEIGHT);
    lv_obj_set_style_bg_color(current_screen, COLOR_BG, 0);
    lv_obj_set_style_border_width(current_screen, 0, 0);
    lv_obj_center(current_screen);

    lv_obj_t *title = lv_label_create(current_screen);
    lv_label_set_text(title, "Scan with wallet");
    lv_obj_set_style_text_color(title, COLOR_TEXT, 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_16, 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 10);

    lv_obj_t *qr_container = lv_obj_create(current_screen);
    lv_obj_set_size(qr_container, 188, 188);
    lv_obj_set_style_bg_color(qr_container, lv_color_white(), 0);
    lv_obj_set_style_border_width(qr_container, 0, 0);
    lv_obj_set_style_radius(qr_container, 8, 0);
    lv_obj_set_style_pad_all(qr_container, 4, 0);
    lv_obj_align(qr_container, LV_ALIGN_CENTER, 0, 5);

    lv_obj_t *qr = lv_qrcode_create(qr_container);
    lv_qrcode_set_size(qr, 180);
    lv_qrcode_set_dark_color(qr, lv_color_black());
    lv_qrcode_set_light_color(qr, lv_color_white());
    lv_qrcode_update(qr, data, len);
    lv_obj_center(qr);

    lv_obj_t *hint = lv_label_create(current_screen);
    lv_label_set_text(hint, "Tap to continue");
    lv_obj_set_style_text_color(hint, COLOR_MUTED, 0);
    lv_obj_set_style_text_font(hint, &lv_font_montserrat_12, 0);
    lv_obj_align(hint, LV_ALIGN_BOTTOM_MID, 0, -15);
}

static void create_error_screen(const char *title, const char *message) {
    current_screen = lv_obj_create(lv_scr_act());
    lv_obj_set_size(current_screen, SCREEN_WIDTH, SCREEN_HEIGHT);
    lv_obj_set_style_bg_color(current_screen, COLOR_BG, 0);
    lv_obj_set_style_border_width(current_screen, 0, 0);
    lv_obj_center(current_screen);

    lv_obj_t *icon = lv_label_create(current_screen);
    lv_label_set_text(icon, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_color(icon, COLOR_DANGER, 0);
    lv_obj_set_style_text_font(icon, &lv_font_montserrat_32, 0);
    lv_obj_align(icon, LV_ALIGN_CENTER, 0, -50);

    lv_obj_t *title_label = lv_label_create(current_screen);
    lv_label_set_text(title_label, title ? title : "Error");
    lv_obj_set_style_text_color(title_label, COLOR_TEXT, 0);
    lv_obj_set_style_text_font(title_label, &lv_font_montserrat_16, 0);
    lv_obj_align(title_label, LV_ALIGN_CENTER, 0, -10);

    lv_obj_t *msg_label = lv_label_create(current_screen);
    lv_label_set_text(msg_label, message ? message : "An error occurred");
    lv_obj_set_style_text_color(msg_label, COLOR_MUTED, 0);
    lv_obj_set_style_text_align(msg_label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(msg_label, &lv_font_montserrat_12, 0);
    lv_obj_set_width(msg_label, 280);
    lv_obj_align(msg_label, LV_ALIGN_CENTER, 0, 25);

    lv_obj_t *hint = lv_label_create(current_screen);
    lv_label_set_text(hint, "Tap to continue");
    lv_obj_set_style_text_color(hint, COLOR_MUTED, 0);
    lv_obj_set_style_text_font(hint, &lv_font_montserrat_12, 0);
    lv_obj_align(hint, LV_ALIGN_BOTTOM_MID, 0, -20);
}

static void create_success_screen(const char *message) {
    current_screen = lv_obj_create(lv_scr_act());
    lv_obj_set_size(current_screen, SCREEN_WIDTH, SCREEN_HEIGHT);
    lv_obj_set_style_bg_color(current_screen, COLOR_BG, 0);
    lv_obj_set_style_border_width(current_screen, 0, 0);
    lv_obj_center(current_screen);

    lv_obj_t *check = lv_label_create(current_screen);
    lv_label_set_text(check, LV_SYMBOL_OK);
    lv_obj_set_style_text_color(check, COLOR_SUCCESS, 0);
    lv_obj_set_style_text_font(check, &lv_font_montserrat_32, 0);
    lv_obj_align(check, LV_ALIGN_CENTER, 0, -40);

    lv_obj_t *title = lv_label_create(current_screen);
    lv_label_set_text(title, "Success");
    lv_obj_set_style_text_color(title, COLOR_TEXT, 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_24, 0);
    lv_obj_align(title, LV_ALIGN_CENTER, 0, 10);

    lv_obj_t *msg_label = lv_label_create(current_screen);
    lv_label_set_text(msg_label, message ? message : "");
    lv_obj_set_style_text_color(msg_label, COLOR_MUTED, 0);
    lv_obj_set_style_text_font(msg_label, &lv_font_montserrat_12, 0);
    lv_obj_align(msg_label, LV_ALIGN_CENTER, 0, 45);

    lv_obj_t *hint = lv_label_create(current_screen);
    lv_label_set_text(hint, "Tap to continue");
    lv_obj_set_style_text_color(hint, COLOR_MUTED, 0);
    lv_obj_set_style_text_font(hint, &lv_font_montserrat_12, 0);
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
