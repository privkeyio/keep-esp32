// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

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

#define SCREEN_WIDTH        320
#define SCREEN_HEIGHT       240
#define CONFIRM_TIMEOUT_SEC 30

#define COLOR_BG      lv_color_hex(0x000000)
#define COLOR_SURFACE lv_color_hex(0x1c1c1e)
#define COLOR_ACCENT  lv_color_hex(0x0a84ff)
#define COLOR_DANGER  lv_color_hex(0xff453a)
#define COLOR_SUCCESS lv_color_hex(0x30d158)
#define COLOR_WARNING lv_color_hex(0xffd60a)
#define COLOR_TEXT    lv_color_hex(0xffffff)
#define COLOR_MUTED   lv_color_hex(0x8e8e93)

static ui_state_t current_state = UI_STATE_IDLE;
static ux_decision_cb_t pending_callback = NULL;
static void *pending_user_data = NULL;
static lv_obj_t *current_screen = NULL;
static lv_obj_t *signing_bar = NULL;
static lv_obj_t *signing_label = NULL;
static lv_timer_t *confirm_timer = NULL;
static int timeout_remaining = 0;
static lv_obj_t *timeout_arc = NULL;
static lv_obj_t *timeout_label = NULL;

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

static void stop_confirm_timer(void) {
    if (confirm_timer) {
        lv_timer_del(confirm_timer);
        confirm_timer = NULL;
    }
    timeout_remaining = 0;
    timeout_arc = NULL;
    timeout_label = NULL;
}

static void invoke_pending_callback(bool approved);

static lv_color_t get_timeout_color(int remaining) {
    if (remaining <= 5) {
        return COLOR_DANGER;
    } else if (remaining <= 10) {
        return COLOR_WARNING;
    }
    return COLOR_ACCENT;
}

static void confirm_timer_cb(lv_timer_t *timer) {
    (void)timer;
    if (timeout_remaining > 0) {
        timeout_remaining--;

        if (timeout_arc) {
            int angle = (timeout_remaining * 360) / CONFIRM_TIMEOUT_SEC;
            lv_arc_set_angles(timeout_arc, 270, 270 + angle);
            lv_obj_set_style_arc_color(timeout_arc, get_timeout_color(timeout_remaining),
                                       LV_PART_INDICATOR);
        }

        if (timeout_label) {
            char timeout_str[8];
            snprintf(timeout_str, sizeof(timeout_str), "%d", timeout_remaining);
            lv_label_set_text(timeout_label, timeout_str);
            lv_obj_set_style_text_color(timeout_label, get_timeout_color(timeout_remaining), 0);
        }

        if (timeout_remaining == 0) {
            invoke_pending_callback(false);
        }
    }
}

static void clear_screen(void) {
    stop_confirm_timer();
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
    stop_confirm_timer();
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

    timeout_remaining = CONFIRM_TIMEOUT_SEC;
    confirm_timer = lv_timer_create(confirm_timer_cb, 1000, NULL);

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

static lv_obj_t *create_action_btn(lv_obj_t *parent, const char *text, lv_color_t bg_color,
                                    lv_color_t text_color, lv_event_cb_t click_cb);

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
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 40);

    lv_obj_t *subtitle = lv_label_create(current_screen);
    lv_label_set_text(subtitle, "Threshold Signer");
    lv_obj_set_style_text_color(subtitle, COLOR_MUTED, 0);
    lv_obj_set_style_text_font(subtitle, &lv_font_montserrat_14, 0);
    lv_obj_align(subtitle, LV_ALIGN_TOP_MID, 0, 78);

    lv_obj_t *status_pill = lv_obj_create(current_screen);
    lv_obj_set_size(status_pill, LV_SIZE_CONTENT, 28);
    lv_obj_set_style_bg_color(status_pill, policy_loaded ? lv_color_hex(0x1a3d1a) : lv_color_hex(0x3d3d1a), 0);
    lv_obj_set_style_border_width(status_pill, 0, 0);
    lv_obj_set_style_radius(status_pill, 14, 0);
    lv_obj_set_style_pad_hor(status_pill, 12, 0);
    lv_obj_set_style_pad_ver(status_pill, 4, 0);
    lv_obj_align(status_pill, LV_ALIGN_TOP_MID, 0, 105);

    lv_obj_t *policy_label = lv_label_create(status_pill);
    if (policy_loaded) {
        char policy_str[48];
        snprintf(policy_str, sizeof(policy_str), "Policy v%lu", (unsigned long)policy_version);
        lv_label_set_text(policy_label, policy_str);
        lv_obj_set_style_text_color(policy_label, COLOR_SUCCESS, 0);
    } else {
        lv_label_set_text(policy_label, "No policy loaded");
        lv_obj_set_style_text_color(policy_label, COLOR_WARNING, 0);
    }
    lv_obj_set_style_text_font(policy_label, &lv_font_montserrat_12, 0);
    lv_obj_center(policy_label);

    lv_obj_t *scan_btn = create_action_btn(current_screen, "Scan QR",
                                            COLOR_ACCENT, COLOR_TEXT, scan_btn_cb);
    lv_obj_set_size(scan_btn, 180, 52);
    lv_obj_align(scan_btn, LV_ALIGN_CENTER, 0, 35);

    lv_obj_t *device_label = lv_label_create(current_screen);
    lv_label_set_text(device_label, device_name ? device_name : "Unknown Device");
    lv_obj_set_style_text_color(device_label, COLOR_MUTED, 0);
    lv_obj_set_style_text_font(device_label, &lv_font_montserrat_12, 0);
    lv_obj_align(device_label, LV_ALIGN_BOTTOM_MID, 0, -20);
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

static void create_sign_request_screen(const ux_tx_info_t *tx) {
    current_screen = lv_obj_create(lv_scr_act());
    lv_obj_set_size(current_screen, SCREEN_WIDTH, SCREEN_HEIGHT);
    lv_obj_set_style_bg_color(current_screen, COLOR_BG, 0);
    lv_obj_set_style_pad_all(current_screen, 0, 0);
    lv_obj_set_style_border_width(current_screen, 0, 0);
    lv_obj_center(current_screen);

    lv_obj_t *title = lv_label_create(current_screen);
    lv_label_set_text(title, "Sign Request");
    lv_obj_set_style_text_color(title, COLOR_MUTED, 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_12, 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 16);

    lv_obj_t *wallet_label = lv_label_create(current_screen);
    lv_label_set_text(wallet_label, tx->destination[0] ? tx->destination : "Unknown");
    lv_obj_set_style_text_color(wallet_label, COLOR_TEXT, 0);
    lv_obj_set_style_text_font(wallet_label, &lv_font_montserrat_24, 0);
    lv_obj_align(wallet_label, LV_ALIGN_TOP_MID, 0, 36);

    if (tx->threshold > 0) {
        char frost_str[24];
        snprintf(frost_str, sizeof(frost_str), "%d-of-%d multisig", tx->threshold, tx->total_signers);
        lv_obj_t *frost_label = lv_label_create(current_screen);
        lv_label_set_text(frost_label, frost_str);
        lv_obj_set_style_text_color(frost_label, COLOR_MUTED, 0);
        lv_obj_set_style_text_font(frost_label, &lv_font_montserrat_12, 0);
        lv_obj_align(frost_label, LV_ALIGN_TOP_MID, 0, 68);
    }

    lv_obj_t *warn_box = lv_obj_create(current_screen);
    lv_obj_set_size(warn_box, 280, 44);
    lv_obj_set_style_bg_color(warn_box, lv_color_hex(0x1a1a00), 0);
    lv_obj_set_style_border_color(warn_box, COLOR_WARNING, 0);
    lv_obj_set_style_border_width(warn_box, 1, 0);
    lv_obj_set_style_radius(warn_box, 12, 0);
    lv_obj_set_style_pad_all(warn_box, 8, 0);
    lv_obj_align(warn_box, LV_ALIGN_CENTER, 0, -10);

    lv_obj_t *warn_icon = lv_label_create(warn_box);
    lv_label_set_text(warn_icon, LV_SYMBOL_WARNING);
    lv_obj_set_style_text_color(warn_icon, COLOR_WARNING, 0);
    lv_obj_align(warn_icon, LV_ALIGN_LEFT_MID, 4, 0);

    lv_obj_t *warn_text = lv_label_create(warn_box);
    lv_label_set_text(warn_text, "Verify details on coordinator");
    lv_obj_set_style_text_color(warn_text, COLOR_WARNING, 0);
    lv_obj_set_style_text_font(warn_text, &lv_font_montserrat_12, 0);
    lv_obj_align(warn_text, LV_ALIGN_LEFT_MID, 28, 0);

    timeout_arc = lv_arc_create(current_screen);
    lv_obj_set_size(timeout_arc, 50, 50);
    lv_arc_set_rotation(timeout_arc, 270);
    lv_arc_set_bg_angles(timeout_arc, 0, 360);
    lv_arc_set_angles(timeout_arc, 270, 270 + 360);
    lv_obj_set_style_arc_width(timeout_arc, 4, LV_PART_MAIN);
    lv_obj_set_style_arc_width(timeout_arc, 4, LV_PART_INDICATOR);
    lv_obj_set_style_arc_color(timeout_arc, COLOR_SURFACE, LV_PART_MAIN);
    lv_obj_set_style_arc_color(timeout_arc, COLOR_ACCENT, LV_PART_INDICATOR);
    lv_obj_remove_style(timeout_arc, NULL, LV_PART_KNOB);
    lv_obj_remove_flag(timeout_arc, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_align(timeout_arc, LV_ALIGN_TOP_RIGHT, -12, 12);

    char timeout_str[8];
    snprintf(timeout_str, sizeof(timeout_str), "%d", CONFIRM_TIMEOUT_SEC);
    timeout_label = lv_label_create(current_screen);
    lv_label_set_text(timeout_label, timeout_str);
    lv_obj_set_style_text_color(timeout_label, COLOR_ACCENT, 0);
    lv_obj_set_style_text_font(timeout_label, &lv_font_montserrat_12, 0);
    lv_obj_align_to(timeout_label, timeout_arc, LV_ALIGN_CENTER, 0, 0);

    lv_obj_t *reject_btn = lv_btn_create(current_screen);
    lv_obj_set_size(reject_btn, 140, 52);
    lv_obj_align(reject_btn, LV_ALIGN_BOTTOM_LEFT, 12, -12);
    lv_obj_set_style_bg_color(reject_btn, COLOR_SURFACE, 0);
    lv_obj_set_style_radius(reject_btn, 26, 0);
    lv_obj_add_event_cb(reject_btn, reject_btn_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *reject_icon = lv_label_create(reject_btn);
    lv_label_set_text(reject_icon, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_color(reject_icon, COLOR_DANGER, 0);
    lv_obj_set_style_text_font(reject_icon, &lv_font_montserrat_16, 0);
    lv_obj_align(reject_icon, LV_ALIGN_LEFT_MID, 16, 0);

    lv_obj_t *reject_label = lv_label_create(reject_btn);
    lv_label_set_text(reject_label, "Reject");
    lv_obj_set_style_text_color(reject_label, COLOR_TEXT, 0);
    lv_obj_set_style_text_font(reject_label, &lv_font_montserrat_14, 0);
    lv_obj_align(reject_label, LV_ALIGN_LEFT_MID, 40, 0);

    lv_obj_t *approve_btn = lv_btn_create(current_screen);
    lv_obj_set_size(approve_btn, 140, 52);
    lv_obj_align(approve_btn, LV_ALIGN_BOTTOM_RIGHT, -12, -12);
    lv_obj_set_style_bg_color(approve_btn, COLOR_SUCCESS, 0);
    lv_obj_set_style_radius(approve_btn, 26, 0);
    lv_obj_add_event_cb(approve_btn, approve_btn_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *approve_icon = lv_label_create(approve_btn);
    lv_label_set_text(approve_icon, LV_SYMBOL_OK);
    lv_obj_set_style_text_color(approve_icon, COLOR_TEXT, 0);
    lv_obj_set_style_text_font(approve_icon, &lv_font_montserrat_16, 0);
    lv_obj_align(approve_icon, LV_ALIGN_LEFT_MID, 12, 0);

    lv_obj_t *approve_label = lv_label_create(approve_btn);
    lv_label_set_text(approve_label, "Approve");
    lv_obj_set_style_text_color(approve_label, COLOR_TEXT, 0);
    lv_obj_set_style_text_font(approve_label, &lv_font_montserrat_14, 0);
    lv_obj_align(approve_label, LV_ALIGN_LEFT_MID, 36, 0);
}

static void format_address(const char *addr, char *out, size_t out_len) {
    size_t len = strlen(addr);
    if (len <= 20) {
        strncpy(out, addr, out_len - 1);
        out[out_len - 1] = '\0';
    } else {
        snprintf(out, out_len, "%.*s...%s", 10, addr, addr + len - 6);
    }
}

static void format_sats(uint64_t sats, char *out, size_t out_len) {
    if (sats >= 100000000) {
        double btc = sats / 100000000.0;
        if (btc >= 1.0) {
            snprintf(out, out_len, "%.4f", btc);
        } else {
            snprintf(out, out_len, "%.6f", btc);
        }
    } else if (sats >= 1000000) {
        snprintf(out, out_len, "%.2fM", sats / 1000000.0);
    } else if (sats >= 1000) {
        snprintf(out, out_len, "%llu,%03llu",
                 (unsigned long long)(sats / 1000),
                 (unsigned long long)(sats % 1000));
    } else {
        snprintf(out, out_len, "%llu", (unsigned long long)sats);
    }
}

static lv_obj_t *create_action_btn(lv_obj_t *parent, const char *text, lv_color_t bg_color,
                                    lv_color_t text_color, lv_event_cb_t click_cb) {
    lv_obj_t *btn = lv_btn_create(parent);
    lv_obj_set_size(btn, 145, 56);
    lv_obj_set_style_bg_color(btn, bg_color, 0);
    lv_obj_set_style_bg_color(btn, lv_color_darken(bg_color, 40), LV_STATE_PRESSED);
    lv_obj_set_style_radius(btn, 28, 0);
    lv_obj_set_style_shadow_width(btn, 0, 0);
    lv_obj_set_style_border_width(btn, 0, 0);
    lv_obj_add_event_cb(btn, click_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *label = lv_label_create(btn);
    lv_label_set_text(label, text);
    lv_obj_set_style_text_color(label, text_color, 0);
    lv_obj_set_style_text_font(label, &lv_font_montserrat_16, 0);
    lv_obj_center(label);

    return btn;
}

static void create_transaction_screen(const ux_tx_info_t *tx) {
    bool is_generic_sign = (tx->amount_sats == 0 && tx->fee_sats == 0);

    if (is_generic_sign) {
        create_sign_request_screen(tx);
        return;
    }

    current_screen = lv_obj_create(lv_scr_act());
    lv_obj_set_size(current_screen, SCREEN_WIDTH, SCREEN_HEIGHT);
    lv_obj_set_style_bg_color(current_screen, COLOR_BG, 0);
    lv_obj_set_style_pad_all(current_screen, 0, 0);
    lv_obj_set_style_border_width(current_screen, 0, 0);
    lv_obj_center(current_screen);

    bool high_fee = tx->amount_sats > 0 && tx->fee_sats > tx->amount_sats / 10;

    timeout_arc = lv_arc_create(current_screen);
    lv_obj_set_size(timeout_arc, 44, 44);
    lv_arc_set_rotation(timeout_arc, 270);
    lv_arc_set_bg_angles(timeout_arc, 0, 360);
    lv_arc_set_angles(timeout_arc, 270, 270 + 360);
    lv_obj_set_style_arc_width(timeout_arc, 3, LV_PART_MAIN);
    lv_obj_set_style_arc_width(timeout_arc, 3, LV_PART_INDICATOR);
    lv_obj_set_style_arc_color(timeout_arc, COLOR_SURFACE, LV_PART_MAIN);
    lv_obj_set_style_arc_color(timeout_arc, COLOR_ACCENT, LV_PART_INDICATOR);
    lv_obj_remove_style(timeout_arc, NULL, LV_PART_KNOB);
    lv_obj_remove_flag(timeout_arc, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_align(timeout_arc, LV_ALIGN_TOP_RIGHT, -8, 8);

    char timeout_str[8];
    snprintf(timeout_str, sizeof(timeout_str), "%d", CONFIRM_TIMEOUT_SEC);
    timeout_label = lv_label_create(current_screen);
    lv_label_set_text(timeout_label, timeout_str);
    lv_obj_set_style_text_color(timeout_label, COLOR_ACCENT, 0);
    lv_obj_set_style_text_font(timeout_label, &lv_font_montserrat_12, 0);
    lv_obj_align_to(timeout_label, timeout_arc, LV_ALIGN_CENTER, 0, 0);

    lv_obj_t *send_label = lv_label_create(current_screen);
    lv_label_set_text(send_label, "Send");
    lv_obj_set_style_text_color(send_label, COLOR_MUTED, 0);
    lv_obj_set_style_text_font(send_label, &lv_font_montserrat_14, 0);
    lv_obj_align(send_label, LV_ALIGN_TOP_LEFT, 16, 16);

    char amount_str[32];
    format_sats(tx->amount_sats, amount_str, sizeof(amount_str));

    lv_obj_t *amount_label = lv_label_create(current_screen);
    lv_label_set_text(amount_label, amount_str);
    lv_obj_set_style_text_color(amount_label, COLOR_TEXT, 0);
    lv_obj_set_style_text_font(amount_label, &lv_font_montserrat_32, 0);
    lv_obj_align(amount_label, LV_ALIGN_TOP_LEFT, 16, 36);

    lv_obj_t *unit_label = lv_label_create(current_screen);
    lv_label_set_text(unit_label, tx->amount_sats >= 100000000 ? "BTC" : "sats");
    lv_obj_set_style_text_color(unit_label, COLOR_MUTED, 0);
    lv_obj_set_style_text_font(unit_label, &lv_font_montserrat_14, 0);
    lv_obj_align_to(unit_label, amount_label, LV_ALIGN_OUT_RIGHT_BOTTOM, 6, -2);

    lv_obj_t *to_label = lv_label_create(current_screen);
    lv_label_set_text(to_label, "To");
    lv_obj_set_style_text_color(to_label, COLOR_MUTED, 0);
    lv_obj_set_style_text_font(to_label, &lv_font_montserrat_12, 0);
    lv_obj_align(to_label, LV_ALIGN_TOP_LEFT, 16, 78);

    lv_obj_t *dest_label = lv_label_create(current_screen);
    lv_label_set_text(dest_label, tx->destination[0] ? tx->destination : "Unknown");
    lv_obj_set_style_text_color(dest_label, COLOR_TEXT, 0);
    lv_obj_set_style_text_font(dest_label, &lv_font_montserrat_12, 0);
    lv_obj_set_width(dest_label, 288);
    lv_label_set_long_mode(dest_label, LV_LABEL_LONG_SCROLL_CIRCULAR);
    lv_obj_align(dest_label, LV_ALIGN_TOP_LEFT, 16, 94);

    int info_y = 114;
    if (tx->destination_label[0]) {
        lv_obj_t *label_tag = lv_label_create(current_screen);
        lv_label_set_text(label_tag, tx->destination_label);
        lv_obj_set_style_text_color(label_tag, COLOR_SUCCESS, 0);
        lv_obj_set_style_text_font(label_tag, &lv_font_montserrat_12, 0);
        lv_obj_align(label_tag, LV_ALIGN_TOP_LEFT, 16, info_y);
        info_y += 18;
    }

    lv_obj_t *info_bar = lv_obj_create(current_screen);
    lv_obj_set_size(info_bar, 288, 32);
    lv_obj_set_style_bg_color(info_bar, COLOR_SURFACE, 0);
    lv_obj_set_style_border_width(info_bar, 0, 0);
    lv_obj_set_style_radius(info_bar, 8, 0);
    lv_obj_set_style_pad_all(info_bar, 8, 0);
    lv_obj_align(info_bar, LV_ALIGN_TOP_LEFT, 16, info_y + 4);

    char fee_str[32];
    snprintf(fee_str, sizeof(fee_str), "Fee: %llu sats", (unsigned long long)tx->fee_sats);
    lv_obj_t *fee_label = lv_label_create(info_bar);
    lv_label_set_text(fee_label, fee_str);
    lv_obj_set_style_text_color(fee_label, high_fee ? COLOR_WARNING : COLOR_MUTED, 0);
    lv_obj_set_style_text_font(fee_label, &lv_font_montserrat_12, 0);
    lv_obj_align(fee_label, LV_ALIGN_LEFT_MID, 0, 0);

    if (tx->threshold > 0) {
        char frost_str[24];
        snprintf(frost_str, sizeof(frost_str), "%d-of-%d", tx->threshold, tx->total_signers);
        lv_obj_t *frost_label = lv_label_create(info_bar);
        lv_label_set_text(frost_label, frost_str);
        lv_obj_set_style_text_color(frost_label, COLOR_ACCENT, 0);
        lv_obj_set_style_text_font(frost_label, &lv_font_montserrat_12, 0);
        lv_obj_align(frost_label, LV_ALIGN_RIGHT_MID, 0, 0);
    }

    lv_obj_t *reject_btn = create_action_btn(current_screen, "Reject",
                                              COLOR_SURFACE, COLOR_DANGER, reject_btn_cb);
    lv_obj_align(reject_btn, LV_ALIGN_BOTTOM_LEFT, 10, -10);

    lv_obj_t *approve_btn = create_action_btn(current_screen, "Approve",
                                               COLOR_SUCCESS, COLOR_TEXT, approve_btn_cb);
    lv_obj_align(approve_btn, LV_ALIGN_BOTTOM_RIGHT, -10, -10);
}

static void create_signing_screen(int current, int total) {
    current_screen = lv_obj_create(lv_scr_act());
    lv_obj_set_size(current_screen, SCREEN_WIDTH, SCREEN_HEIGHT);
    lv_obj_set_style_bg_color(current_screen, COLOR_BG, 0);
    lv_obj_set_style_border_width(current_screen, 0, 0);
    lv_obj_center(current_screen);

    lv_obj_t *spinner = lv_spinner_create(current_screen);
    lv_obj_set_size(spinner, 50, 50);
    lv_obj_set_style_arc_color(spinner, COLOR_SURFACE, LV_PART_MAIN);
    lv_obj_set_style_arc_color(spinner, COLOR_ACCENT, LV_PART_INDICATOR);
    lv_obj_set_style_arc_width(spinner, 5, LV_PART_MAIN);
    lv_obj_set_style_arc_width(spinner, 5, LV_PART_INDICATOR);
    lv_obj_align(spinner, LV_ALIGN_CENTER, 0, -55);

    lv_obj_t *title = lv_label_create(current_screen);
    lv_label_set_text(title, "Signing");
    lv_obj_set_style_text_color(title, COLOR_TEXT, 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_24, 0);
    lv_obj_align(title, LV_ALIGN_CENTER, 0, 5);

    int progress = (total > 0) ? (current * 100) / total : 0;

    signing_bar = lv_bar_create(current_screen);
    lv_obj_set_size(signing_bar, 260, 8);
    lv_obj_align(signing_bar, LV_ALIGN_CENTER, 0, 50);
    lv_obj_set_style_bg_color(signing_bar, COLOR_SURFACE, LV_PART_MAIN);
    lv_obj_set_style_bg_color(signing_bar, COLOR_ACCENT, LV_PART_INDICATOR);
    lv_obj_set_style_radius(signing_bar, 4, LV_PART_MAIN);
    lv_obj_set_style_radius(signing_bar, 4, LV_PART_INDICATOR);
    lv_bar_set_range(signing_bar, 0, 100);
    lv_bar_set_value(signing_bar, progress, LV_ANIM_OFF);

    signing_label = lv_label_create(current_screen);
    char progress_str[32];
    snprintf(progress_str, sizeof(progress_str), "Input %d of %d", current, total);
    lv_label_set_text(signing_label, progress_str);
    lv_obj_set_style_text_color(signing_label, COLOR_MUTED, 0);
    lv_obj_set_style_text_font(signing_label, &lv_font_montserrat_12, 0);
    lv_obj_align(signing_label, LV_ALIGN_CENTER, 0, 75);
}

static void create_qr_screen(const char *data, size_t len) {
    current_screen = lv_obj_create(lv_scr_act());
    lv_obj_set_size(current_screen, SCREEN_WIDTH, SCREEN_HEIGHT);
    lv_obj_set_style_bg_color(current_screen, COLOR_BG, 0);
    lv_obj_set_style_border_width(current_screen, 0, 0);
    lv_obj_set_style_pad_all(current_screen, 0, 0);
    lv_obj_center(current_screen);

    lv_obj_t *title = lv_label_create(current_screen);
    lv_label_set_text(title, "Scan with Wallet");
    lv_obj_set_style_text_color(title, COLOR_TEXT, 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_16, 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 14);

    lv_obj_t *qr_container = lv_obj_create(current_screen);
    lv_obj_set_size(qr_container, 172, 172);
    lv_obj_set_style_bg_color(qr_container, lv_color_white(), 0);
    lv_obj_set_style_border_width(qr_container, 0, 0);
    lv_obj_set_style_radius(qr_container, 12, 0);
    lv_obj_set_style_pad_all(qr_container, 6, 0);
    lv_obj_set_style_shadow_width(qr_container, 20, 0);
    lv_obj_set_style_shadow_color(qr_container, lv_color_hex(0x0a84ff), 0);
    lv_obj_set_style_shadow_opa(qr_container, 60, 0);
    lv_obj_align(qr_container, LV_ALIGN_CENTER, 0, 8);

    lv_obj_t *qr = lv_qrcode_create(qr_container);
    lv_qrcode_set_size(qr, 160);
    lv_qrcode_set_dark_color(qr, lv_color_black());
    lv_qrcode_set_light_color(qr, lv_color_white());
    lv_qrcode_update(qr, data, len);
    lv_obj_center(qr);

    lv_obj_t *hint = lv_label_create(current_screen);
    lv_label_set_text(hint, "Tap to continue");
    lv_obj_set_style_text_color(hint, COLOR_MUTED, 0);
    lv_obj_set_style_text_font(hint, &lv_font_montserrat_12, 0);
    lv_obj_align(hint, LV_ALIGN_BOTTOM_MID, 0, -20);
}

static void create_error_screen(const char *title, const char *message) {
    current_screen = lv_obj_create(lv_scr_act());
    lv_obj_set_size(current_screen, SCREEN_WIDTH, SCREEN_HEIGHT);
    lv_obj_set_style_bg_color(current_screen, COLOR_BG, 0);
    lv_obj_set_style_border_width(current_screen, 0, 0);
    lv_obj_center(current_screen);

    lv_obj_t *icon_bg = lv_obj_create(current_screen);
    lv_obj_set_size(icon_bg, 72, 72);
    lv_obj_set_style_bg_color(icon_bg, lv_color_hex(0x3d1a1a), 0);
    lv_obj_set_style_border_width(icon_bg, 0, 0);
    lv_obj_set_style_radius(icon_bg, 36, 0);
    lv_obj_align(icon_bg, LV_ALIGN_CENTER, 0, -50);

    lv_obj_t *icon = lv_label_create(icon_bg);
    lv_label_set_text(icon, LV_SYMBOL_CLOSE);
    lv_obj_set_style_text_color(icon, COLOR_DANGER, 0);
    lv_obj_set_style_text_font(icon, &lv_font_montserrat_32, 0);
    lv_obj_center(icon);

    lv_obj_t *title_label = lv_label_create(current_screen);
    lv_label_set_text(title_label, title ? title : "Error");
    lv_obj_set_style_text_color(title_label, COLOR_TEXT, 0);
    lv_obj_set_style_text_font(title_label, &lv_font_montserrat_16, 0);
    lv_obj_align(title_label, LV_ALIGN_CENTER, 0, 5);

    lv_obj_t *msg_label = lv_label_create(current_screen);
    lv_label_set_text(msg_label, message ? message : "An error occurred");
    lv_obj_set_style_text_color(msg_label, COLOR_MUTED, 0);
    lv_obj_set_style_text_align(msg_label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(msg_label, &lv_font_montserrat_12, 0);
    lv_obj_set_width(msg_label, 280);
    lv_obj_align(msg_label, LV_ALIGN_CENTER, 0, 35);

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

    lv_obj_t *icon_bg = lv_obj_create(current_screen);
    lv_obj_set_size(icon_bg, 72, 72);
    lv_obj_set_style_bg_color(icon_bg, lv_color_hex(0x1a3d1a), 0);
    lv_obj_set_style_border_width(icon_bg, 0, 0);
    lv_obj_set_style_radius(icon_bg, 36, 0);
    lv_obj_align(icon_bg, LV_ALIGN_CENTER, 0, -50);

    lv_obj_t *check = lv_label_create(icon_bg);
    lv_label_set_text(check, LV_SYMBOL_OK);
    lv_obj_set_style_text_color(check, COLOR_SUCCESS, 0);
    lv_obj_set_style_text_font(check, &lv_font_montserrat_32, 0);
    lv_obj_center(check);

    lv_obj_t *title = lv_label_create(current_screen);
    lv_label_set_text(title, "Success");
    lv_obj_set_style_text_color(title, COLOR_TEXT, 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_24, 0);
    lv_obj_align(title, LV_ALIGN_CENTER, 0, 5);

    lv_obj_t *msg_label = lv_label_create(current_screen);
    lv_label_set_text(msg_label, message ? message : "");
    lv_obj_set_style_text_color(msg_label, COLOR_MUTED, 0);
    lv_obj_set_style_text_font(msg_label, &lv_font_montserrat_12, 0);
    lv_obj_align(msg_label, LV_ALIGN_CENTER, 0, 40);

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
