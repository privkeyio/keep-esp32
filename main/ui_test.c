// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include "ui_test.h"
#include "ux_display.h"
#include "bsp/esp-bsp.h"
#include "cJSON.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "lvgl.h"
#include <string.h>

#define TAG        "ui_test"
#define TEXT_LEN   32
#define MAX_TEXTS  32
#define QUEUE_LEN  4
#define TICK_MS    10
#define RELEASE_MS 80

typedef struct {
    char text[TEXT_LEN];
    uint32_t after_ms;
    uint32_t hold_ms;
    uint32_t bounce_ms;
    uint32_t timeout_ms;
} tap_t;

typedef enum { TAP_IDLE, TAP_FIND, TAP_WAIT, TAP_PRESSED, TAP_RELEASED } tap_phase_t;

/* Taps run from an LVGL timer on the LVGL task, under the display lock: internal RAM
 * has no room for a task of their own. */
static tap_t queue[QUEUE_LEN];
static int queue_head = 0;
static int queue_count = 0;
static tap_t current;
static tap_phase_t phase = TAP_IDLE;
static uint32_t phase_since = 0;
static bool ready = false;
static int32_t touch_x = 0;
static int32_t touch_y = 0;
static bool touch_pressed = false;
static int taps_done = 0;
static int taps_missed = 0;

static void read_cb(lv_indev_t *indev, lv_indev_data_t *data) {
    (void)indev;
    data->point.x = touch_x;
    data->point.y = touch_y;
    data->state = touch_pressed ? LV_INDEV_STATE_PRESSED : LV_INDEV_STATE_RELEASED;
}

static lv_obj_t *find_label(lv_obj_t *obj, const char *text) {
    if (lv_obj_has_flag(obj, LV_OBJ_FLAG_HIDDEN)) {
        return NULL;
    }
    if (lv_obj_check_type(obj, &lv_label_class) && strcmp(lv_label_get_text(obj), text) == 0) {
        return obj;
    }
    for (uint32_t i = 0; i < lv_obj_get_child_count(obj); i++) {
        lv_obj_t *found = find_label(lv_obj_get_child(obj, (int32_t)i), text);
        if (found) {
            return found;
        }
    }
    return NULL;
}

/* The center of the clickable object a label belongs to, as a finger would aim. */
static bool locate(const char *text, int32_t *x, int32_t *y) {
    lv_obj_update_layout(lv_screen_active());
    lv_obj_t *obj = find_label(lv_screen_active(), text);
    while (obj && !lv_obj_has_flag(obj, LV_OBJ_FLAG_CLICKABLE)) {
        obj = lv_obj_get_parent(obj);
    }
    if (!obj) {
        return false;
    }
    lv_area_t area;
    lv_obj_get_coords(obj, &area);
    *x = (area.x1 + area.x2) / 2;
    *y = (area.y1 + area.y2) / 2;
    return true;
}

static void enter(tap_phase_t next) {
    phase = next;
    phase_since = lv_tick_get();
}

static void missed(const char *why) {
    ESP_LOGW(TAG, "'%s' %s", current.text, why);
    taps_missed++;
    enter(TAP_IDLE);
}

static void tap_tick(lv_timer_t *timer) {
    (void)timer;
    uint32_t elapsed = lv_tick_elaps(phase_since);
    switch (phase) {
    case TAP_IDLE:
        if (queue_count > 0) {
            current = queue[queue_head];
            queue_head = (queue_head + 1) % QUEUE_LEN;
            queue_count--;
            enter(TAP_FIND);
        }
        break;
    case TAP_FIND:
        if (locate(current.text, &touch_x, &touch_y)) {
            enter(TAP_WAIT);
        } else if (elapsed >= current.timeout_ms) {
            missed("never appeared");
        }
        break;
    case TAP_WAIT:
        if (elapsed < current.after_ms) {
            break;
        }
        if (!locate(current.text, &touch_x, &touch_y)) {
            missed("was gone before the tap");
            break;
        }
        touch_pressed = true;
        enter(TAP_PRESSED);
        break;
    case TAP_PRESSED:
        if (elapsed >= current.hold_ms) {
            touch_pressed = false;
            enter(TAP_RELEASED);
        }
        break;
    case TAP_RELEASED:
        if (current.bounce_ms && elapsed >= current.bounce_ms) {
            current.bounce_ms = 0;
            touch_pressed = true;
            enter(TAP_PRESSED);
        } else if (!current.bounce_ms && elapsed >= RELEASE_MS) {
            taps_done++;
            enter(TAP_IDLE);
        }
        break;
    }
}

void ui_test_init(void) {
    bsp_display_lock(0);
    lv_indev_t *indev = lv_indev_create();
    lv_indev_set_type(indev, LV_INDEV_TYPE_POINTER);
    lv_indev_set_read_cb(indev, read_cb);
    lv_timer_create(tap_tick, TICK_MS, NULL);

    lv_obj_t *banner = lv_label_create(lv_layer_top());
    lv_label_set_text(banner, "TEST");
    lv_obj_set_style_text_color(banner, lv_color_hex(0xf85149), 0);
    lv_obj_set_style_text_font(banner, &lv_font_montserrat_12, 0);
    lv_obj_align(banner, LV_ALIGN_TOP_RIGHT, -4, 2);
    ready = true;
    bsp_display_unlock();
    ESP_LOGW(TAG, "UI test build: the host can tap the screen");
}

static uint32_t get_ms(const cJSON *params, const char *key, uint32_t fallback) {
    const cJSON *item = cJSON_GetObjectItem(params, key);
    if (!cJSON_IsNumber(item) || item->valuedouble < 0 || item->valuedouble > 600000) {
        return fallback;
    }
    return (uint32_t)item->valuedouble;
}

static void collect_texts(lv_obj_t *obj, cJSON *out) {
    if (lv_obj_has_flag(obj, LV_OBJ_FLAG_HIDDEN) || cJSON_GetArraySize(out) >= MAX_TEXTS) {
        return;
    }
    if (lv_obj_check_type(obj, &lv_label_class)) {
        cJSON_AddItemToArray(out, cJSON_CreateString(lv_label_get_text(obj)));
    }
    for (uint32_t i = 0; i < lv_obj_get_child_count(obj); i++) {
        collect_texts(lv_obj_get_child(obj, (int32_t)i), out);
    }
}

static void handle_state(int id, rpc_response_t *resp) {
    cJSON *root = cJSON_CreateObject();
    cJSON *texts = cJSON_AddArrayToObject(root, "texts");
    bsp_display_lock(0);
    cJSON_AddNumberToObject(root, "state", ui_get_state());
    collect_texts(lv_screen_active(), texts);
    bsp_display_unlock();
    cJSON_AddNumberToObject(root, "taps_done", taps_done);
    cJSON_AddNumberToObject(root, "taps_missed", taps_missed);
    cJSON_AddNumberToObject(root, "free_heap", heap_caps_get_free_size(MALLOC_CAP_8BIT));
    cJSON_AddNumberToObject(root, "largest_block",
                            heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (json) {
        protocol_success(resp, id, json);
        cJSON_free(json);
    } else {
        PROTOCOL_ERROR(resp, id, PROTOCOL_ERR_INTERNAL, "Out of memory");
    }
}

static void handle_tap(const cJSON *params, int id, rpc_response_t *resp) {
    const cJSON *text = cJSON_GetObjectItem(params, "text");
    if (!cJSON_IsString(text) || strlen(text->valuestring) >= TEXT_LEN) {
        PROTOCOL_ERROR(resp, id, PROTOCOL_ERR_PARAMS, "text required");
        return;
    }
    tap_t tap = {0};
    strncpy(tap.text, text->valuestring, TEXT_LEN - 1);
    tap.after_ms = get_ms(params, "after_ms", 800);
    tap.hold_ms = get_ms(params, "hold_ms", 100);
    tap.bounce_ms = get_ms(params, "bounce_ms", 0);
    tap.timeout_ms = get_ms(params, "timeout_ms", 10000);
    bsp_display_lock(0);
    bool queued = queue_count < QUEUE_LEN;
    if (queued) {
        queue[(queue_head + queue_count) % QUEUE_LEN] = tap;
        queue_count++;
    }
    bsp_display_unlock();
    if (!queued) {
        PROTOCOL_ERROR(resp, id, PROTOCOL_ERR_INTERNAL, "Tap queue full");
        return;
    }
    protocol_success(resp, id, "{\"scheduled\":true}");
}

bool ui_test_handle(const char *line, const rpc_request_t *req, rpc_response_t *resp) {
    if (req->method != RPC_METHOD_UNKNOWN || !ready) {
        return false;
    }
    cJSON *root = cJSON_Parse(line);
    const cJSON *method = cJSON_GetObjectItem(root, "method");
    const cJSON *params = cJSON_GetObjectItem(root, "params");
    bool handled = true;
    if (cJSON_IsString(method) && strcmp(method->valuestring, "ui_state") == 0) {
        handle_state(req->id, resp);
    } else if (cJSON_IsString(method) && strcmp(method->valuestring, "ui_tap") == 0) {
        handle_tap(params, req->id, resp);
    } else {
        handled = false;
    }
    cJSON_Delete(root);
    return handled;
}
