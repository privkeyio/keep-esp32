// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#include "ui_harness.h"
#include "bsp/esp-bsp.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "touch_input.h"
#include "lvgl.h"
#include "src/libs/lodepng/lodepng.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define WIDTH   320
#define HEIGHT  240
#define STEP_MS 10

static pthread_mutex_t clock_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t clock_cv = PTHREAD_COND_INITIALIZER;
static uint32_t now_ms = 0;

static pthread_mutex_t display_mu;
static uint16_t framebuffer[HEIGHT][WIDTH];
static uint16_t draw_buf[WIDTH * 40];
static int touch_x, touch_y;
static bool touch_pressed;

struct shim_sem {
    bool given;
};

TickType_t xTaskGetTickCount(void) {
    pthread_mutex_lock(&clock_mu);
    uint32_t t = now_ms;
    pthread_mutex_unlock(&clock_mu);
    return t;
}

void vTaskDelay(TickType_t ticks) {
    pthread_mutex_lock(&clock_mu);
    uint32_t until = now_ms + ticks;
    while (now_ms < until) {
        pthread_cond_wait(&clock_cv, &clock_mu);
    }
    pthread_mutex_unlock(&clock_mu);
}

SemaphoreHandle_t xSemaphoreCreateBinary(void) {
    return calloc(1, sizeof(struct shim_sem));
}

BaseType_t xSemaphoreTake(SemaphoreHandle_t sem, TickType_t ticks) {
    pthread_mutex_lock(&clock_mu);
    uint64_t deadline = (uint64_t)now_ms + ticks;
    while (!sem->given && (ticks == portMAX_DELAY || now_ms < deadline)) {
        if (ticks == 0) {
            break;
        }
        pthread_cond_wait(&clock_cv, &clock_mu);
    }
    BaseType_t got = sem->given ? pdTRUE : pdFALSE;
    sem->given = false;
    pthread_mutex_unlock(&clock_mu);
    return got;
}

BaseType_t xSemaphoreGive(SemaphoreHandle_t sem) {
    pthread_mutex_lock(&clock_mu);
    sem->given = true;
    pthread_cond_broadcast(&clock_cv);
    pthread_mutex_unlock(&clock_mu);
    return pdTRUE;
}

bool touch_poll(touch_point_t *point) {
    point->x = (int16_t)touch_x;
    point->y = (int16_t)touch_y;
    point->pressed = touch_pressed;
    return true;
}

static uint32_t tick_cb(void) {
    return xTaskGetTickCount();
}

static void flush_cb(lv_display_t *disp, const lv_area_t *area, uint8_t *px_map) {
    const uint16_t *src = (const uint16_t *)px_map;
    for (int y = area->y1; y <= area->y2; y++) {
        for (int x = area->x1; x <= area->x2; x++) {
            framebuffer[y][x] = *src++;
        }
    }
    lv_display_flush_ready(disp);
}

static void touch_read_cb(lv_indev_t *indev, lv_indev_data_t *data) {
    (void)indev;
    data->point.x = touch_x;
    data->point.y = touch_y;
    data->state = touch_pressed ? LV_INDEV_STATE_PRESSED : LV_INDEV_STATE_RELEASED;
}

lv_display_t *bsp_display_start_with_config(const bsp_display_cfg_t *cfg) {
    (void)cfg;
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&display_mu, &attr);

    lv_init();
    lv_tick_set_cb(tick_cb);
    lv_display_t *disp = lv_display_create(WIDTH, HEIGHT);
    lv_display_set_color_format(disp, LV_COLOR_FORMAT_RGB565);
    lv_display_set_buffers(disp, draw_buf, NULL, sizeof(draw_buf), LV_DISPLAY_RENDER_MODE_PARTIAL);
    lv_display_set_flush_cb(disp, flush_cb);

    lv_indev_t *indev = lv_indev_create();
    lv_indev_set_type(indev, LV_INDEV_TYPE_POINTER);
    lv_indev_set_read_cb(indev, touch_read_cb);
    return disp;
}

esp_err_t bsp_display_backlight_on(void) {
    return ESP_OK;
}

esp_err_t bsp_display_backlight_off(void) {
    return ESP_OK;
}

bool bsp_display_lock(uint32_t timeout_ms) {
    (void)timeout_ms;
    pthread_mutex_lock(&display_mu);
    return true;
}

void bsp_display_unlock(void) {
    pthread_mutex_unlock(&display_mu);
}

static void step(uint32_t ms) {
    pthread_mutex_lock(&clock_mu);
    now_ms += ms;
    pthread_cond_broadcast(&clock_cv);
    pthread_mutex_unlock(&clock_mu);
    bsp_display_lock(0);
    lv_timer_handler();
    bsp_display_unlock();
}

void ui_run(uint32_t ms) {
    for (uint32_t t = 0; t < ms; t += STEP_MS) {
        step(STEP_MS);
    }
}

/* Lets a ui_call thread reach its next blocking point without moving the clock. */
bool ui_settle(bool (*done)(void *), void *arg) {
    for (int i = 0; i < 2000; i++) {
        bsp_display_lock(0);
        lv_timer_handler();
        lv_obj_update_layout(lv_screen_active());
        bsp_display_unlock();
        if (done(arg)) {
            return true;
        }
        nanosleep(&(struct timespec){0, 1000000}, NULL);
    }
    return false;
}

void ui_press(int x, int y) {
    touch_x = x;
    touch_y = y;
    touch_pressed = true;
    step(STEP_MS);
}

void ui_release(void) {
    touch_pressed = false;
    step(STEP_MS);
}

void ui_tap(int x, int y) {
    ui_press(x, y);
    ui_run(60);
    ui_release();
    ui_run(60);
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

bool ui_find_text(const char *text, int *x, int *y) {
    bsp_display_lock(0);
    lv_obj_update_layout(lv_screen_active());
    lv_obj_t *obj = find_label(lv_screen_active(), text);
    while (obj && !lv_obj_has_flag(obj, LV_OBJ_FLAG_CLICKABLE)) {
        obj = lv_obj_get_parent(obj);
    }
    if (obj && x && y) {
        lv_area_t area;
        lv_obj_get_coords(obj, &area);
        *x = (area.x1 + area.x2) / 2;
        *y = (area.y1 + area.y2) / 2;
    }
    bsp_display_unlock();
    return obj != NULL;
}

bool ui_has_text(const char *text) {
    bsp_display_lock(0);
    bool found = find_label(lv_screen_active(), text) != NULL;
    bsp_display_unlock();
    return found;
}

bool ui_tap_text(const char *text) {
    int x, y;
    if (!ui_find_text(text, &x, &y)) {
        return false;
    }
    ui_tap(x, y);
    return true;
}

int ui_screenshot(const char *path) {
    static uint8_t rgb[HEIGHT][WIDTH][3];
    bsp_display_lock(0);
    lv_obj_invalidate(lv_screen_active());
    lv_refr_now(NULL);
    for (int y = 0; y < HEIGHT; y++) {
        for (int x = 0; x < WIDTH; x++) {
            uint16_t p = framebuffer[y][x];
            rgb[y][x][0] = (uint8_t)((p >> 11) << 3);
            rgb[y][x][1] = (uint8_t)(((p >> 5) & 0x3f) << 2);
            rgb[y][x][2] = (uint8_t)((p & 0x1f) << 3);
        }
    }
    bsp_display_unlock();

    unsigned char *png = NULL;
    size_t png_len = 0;
    if (lodepng_encode24(&png, &png_len, &rgb[0][0][0], WIDTH, HEIGHT) != 0) {
        return -1;
    }
    FILE *f = fopen(path, "wb");
    int ret = f && fwrite(png, 1, png_len, f) == png_len ? 0 : -1;
    if (f) {
        fclose(f);
    }
    lv_free(png);
    return ret;
}

struct ui_call {
    pthread_t thread;
    void *(*fn)(void *);
    void *arg;
    void *result;
    volatile bool done;
};

static void *call_main(void *p) {
    ui_call_t *call = p;
    call->result = call->fn(call->arg);
    call->done = true;
    return NULL;
}

ui_call_t *ui_call_start(void *(*fn)(void *), void *arg) {
    ui_call_t *call = calloc(1, sizeof(*call));
    call->fn = fn;
    call->arg = arg;
    pthread_create(&call->thread, NULL, call_main, call);
    return call;
}

bool ui_call_done(void *call) {
    return ((ui_call_t *)call)->done;
}

void *ui_call_join(ui_call_t *call) {
    pthread_join(call->thread, NULL);
    void *result = call->result;
    free(call);
    return result;
}
