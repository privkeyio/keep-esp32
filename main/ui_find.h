// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

#ifndef UI_FIND_H
#define UI_FIND_H

#include "lvgl.h"
#include <stdbool.h>
#include <string.h>

/* Shared by the device test hook and the host UI harness, so both aim taps the same way.
 * Call with the display lock held. */

static inline lv_obj_t *ui_find_label(lv_obj_t *obj, const char *text) {
    if (lv_obj_has_flag(obj, LV_OBJ_FLAG_HIDDEN)) {
        return NULL;
    }
    if (lv_obj_check_type(obj, &lv_label_class) && strcmp(lv_label_get_text(obj), text) == 0) {
        return obj;
    }
    for (uint32_t i = 0; i < lv_obj_get_child_count(obj); i++) {
        lv_obj_t *found = ui_find_label(lv_obj_get_child(obj, (int32_t)i), text);
        if (found) {
            return found;
        }
    }
    return NULL;
}

/* The center of the clickable object a label belongs to, as a finger would aim. */
static inline bool ui_find_clickable(const char *text, int32_t *x, int32_t *y) {
    lv_obj_update_layout(lv_screen_active());
    lv_obj_t *obj = ui_find_label(lv_screen_active(), text);
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

#endif
