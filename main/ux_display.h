// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef UX_DISPLAY_H
#define UX_DISPLAY_H

#include "ux_interface.h"

typedef enum {
    UI_STATE_IDLE,
    UI_STATE_SCANNING,
    UI_STATE_CONFIRM_TX,
    UI_STATE_SIGNING,
    UI_STATE_SHOW_QR,
    UI_STATE_ERROR,
    UI_STATE_SUCCESS,
} ui_state_t;

ui_state_t ui_get_state(void);

extern const ux_backend_t ux_display_backend;

#endif
