// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

/* Mirrors the firmware's CONFIG_LV_* values so screens render as they do on the device. */
#ifndef LV_CONF_H
#define LV_CONF_H

#define LV_COLOR_DEPTH        16
#define LV_DPI_DEF            130
#define LV_DEF_REFR_PERIOD    33
#define LV_USE_OS             LV_OS_NONE
#define LV_USE_STDLIB_MALLOC  LV_STDLIB_CLIB
#define LV_USE_STDLIB_STRING  LV_STDLIB_CLIB
#define LV_USE_STDLIB_SPRINTF LV_STDLIB_CLIB

#define LV_FONT_MONTSERRAT_12 1
#define LV_FONT_MONTSERRAT_14 1
#define LV_FONT_MONTSERRAT_16 1
#define LV_FONT_MONTSERRAT_24 1
#define LV_FONT_MONTSERRAT_32 1

#define LV_USE_THEME_DEFAULT             1
#define LV_THEME_DEFAULT_GROW            1
#define LV_THEME_DEFAULT_TRANSITION_TIME 80
#define LV_USE_QRCODE                    1
#define LV_USE_LODEPNG                   1

#define LV_USE_LOG        1
#define LV_LOG_LEVEL      LV_LOG_LEVEL_WARN
#define LV_LOG_PRINTF     1
#define LV_USE_ASSERT_OBJ 1

#endif
