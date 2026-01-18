// SPDX-FileCopyrightText: © 2026 Privkey Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

#include <stddef.h>

void wally_clear(void *p, size_t len) {
    if (!p || len == 0) {
        return;
    }
    volatile unsigned char *ptr = (volatile unsigned char *)p;
    while (len--) {
        *ptr++ = 0;
    }
}
