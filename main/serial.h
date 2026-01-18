// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef SERIAL_H
#define SERIAL_H

#include <stddef.h>

int serial_init(void);
int serial_read_line(char *buf, size_t len);
int serial_write_line(const char *buf);

#endif
