#ifndef SERIAL_H
#define SERIAL_H

#include <stddef.h>

void serial_init(void);
int serial_read_line(char *buf, size_t len);
int serial_write_line(const char *buf);

#endif
