#ifndef HW_ENTROPY_H
#define HW_ENTROPY_H

#include <stdint.h>
#include <stddef.h>

int hw_entropy_init(void);
int hw_entropy_fill(uint8_t *buf, size_t len);

#endif
