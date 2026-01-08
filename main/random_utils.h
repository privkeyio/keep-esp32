#ifndef RANDOM_UTILS_H
#define RANDOM_UTILS_H

#include <stdint.h>
#include <stddef.h>

int secure_random_fill(uint8_t *buf, size_t len);

#endif
