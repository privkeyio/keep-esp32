#ifndef ANTI_GLITCH_H
#define ANTI_GLITCH_H

#include <stdint.h>
#include <stdbool.h>
#include "secresult.h"

#define AG_DELAY_MIN_US      10000
#define AG_DELAY_MAX_US      100000
#define AG_BOOT_DELAY_MIN_MS 10
#define AG_BOOT_DELAY_MAX_MS 100
#define AG_MIN_OP_CYCLES     1000

int ag_init(void);
void ag_random_delay_us(uint32_t min_us, uint32_t max_us);
void ag_random_delay_ms(uint32_t min_ms, uint32_t max_ms);
int ag_increment_boot_counter(void);
int ag_get_boot_counter(uint32_t *value);
uint32_t ag_get_cycle_count(void);
bool ag_check_min_cycles(uint32_t start, uint32_t min_cycles);

secresult_t ag_verify_condition_secure(secresult_t condition);

#endif
