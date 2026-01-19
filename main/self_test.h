#ifndef SELF_TEST_H
#define SELF_TEST_H

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    SELF_TEST_STORAGE_CRYPTO,
    SELF_TEST_CRYPTO_LIB,
    SELF_TEST_FLASH_PARTITIONS,
    SELF_TEST_STORAGE_SLOTS,
    SELF_TEST_COUNT
} self_test_id_t;

typedef struct {
    self_test_id_t id;
    const char *name;
    int (*run)(void);
    bool required;
} self_test_t;

typedef struct {
    uint32_t passed;
    uint32_t failed;
    uint32_t skipped;
    uint32_t results;
    bool all_required_passed;
} self_test_stats_t;

int self_test_run_all(void);
void self_test_get_stats(self_test_stats_t *stats);

int self_test_storage_crypto(void);
int self_test_crypto_lib(void);
int self_test_flash_partitions(void);
int self_test_storage_slots(void);

#endif
