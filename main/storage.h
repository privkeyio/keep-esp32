#ifndef STORAGE_H
#define STORAGE_H

#include <stddef.h>
#include <stdbool.h>

#define STORAGE_MAX_SHARES 8
#define STORAGE_GROUP_LEN 64
#define STORAGE_SHARE_LEN 256

#define STORAGE_OK 0
#define STORAGE_ERR_NOT_INIT -1
#define STORAGE_ERR_CRYPTO_NOT_INIT -2
#define STORAGE_ERR_INVALID_GROUP -3
#define STORAGE_ERR_INVALID_DATA -4
#define STORAGE_ERR_NO_SLOT -5
#define STORAGE_ERR_IO -6
#define STORAGE_ERR_NOT_FOUND -7
#define STORAGE_ERR_DECRYPT -8

int storage_init(void);
int storage_save_share(const char *group, const char *share_hex);
int storage_load_share(const char *group, char *share_hex, size_t len);
int storage_delete_share(const char *group);
int storage_list_shares(char groups[][STORAGE_GROUP_LEN + 1], int max_groups);
bool storage_has_share(const char *group);

#endif
