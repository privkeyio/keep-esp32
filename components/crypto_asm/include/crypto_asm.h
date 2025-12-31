#ifndef CRYPTO_ASM_H
#define CRYPTO_ASM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void secure_memzero(void *ptr, size_t len);
int ct_compare(const void *a, const void *b, size_t len);
int ct_is_zero(const void *ptr, size_t len);
uint32_t ct_select32(uint32_t a, uint32_t b, uint32_t condition);
void ct_select_bytes(void *out, const void *a, const void *b, size_t len, uint32_t condition);
void ct_cswap32(uint32_t *a, uint32_t *b, uint32_t condition);

#ifdef __cplusplus
}
#endif

#endif
