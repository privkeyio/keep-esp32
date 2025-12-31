#ifndef CRYPTO_ASM_H
#define CRYPTO_ASM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Constant-time cryptographic primitives (Xtensa assembly).
 * All functions execute in data-independent time. Null pointers are undefined.
 *
 * ct_compare:      Returns 0 if equal, non-zero if different.
 * ct_is_zero:      Returns 1 if all bytes are zero, 0 otherwise.
 * ct_select*:      condition==0 selects a; condition!=0 selects b.
 * ct_cswap32:      Swaps *a and *b iff condition!=0.
 * ct_select_bytes: out may alias a or b.
 */
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
