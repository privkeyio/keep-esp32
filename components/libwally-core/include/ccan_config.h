#ifndef _WALLY_CCAN_CONFIG_H_
#define _WALLY_CCAN_CONFIG_H_ 1

#include <stddef.h>

#define HAVE_BIG_ENDIAN    0
#define HAVE_LITTLE_ENDIAN 1

#define HAVE_ATTRIBUTE_COLD     1
#define HAVE_ATTRIBUTE_NORETURN 1
#define HAVE_ATTRIBUTE_PRINTF   1
#define HAVE_ATTRIBUTE_CONST    1
#define HAVE_ATTRIBUTE_PURE     1
#define HAVE_ATTRIBUTE_UNUSED   1
#define HAVE_ATTRIBUTE_USED     1
#define HAVE_BUILTIN_CONSTANT_P 1
#define HAVE_WARN_UNUSED_RESULT 1

#define HAVE_BYTESWAP_H 0
#define HAVE_BSWAP_64   0

#define alignment_ok(p, n) ((size_t)(p) % (n) == 0)

#define CCAN_CRYPTO_SHA256_USE_MBEDTLS 1
#define CCAN_CRYPTO_SHA512_USE_MBEDTLS 1

void wally_clear(void *p, size_t len);
#define CCAN_CLEAR_MEMORY(p, len) wally_clear(p, len)

#endif
