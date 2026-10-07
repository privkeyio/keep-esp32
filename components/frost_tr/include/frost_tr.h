// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

// FROST(secp256k1, SHA-256, Taproot): the Zcash Foundation's frost-secp256k1-tr
// 3.0.0, the implementation the keep host uses, built from rust/ into
// lib/libfrost_tr.a by scripts/build-frost-tr.sh.

#ifndef FROST_TR_H
#define FROST_TR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Fills `buf` with `len` health-checked random bytes; returns 0 on success.
typedef int (*ftr_rng_fill_fn)(uint8_t *buf, size_t len);
// Returns SECRESULT_TRUE while the RNG is healthy.
typedef uint32_t (*ftr_rng_healthy_fn)(void);

// Registers the firmware RNG. Call once at boot before any other ftr_ call.
// Returns 0, or -1 if either pointer is NULL or an RNG is already registered.
// Any later RNG failure inside frost_tr resets the device: FROST nonces must
// never be drawn from a failed source.
int ftr_init(ftr_rng_fill_fn fill, ftr_rng_healthy_fn healthy);

// Boot self-test: heap alignment, the ZF test vectors byte for byte, and that
// the RNG is registered and healthy. Returns 0, or the code of the first failed
// check (see rust/src/selftest.rs).
int ftr_selftest(void);

#ifdef __cplusplus
}
#endif

#endif
