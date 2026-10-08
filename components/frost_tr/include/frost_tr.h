// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

// FROST(secp256k1, SHA-256, Taproot): the Zcash Foundation's frost-secp256k1-tr
// 3.0.0, the implementation the keep host uses, built from rust/ into
// lib/libfrost_tr.a by scripts/build-frost-tr.sh.

#ifndef FROST_TR_H
#define FROST_TR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FTR_KEY_PACKAGE_MAX     256
#define FTR_NONCES_LEN          64
#define FTR_COMMITMENTS_LEN     71
#define FTR_SIGNATURE_SHARE_LEN 32
#define FTR_MESSAGE_LEN         32
#define FTR_MAX_SIGNERS         16
#define FTR_SIGNING_PACKAGE_MAX 1687
#define FTR_MAX_PATH_DEPTH      8
#define FTR_KFP_MAX_PLAINTEXT   65408

// Status codes of the key package and signing calls (see rust/src/signer.rs).
#define FTR_OK                 0
#define FTR_E_NULL             -1
#define FTR_E_LENGTH           -2
#define FTR_E_DESERIALIZE      -3
#define FTR_E_NONCANONICAL     -4
#define FTR_E_SHARE_MISMATCH   -5
#define FTR_E_IDENTIFIER       -6
#define FTR_E_THRESHOLD        -7
#define FTR_E_MESSAGE          -8
#define FTR_E_COMMITMENT_COUNT -9
#define FTR_E_OWN_COMMITMENT   -10
#define FTR_E_NONCES           -11
#define FTR_E_SIGN             -12
#define FTR_E_SELFCHECK        -13
#define FTR_E_PATH             -14
#define FTR_E_TWEAK            -15
#define FTR_E_KEY              -16
#define FTR_E_DECRYPT          -17
#define FTR_E_CAPACITY         -18

typedef struct {
    uint16_t index;
    uint16_t min_signers;
    uint8_t verifying_share[33];
    uint8_t group_key[33];
} ftr_key_info_t;
_Static_assert(sizeof(ftr_key_info_t) == 70, "ftr_key_info_t must match FtrKeyInfo in lib.rs");

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

// Validates a frost-core KeyPackage serialization: canonical encoding, the
// verifying share matches the signing share, identifier 1..16, min_signers
// 2..16. Fills `out` on success.
int ftr_key_package_import(const uint8_t *kp, size_t kp_len, ftr_key_info_t *out);

// Rebuilds the KeyPackage behind a 102- or 104-byte share stored before
// protocol 2 and validates it as ftr_key_package_import does.
int ftr_key_package_from_legacy(const uint8_t *legacy, size_t legacy_len,
                                uint8_t out_kp[FTR_KEY_PACKAGE_MAX], size_t *out_len,
                                uint16_t *out_participants);

// Draws fresh signing nonces and their SigningCommitments serialization. The
// nonces are secret, must stay in RAM, and must reach exactly one ftr_sign.
int ftr_commit(const uint8_t *kp, size_t kp_len, uint8_t out_nonces[FTR_NONCES_LEN],
               uint8_t out_commitments[FTR_COMMITMENTS_LEN]);

// Produces this signer's SignatureShare for a SigningPackage serialization.
// Refuses unless the package is canonical, carries `expected_message`, holds
// min_signers..16 commitments including this signer's own unaltered one, and
// the share verifies. With a non-empty `path` (up to FTR_MAX_PATH_DEPTH
// unhardened indexes) it signs under the BIP-32 child key keep derives from
// the group key. With `taproot` it then signs under the BIP-341 output key of
// a key-path spend, committing to the 32-byte `merkle_root` or, when it is
// NULL, to no script tree; a `merkle_root` without `taproot` is refused.
// `nonces` is zeroed on every path.
int ftr_sign(const uint8_t *kp, size_t kp_len, uint8_t nonces[FTR_NONCES_LEN],
             const uint8_t *signing_package, size_t signing_package_len,
             const uint8_t expected_message[FTR_MESSAGE_LEN], const uint32_t *path, size_t path_len,
             bool taproot, const uint8_t *merkle_root, uint8_t out_share[FTR_SIGNATURE_SHARE_LEN]);

// KFP v2 (keep-frost-net), with the transport key derived inside from the key
// package, so it never leaves the device and no caller supplies it.

// The x-only transport public key keep derives from the key package.
int ftr_kfp_transport_pubkey(const uint8_t *kp, size_t kp_len, uint8_t out[32]);

// The announce proof binding this key package's transport key at `timestamp`.
int ftr_kfp_announce_proof(const uint8_t *kp, size_t kp_len, uint64_t timestamp, uint8_t out[64]);

// The rendezvous address keep announces to for member `index` of `group`.
int ftr_kfp_rendezvous(const uint8_t group[32], uint16_t index, uint8_t out[32]);

// NIP-44 v2 from the transport key to the x-only `recipient`: a base64 payload
// of up to `cap` bytes, not NUL-terminated. Plaintext is 1..FTR_KFP_MAX_PLAINTEXT.
int ftr_kfp_seal(const uint8_t *kp, size_t kp_len, const uint8_t recipient[32],
                 const uint8_t *plaintext, size_t plaintext_len, uint8_t *out, size_t cap,
                 size_t *out_len);

// Opens a NIP-44 v2 base64 payload the x-only `sender` sealed to the transport
// key. Writes nothing unless the MAC verifies; the caller wipes `out` after use.
int ftr_kfp_open(const uint8_t *kp, size_t kp_len, const uint8_t sender[32], const uint8_t *payload,
                 size_t payload_len, uint8_t *out, size_t cap, size_t *out_len);

// The NIP-01 id of a serialized event built by the firmware
// (`[0,pubkey,created_at,kind,tags,content]`) and its BIP-340 signature by the
// transport key. Never to be called with bytes a host chose.
int ftr_kfp_sign_event(const uint8_t *kp, size_t kp_len, const uint8_t *serialized,
                       size_t serialized_len, uint8_t out_id[32], uint8_t out_sig[64]);

// keep's salted session id (BLAKE2b-512, first 32 bytes) for a sign request.
int ftr_kfp_session_id(const uint8_t *message, size_t message_len, const uint16_t *participants,
                       size_t participants_len, uint16_t threshold, const uint8_t *salt,
                       size_t salt_len, uint8_t out[32]);

// 1 when `salt` binds the request's path and taproot tweak, 0 when it does not,
// or a negative error code.
int ftr_kfp_salt_binds(const uint8_t *salt, size_t salt_len, const uint32_t *path, size_t path_len,
                       bool taproot, const uint8_t *merkle_root);

#ifdef __cplusplus
}
#endif

#endif
