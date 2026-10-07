// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Boot self-test: heap alignment, the ZF test vectors byte for byte, and that
//! the firmware RNG is registered. Each failing check returns its own code so a
//! failure on a device can be traced to the exact step.


use alloc::collections::BTreeMap;

use frost_secp256k1_tr as frost;
use frost::keys::{KeyPackage, PublicKeyPackage, SigningShare, VerifyingShare};
use frost::round1::SigningNonces;
use frost::{Identifier, SigningPackage, VerifyingKey};

use crate::rng::registered;
use crate::vectors::{MESSAGE, MIN_SIGNERS, PARTICIPANTS, SIGNATURE, VERIFYING_KEY};

type Nonce = frost_core::round1::Nonce<frost::Secp256K1Sha256TR>;

pub const OK: i32 = 0;
pub const E_VERIFYING_KEY: i32 = 1;
pub const E_IDENTIFIER: i32 = 2;
pub const E_SHARE: i32 = 3;
pub const E_NONCE: i32 = 4;
pub const E_COMMITMENT: i32 = 5;
pub const E_SIGN: i32 = 6;
pub const E_SIGNATURE_SHARE: i32 = 7;
pub const E_AGGREGATE: i32 = 8;
pub const E_SIGNATURE: i32 = 9;
pub const E_VERIFY: i32 = 10;
pub const E_RNG_UNREGISTERED: i32 = 11;
pub const E_ALIGNMENT: i32 = 13;

pub fn vectors() -> i32 {
    let Ok(vk) = VerifyingKey::deserialize(&VERIFYING_KEY) else {
        return E_VERIFYING_KEY;
    };
    let mut commitments = BTreeMap::new();
    let mut nonces = BTreeMap::new();
    let mut key_packages = BTreeMap::new();
    let mut verifying_shares = BTreeMap::new();
    for p in PARTICIPANTS {
        let Ok(id) = Identifier::try_from(p.identifier) else {
            return E_IDENTIFIER;
        };
        let Ok(share) = SigningShare::deserialize(&p.signing_share) else {
            return E_SHARE;
        };
        let vs = VerifyingShare::from(share);
        verifying_shares.insert(id, vs);
        key_packages.insert(id, KeyPackage::new(id, share, vs, vk, MIN_SIGNERS));
        let (Ok(h), Ok(b)) = (Nonce::deserialize(&p.hiding_nonce), Nonce::deserialize(&p.binding_nonce)) else {
            return E_NONCE;
        };
        let n = SigningNonces::from_nonces(h, b);
        let c = *n.commitments();
        match (c.hiding().serialize(), c.binding().serialize()) {
            (Ok(hs), Ok(bs)) if hs[..] == p.hiding_commitment[..] && bs[..] == p.binding_commitment[..] => {}
            _ => return E_COMMITMENT,
        }
        commitments.insert(id, c);
        nonces.insert(id, n);
    }
    let package = SigningPackage::new(commitments, MESSAGE);
    let mut shares = BTreeMap::new();
    for p in PARTICIPANTS {
        let Ok(id) = Identifier::try_from(p.identifier) else {
            return E_IDENTIFIER;
        };
        let Ok(share) = frost::round2::sign(&package, &nonces[&id], &key_packages[&id]) else {
            return E_SIGN;
        };
        if share.serialize()[..] != p.signature_share[..] {
            return E_SIGNATURE_SHARE;
        }
        shares.insert(id, share);
    }
    let pubkeys = PublicKeyPackage::new(verifying_shares, vk, Some(MIN_SIGNERS));
    let Ok(sig) = frost::aggregate(&package, &shares, &pubkeys) else {
        return E_AGGREGATE;
    };
    match sig.serialize() {
        Ok(s) if s[..] == SIGNATURE[..] => {}
        _ => return E_SIGNATURE,
    }
    if vk.verify(MESSAGE, &sig).is_err() {
        return E_VERIFY;
    }
    OK
}

pub fn rng_registered() -> i32 {
    if registered() {
        OK
    } else {
        E_RNG_UNREGISTERED
    }
}

/// A heap allocation with alignment above the IDF heap's 4-byte guarantee
/// must come back aligned.
pub fn alignment() -> i32 {
    #[repr(align(16))]
    struct Aligned([u8; 48]);
    let b = alloc::boxed::Box::new(Aligned([0x5a; 48]));
    let addr = &*b as *const Aligned as usize;
    if addr % 16 != 0 || b.0[47] != 0x5a {
        return E_ALIGNMENT;
    }
    OK
}

pub fn run() -> i32 {
    for check in [alignment as fn() -> i32, vectors, rng_registered] {
        let r = check();
        if r != OK {
            return r;
        }
    }
    OK
}
