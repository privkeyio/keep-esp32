// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Signing under a BIP-32 unhardened path, as keep does it
//! (`keep_core::frost::bip32_signing`): one composite tweak, derived publicly
//! from the group's x-only key and keep's deterministic chain code, is added to
//! the signing share, the verifying share and the group key. Checked byte for
//! byte against vectors produced by keep v0.10.0 (`vectors/bip32.json`).

use frost_secp256k1_tr as frost;
use frost::keys::{KeyPackage, SigningShare, VerifyingShare};
use frost::VerifyingKey;
use k256::elliptic_curve::group::{Group, GroupEncoding};
use k256::elliptic_curve::ff::PrimeField;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

use crate::signer::E_PATH;

/// keep's limit on a signing request's path (`MAX_DERIVATION_PATH_DEPTH`).
pub const MAX_DEPTH: usize = 8;
pub const HARDENED: u32 = 0x8000_0000;
const CHAINCODE_DOMAIN: &[u8] = b"keep-frost-bip32-chaincode-v1";

fn hmac_sha512(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 64] {
    let mut ipad = [0x36u8; 128];
    let mut opad = [0x5cu8; 128];
    for (i, k) in key.iter().enumerate() {
        ipad[i] ^= k;
        opad[i] ^= k;
    }
    let mut inner = Sha512::new();
    inner.update(ipad);
    for p in parts {
        inner.update(p);
    }
    let inner = inner.finalize();
    let mut outer = Sha512::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

fn point(compressed: &[u8]) -> Option<ProjectivePoint> {
    let bytes: [u8; 33] = compressed.try_into().ok()?;
    Option::<AffinePoint>::from(AffinePoint::from_bytes(&bytes.into())).map(ProjectivePoint::from)
}

fn compressed(p: &ProjectivePoint) -> Option<[u8; 33]> {
    if bool::from(p.is_identity()) {
        return None;
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(&p.to_affine().to_bytes());
    Some(out)
}

fn scalar(bytes: &[u8; 32]) -> Option<Scalar> {
    Option::from(Scalar::from_repr((*bytes).into()))
}

/// The composite tweak for `path` from the group's x-only key, refusing what
/// keep refuses: hardened or too many indexes, a step tweak at or above the
/// curve order, a zero first tweak or running sum, an infinite child point.
pub fn aggregate_tweak(group_xonly: &[u8; 32], path: &[u32]) -> Result<Scalar, i32> {
    if path.is_empty() || path.len() > MAX_DEPTH || path.iter().any(|&i| i >= HARDENED) {
        return Err(E_PATH);
    }
    let mut lift = [0x02u8; 33];
    lift[1..].copy_from_slice(group_xonly);
    let root = point(&lift).ok_or(E_PATH)?;
    let mut parent = root;
    let mut chaincode: [u8; 32] = Sha256::new().chain_update(CHAINCODE_DOMAIN).chain_update(group_xonly).finalize().into();
    let mut acc = Scalar::ZERO;
    for (step, &index) in path.iter().enumerate() {
        let i = hmac_sha512(&chaincode, &[&compressed(&parent).ok_or(E_PATH)?, &index.to_be_bytes()]);
        let t = scalar(i[..32].try_into().map_err(|_| E_PATH)?).ok_or(E_PATH)?;
        if step == 0 && bool::from(t.is_zero()) {
            return Err(E_PATH);
        }
        parent += ProjectivePoint::GENERATOR * t;
        if compressed(&parent).is_none() {
            return Err(E_PATH);
        }
        acc += t;
        if bool::from(acc.is_zero()) {
            return Err(E_PATH);
        }
        chaincode.copy_from_slice(&i[32..]);
    }
    if root + ProjectivePoint::GENERATOR * acc != parent {
        return Err(E_PATH);
    }
    Ok(acc)
}

/// `kp` tweaked for `path`. The tweak is negated for an odd-y group key, so
/// the tweaked key has the x coordinate wallets derive for the even lift.
pub fn tweak(kp: &KeyPackage, path: &[u32]) -> Result<KeyPackage, i32> {
    let vk = kp.verifying_key().serialize().map_err(|_| E_PATH)?;
    let group_xonly: [u8; 32] = vk.get(1..33).and_then(|x| x.try_into().ok()).ok_or(E_PATH)?;
    let mut t = aggregate_tweak(&group_xonly, path)?;
    if vk[0] == 0x03 {
        t = -t;
    }
    let tg = ProjectivePoint::GENERATOR * t;

    let shift = |encoded: &[u8]| -> Result<[u8; 33], i32> { compressed(&(point(encoded).ok_or(E_PATH)? + tg)).ok_or(E_PATH) };
    let vs = kp.verifying_share().serialize().map_err(|_| E_PATH)?;
    let tweaked_vs = VerifyingShare::deserialize(&shift(&vs)?).map_err(|_| E_PATH)?;
    let tweaked_vk = VerifyingKey::deserialize(&shift(&vk)?).map_err(|_| E_PATH)?;

    // The buffers this function owns that hold the share, or the tweaked share
    // (equivalent, as the tweak is public), are wiped here, including the heap
    // copy. Copies made by value inside the scalar and frost-core calls are not;
    // the signing task's stack refill clears those, so this runs only there.
    let mut share_bytes = kp.signing_share().serialize();
    let mut share_arr = [0u8; 32];
    let ok = share_bytes.len() == 32;
    if ok {
        share_arr.copy_from_slice(&share_bytes);
    }
    share_bytes.zeroize();
    let mut share = if ok { scalar(&share_arr) } else { None };
    share_arr.zeroize();
    let mut sum = share.map(|s| s + t);
    share.zeroize();
    let Some(mut sum_scalar) = sum.take() else { return Err(E_PATH) };
    let mut sum_bytes: [u8; 32] = sum_scalar.to_repr().into();
    let zero = bool::from(sum_scalar.is_zero());
    sum_scalar.zeroize();
    let tweaked_share = if zero { Err(E_PATH) } else { SigningShare::deserialize(&sum_bytes).map_err(|_| E_PATH) };
    sum_bytes.zeroize();
    Ok(KeyPackage::new(*kp.identifier(), tweaked_share?, tweaked_vs, tweaked_vk, *kp.min_signers()))
}
