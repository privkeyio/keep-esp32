// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Key package import, commit and sign over frost-core serialization, the
//! formats keep stores and sends. Every input is checked to be the canonical
//! encoding of what it claims to be before it is used.

use frost_secp256k1_tr as frost;
use frost::keys::{KeyPackage, SigningShare, VerifyingShare};
use frost::round1::SigningNonces;
use frost::{Identifier, SigningPackage, VerifyingKey};
use zeroize::Zeroize;

use crate::rng::DeviceRng;

type Nonce = frost_core::round1::Nonce<frost::Secp256K1Sha256TR>;

pub const KEY_PACKAGE_MAX: usize = 256;
pub const NONCES_LEN: usize = 64;
pub const COMMITMENTS_LEN: usize = 71;
pub const SIGNATURE_SHARE_LEN: usize = 32;
pub const MESSAGE_LEN: usize = 32;
pub const MAX_SIGNERS: u16 = 16;
/// Header 5, one-byte map length, 16 × (identifier 32 + commitments 71),
/// one-byte message length, message 32.
pub const SIGNING_PACKAGE_MAX: usize = 5 + 1 + MAX_SIGNERS as usize * (32 + COMMITMENTS_LEN) + 1 + MESSAGE_LEN;

pub const E_NULL: i32 = -1;
pub const E_LENGTH: i32 = -2;
pub const E_DESERIALIZE: i32 = -3;
pub const E_NONCANONICAL: i32 = -4;
pub const E_SHARE_MISMATCH: i32 = -5;
pub const E_IDENTIFIER: i32 = -6;
pub const E_THRESHOLD: i32 = -7;
pub const E_MESSAGE: i32 = -8;
pub const E_COMMITMENT_COUNT: i32 = -9;
pub const E_OWN_COMMITMENT: i32 = -10;
pub const E_NONCES: i32 = -11;
pub const E_SIGN: i32 = -12;
pub const E_SELFCHECK: i32 = -13;
pub const E_PATH: i32 = -14;

pub struct KeyInfo {
    pub index: u16,
    pub min_signers: u16,
    pub verifying_share: [u8; 33],
    pub group_key: [u8; 33],
}

/// The participant index an identifier stands for, if it is a nonzero u16:
/// the device and keep both number participants 1..=n.
pub fn identifier_index(id: &Identifier) -> Option<u16> {
    let bytes = id.serialize();
    if bytes.len() != 32 || bytes[..30].iter().any(|b| *b != 0) {
        return None;
    }
    match u16::from_be_bytes([bytes[30], bytes[31]]) {
        0 => None,
        i => Some(i),
    }
}

/// Parses a key package and checks it is canonical and self-consistent.
pub fn load(bytes: &[u8]) -> Result<KeyPackage, i32> {
    if bytes.is_empty() || bytes.len() > KEY_PACKAGE_MAX {
        return Err(E_LENGTH);
    }
    let kp = KeyPackage::deserialize(bytes).map_err(|_| E_DESERIALIZE)?;
    let mut again = kp.serialize().map_err(|_| E_DESERIALIZE)?;
    let canonical = again[..] == bytes[..];
    again.zeroize();
    if !canonical {
        return Err(E_NONCANONICAL);
    }
    if VerifyingShare::from(*kp.signing_share()) != *kp.verifying_share() {
        return Err(E_SHARE_MISMATCH);
    }
    let index = identifier_index(kp.identifier()).ok_or(E_IDENTIFIER)?;
    if *kp.min_signers() < 2 || *kp.min_signers() > MAX_SIGNERS || index > MAX_SIGNERS {
        return Err(E_THRESHOLD);
    }
    Ok(kp)
}

pub fn import(bytes: &[u8]) -> Result<KeyInfo, i32> {
    let kp = load(bytes)?;
    let vs = kp.verifying_share().serialize().map_err(|_| E_DESERIALIZE)?;
    let vk = kp.verifying_key().serialize().map_err(|_| E_DESERIALIZE)?;
    let (Ok(verifying_share), Ok(group_key)) = (<[u8; 33]>::try_from(&vs[..]), <[u8; 33]>::try_from(&vk[..])) else {
        return Err(E_DESERIALIZE);
    };
    Ok(KeyInfo {
        index: identifier_index(kp.identifier()).ok_or(E_IDENTIFIER)?,
        min_signers: *kp.min_signers(),
        verifying_share,
        group_key,
    })
}

/// Rebuilds the key package behind a share stored by firmware before
/// protocol 2: `secret 32 | verifying share 33 | group key 33 | index u16 LE |
/// participants u16 LE | min_signers u16 LE`, the last field absent (meaning
/// 2) in the 102-byte form. keep wrote every field from its own key package,
/// so the rebuilt package is the one keep holds; it must pass `load`.
/// Returns the serialized package and the participant count.
pub fn from_legacy(bytes: &[u8], out: &mut [u8; KEY_PACKAGE_MAX]) -> Result<(usize, u16), i32> {
    if bytes.len() != 102 && bytes.len() != 104 {
        return Err(E_LENGTH);
    }
    let le = |i: usize| u16::from_le_bytes([bytes[i], bytes[i + 1]]);
    let (index, participants) = (le(98), le(100));
    let min_signers = if bytes.len() == 104 { le(102) } else { 2 };
    if index == 0 || index > participants || participants > MAX_SIGNERS || min_signers > participants {
        return Err(E_THRESHOLD);
    }
    let id = Identifier::try_from(index).map_err(|_| E_IDENTIFIER)?;
    let share = SigningShare::deserialize(&bytes[..32]).map_err(|_| E_DESERIALIZE)?;
    let vs = VerifyingShare::deserialize(&bytes[32..65]).map_err(|_| E_DESERIALIZE)?;
    let vk = VerifyingKey::deserialize(&bytes[65..98]).map_err(|_| E_DESERIALIZE)?;
    let mut kp = KeyPackage::new(id, share, vs, vk, min_signers).serialize().map_err(|_| E_DESERIALIZE)?;
    let result = match load(&kp) {
        Ok(_) if kp.len() <= KEY_PACKAGE_MAX => {
            out[..kp.len()].copy_from_slice(&kp);
            Ok((kp.len(), participants))
        }
        Ok(_) => Err(E_LENGTH),
        Err(e) => Err(e),
    };
    kp.zeroize();
    result
}

/// Draws fresh nonces. They are returned to the caller to hold in RAM until
/// the matching `sign`, and must never be written to flash.
pub fn commit(kp_bytes: &[u8], nonces_out: &mut [u8; NONCES_LEN], commitments_out: &mut [u8; COMMITMENTS_LEN]) -> Result<(), i32> {
    let kp = load(kp_bytes)?;
    let (nonces, commitments) = frost::round1::commit(kp.signing_share(), &mut DeviceRng);
    let c = commitments.serialize().map_err(|_| E_DESERIALIZE)?;
    if c.len() != COMMITMENTS_LEN {
        return Err(E_LENGTH);
    }
    let mut h = nonces.hiding().serialize();
    let mut b = nonces.binding().serialize();
    let ok = h.len() == 32 && b.len() == 32;
    if ok {
        nonces_out[..32].copy_from_slice(&h);
        nonces_out[32..].copy_from_slice(&b);
        commitments_out.copy_from_slice(&c);
    }
    h.zeroize();
    b.zeroize();
    if ok {
        Ok(())
    } else {
        Err(E_LENGTH)
    }
}

fn nonces_from(bytes: &[u8; NONCES_LEN]) -> Result<SigningNonces, i32> {
    if bytes.iter().all(|b| *b == 0) {
        return Err(E_NONCES);
    }
    let mut h = Nonce::deserialize(&bytes[..32]).map_err(|_| E_NONCES)?;
    let Ok(mut b) = Nonce::deserialize(&bytes[32..]) else {
        h.zeroize();
        return Err(E_NONCES);
    };
    let n = SigningNonces::from_nonces(h, b);
    h.zeroize();
    b.zeroize();
    Ok(n)
}

/// Produces this signer's share for `package`, which must carry exactly the
/// message approved at commit, under the key derived for `path` (none when
/// empty). `nonces` is wiped before anything else, so the same nonces can
/// never sign twice, whatever the outcome.
pub fn sign(
    kp_bytes: &[u8],
    nonces: &mut [u8; NONCES_LEN],
    package: &[u8],
    expected_message: &[u8; MESSAGE_LEN],
    path: &[u32],
    share_out: &mut [u8; SIGNATURE_SHARE_LEN],
) -> Result<(), i32> {
    let mut local = *nonces;
    unsafe { crate::glue::wipe(nonces.as_mut_ptr(), NONCES_LEN) };
    let result = sign_with(kp_bytes, &local, package, expected_message, path, share_out);
    local.zeroize();
    result
}

fn sign_with(
    kp_bytes: &[u8],
    nonces: &[u8; NONCES_LEN],
    package: &[u8],
    expected_message: &[u8; MESSAGE_LEN],
    path: &[u32],
    share_out: &mut [u8; SIGNATURE_SHARE_LEN],
) -> Result<(), i32> {
    let signer_nonces = nonces_from(nonces)?;
    let kp = load(kp_bytes)?;
    let kp = if path.is_empty() { kp } else { crate::bip32::tweak(&kp, path)? };
    if package.is_empty() || package.len() > SIGNING_PACKAGE_MAX {
        return Err(E_LENGTH);
    }
    let sp = SigningPackage::deserialize(package).map_err(|_| E_DESERIALIZE)?;
    if sp.serialize().map_err(|_| E_DESERIALIZE)?[..] != package[..] {
        return Err(E_NONCANONICAL);
    }
    if sp.message()[..] != expected_message[..] {
        return Err(E_MESSAGE);
    }
    let commitments = sp.signing_commitments();
    let count = commitments.len();
    if count < *kp.min_signers() as usize || count > MAX_SIGNERS as usize {
        return Err(E_COMMITMENT_COUNT);
    }
    if commitments.keys().any(|id| identifier_index(id).is_none()) {
        return Err(E_IDENTIFIER);
    }
    match commitments.get(kp.identifier()) {
        Some(c) if c == signer_nonces.commitments() => {}
        _ => return Err(E_OWN_COMMITMENT),
    }
    let share = frost::round2::sign(&sp, &signer_nonces, &kp).map_err(|_| E_SIGN)?;
    // Recomputing the share's validity catches a fault injected into the
    // computation above before the share leaves the device.
    frost_core::verify_signature_share(*kp.identifier(), kp.verifying_share(), &share, &sp, kp.verifying_key())
        .map_err(|_| E_SELFCHECK)?;
    let s = share.serialize();
    if s.len() != SIGNATURE_SHARE_LEN {
        return Err(E_LENGTH);
    }
    share_out.copy_from_slice(&s);
    Ok(())
}
