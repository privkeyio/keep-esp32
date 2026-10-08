// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! The cryptography of a KFP v2 participant (keep-frost-net), derived from the
//! stored key package so no transport secret ever leaves the device: the
//! transport key, the announce proof, rendezvous addresses, NIP-44 v2
//! encryption between transport keys, BIP-340 event signatures and the salted
//! session id. Checked byte for byte against vectors from keep's own code
//! (`vectors/kfp.json`).

use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use blake2::Blake2b512;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use frost_secp256k1_tr::keys::KeyPackage;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use k256::elliptic_curve::point::AffineCoordinates;
use k256::schnorr::SigningKey;
use k256::{AffinePoint, ProjectivePoint, PublicKey, SecretKey};
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::rng::DeviceRng;
use crate::signer::{identifier_index, E_IDENTIFIER, E_SELFCHECK};

pub const E_KEY: i32 = -16;
pub const E_DECRYPT: i32 = -17;
pub const E_CAPACITY: i32 = -18;

const TRANSPORT_DOMAIN: &[u8] = b"keep-frost-transport-v2";
const PROOF_DOMAIN: &[u8] = b"keep-frost-announce-proof-v2";
const RENDEZVOUS_DOMAIN: &[u8] = b"keep-frost-rendezvous-v2";
const SESSION_DOMAIN: &[u8] = b"keep-frost-session-v1";
const SESSION_VERSION: u8 = 0x02;
const TWEAK_MARKER: [u8; 3] = [0xff, b'T', b'R'];

/// NIP-44 v2 bounds (as the nostr crate keep uses enforces them).
pub const MAX_PLAINTEXT: usize = 65_536 - 128;
const MIN_PAYLOAD: usize = 1 + 32 + 2 + 32 + 32;

fn group_xonly(kp: &KeyPackage) -> Result<[u8; 32], i32> {
    let vk = kp.verifying_key().serialize().map_err(|_| E_KEY)?;
    vk.get(1..33).and_then(|x| x.try_into().ok()).ok_or(E_KEY)
}

/// The transport key keep derives from a share: the first
/// `SHA256(domain || share || group_xonly || index_be || counter)` that is a
/// valid secret key.
pub fn transport_secret(kp: &KeyPackage) -> Result<SecretKey, i32> {
    let group = group_xonly(kp)?;
    let index = identifier_index(kp.identifier()).ok_or(E_IDENTIFIER)?;
    let share = Zeroizing::new(kp.signing_share().serialize());
    for counter in 0u8..=255 {
        let mut digest: [u8; 32] = Sha256::new()
            .chain_update(TRANSPORT_DOMAIN)
            .chain_update(&share[..])
            .chain_update(group)
            .chain_update(index.to_be_bytes())
            .chain_update([counter])
            .finalize()
            .into();
        let key = SecretKey::from_slice(&digest);
        digest.zeroize();
        if let Ok(key) = key {
            return Ok(key);
        }
    }
    Err(E_KEY)
}

fn xonly(public: &PublicKey) -> [u8; 32] {
    public.as_affine().x().into()
}

pub fn transport_pubkey(kp: &KeyPackage) -> Result<[u8; 32], i32> {
    Ok(xonly(&transport_secret(kp)?.public_key()))
}

/// The announce proof binding `transport_xonly` to this share: BIP-340 by the
/// signing share over SHA256 of keep's proof digest, as keep's `sign_proof`
/// and `verify_proof` take it. keep signs with zero auxiliary randomness; the
/// device draws it, so a fault injected into one of two runs over the same
/// timestamp does not meet a repeated nonce.
pub fn announce_proof(kp: &KeyPackage, transport_xonly: &[u8; 32], timestamp: u64) -> Result<[u8; 64], i32> {
    let mut aux = [0u8; 32];
    DeviceRng.fill_bytes(&mut aux);
    let r = announce_proof_with_aux(kp, transport_xonly, timestamp, &aux);
    aux.zeroize();
    r
}

/// The 32-byte BIP-340 message of the announce proof: SHA256 of keep's proof
/// digest.
pub(crate) fn proof_message(kp: &KeyPackage, transport_xonly: &[u8; 32], timestamp: u64) -> Result<[u8; 32], i32> {
    let group = group_xonly(kp)?;
    let index = identifier_index(kp.identifier()).ok_or(E_IDENTIFIER)?;
    let verifying_share = kp.verifying_share().serialize().map_err(|_| E_KEY)?;
    let digest = Sha256::new()
        .chain_update(PROOF_DOMAIN)
        .chain_update(group)
        .chain_update(index.to_be_bytes())
        .chain_update(&verifying_share)
        .chain_update(transport_xonly)
        .chain_update(timestamp.to_be_bytes())
        .finalize();
    Ok(Sha256::digest(digest).into())
}

pub(crate) fn announce_proof_with_aux(
    kp: &KeyPackage,
    transport_xonly: &[u8; 32],
    timestamp: u64,
    aux: &[u8; 32],
) -> Result<[u8; 64], i32> {
    let message = proof_message(kp, transport_xonly, timestamp)?;
    let share = Zeroizing::new(kp.signing_share().serialize());
    let key = SigningKey::from_bytes(&share).map_err(|_| E_KEY)?;
    let sig = key.sign_raw(&message, aux).map_err(|_| E_KEY)?;
    // Recomputing the signature's validity catches a fault injected into the
    // signing above before the signature leaves the device.
    key.verifying_key().verify_raw(&message, &sig).map_err(|_| E_SELFCHECK)?;
    Ok(sig.to_bytes())
}

/// The public routing address keep announces to for member `index`: the first
/// `SHA256(domain || group || index_be || counter)` that is an x coordinate.
pub fn rendezvous(group: &[u8; 32], index: u16) -> Result<[u8; 32], i32> {
    for counter in 0u8..=255 {
        let x: [u8; 32] = Sha256::new()
            .chain_update(RENDEZVOUS_DOMAIN)
            .chain_update(group)
            .chain_update(index.to_be_bytes())
            .chain_update([counter])
            .finalize()
            .into();
        if lift_x(&x).is_some() {
            return Ok(x);
        }
    }
    Err(E_KEY)
}

fn lift_x(x: &[u8; 32]) -> Option<AffinePoint> {
    let mut sec1 = [0x02u8; 33];
    sec1[1..].copy_from_slice(x);
    PublicKey::from_sec1_bytes(&sec1).ok().map(|p| *p.as_affine())
}

/// The NIP-44 v2 conversation key between `secret` and the x-only `peer`:
/// HKDF-extract with salt "nip44-v2" over the x coordinate of their ECDH point.
fn conversation_key(secret: &SecretKey, peer: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, i32> {
    let point = lift_x(peer).ok_or(E_KEY)?;
    let shared = (ProjectivePoint::from(point) * *secret.to_nonzero_scalar()).to_affine();
    let mut shared_x: [u8; 32] = shared.x().into();
    let (mut prk, _) = Hkdf::<Sha256>::extract(Some(b"nip44-v2"), &shared_x);
    shared_x.zeroize();
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&prk);
    prk[..].zeroize();
    Ok(out)
}

struct MessageKeys(Zeroizing<[u8; 76]>);

impl MessageKeys {
    fn new(conversation: &[u8; 32], nonce: &[u8; 32]) -> Result<Self, i32> {
        let hk = Hkdf::<Sha256>::from_prk(conversation).map_err(|_| E_KEY)?;
        let mut keys = Zeroizing::new([0u8; 76]);
        hk.expand(nonce, &mut keys[..]).map_err(|_| E_KEY)?;
        Ok(Self(keys))
    }

    fn cipher(&self) -> ChaCha20 {
        ChaCha20::new(self.0[..32].into(), self.0[32..44].into())
    }

    fn mac(&self, nonce: &[u8; 32], ciphertext: &[u8]) -> Hmac<Sha256> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.0[44..]).expect("any key length");
        mac.update(nonce);
        mac.update(ciphertext);
        mac
    }
}

const fn padded_len(len: usize) -> usize {
    if len <= 32 {
        return 32;
    }
    let next_power = 1usize << (usize::BITS - (len - 1).leading_zeros());
    let chunk = if next_power <= 256 { 32 } else { next_power / 8 };
    chunk * ((len - 1) / chunk + 1)
}

const fn raw_len(plaintext_len: usize) -> usize {
    1 + 32 + 2 + padded_len(plaintext_len) + 32
}

const fn encoded_len(raw: usize) -> usize {
    raw.div_ceil(3) * 4
}

/// Writes the NIP-44 v2 payload (base64) of `plaintext` from this device's
/// transport key to the x-only `recipient`, under `nonce`, into `out`;
/// returns its length. Refuses before allocating when `out` cannot hold it.
pub fn seal_with_nonce(kp: &KeyPackage, recipient: &[u8; 32], plaintext: &[u8], nonce: &[u8; 32], out: &mut [u8]) -> Result<usize, i32> {
    if plaintext.is_empty() || plaintext.len() > MAX_PLAINTEXT || encoded_len(raw_len(plaintext.len())) > out.len() {
        return Err(E_CAPACITY);
    }
    let conversation = conversation_key(&transport_secret(kp)?, recipient)?;
    let keys = MessageKeys::new(&conversation, nonce)?;
    let body = 2 + padded_len(plaintext.len());
    let mut raw = Zeroizing::new(Vec::with_capacity(raw_len(plaintext.len())));
    raw.push(2);
    raw.extend_from_slice(nonce);
    raw.extend_from_slice(&(plaintext.len() as u16).to_be_bytes());
    raw.extend_from_slice(plaintext);
    raw.resize(33 + body, 0);
    keys.cipher().apply_keystream(&mut raw[33..]);
    let tag = keys.mac(nonce, &raw[33..]).finalize().into_bytes();
    raw.extend_from_slice(&tag);
    Ok(Base64::encode(&raw, out).map_err(|_| E_CAPACITY)?.len())
}

pub fn seal(kp: &KeyPackage, recipient: &[u8; 32], plaintext: &[u8], out: &mut [u8]) -> Result<usize, i32> {
    let mut nonce = [0u8; 32];
    DeviceRng.fill_bytes(&mut nonce);
    seal_with_nonce(kp, recipient, plaintext, &nonce, out)
}

/// Writes the plaintext of a NIP-44 v2 `payload` (base64) the x-only `sender`
/// sealed to this device's transport key into `out`; returns its length. A
/// payload too large for `out` is refused before it is decoded. The MAC is
/// checked before anything is decrypted, so a valid result was produced by the
/// holder of `sender`'s key or by this device (the key is symmetric).
pub fn open(kp: &KeyPackage, sender: &[u8; 32], payload: &[u8], out: &mut [u8]) -> Result<usize, i32> {
    let cap = out.len().min(MAX_PLAINTEXT);
    if cap == 0 || payload.len() > encoded_len(raw_len(cap)) {
        return Err(E_CAPACITY);
    }
    let mut raw = Zeroizing::new(alloc::vec![0u8; payload.len() / 4 * 3]);
    let len = Base64::decode(payload, &mut raw).map_err(|_| E_DECRYPT)?.len();
    raw.truncate(len);
    if len < MIN_PAYLOAD || raw[0] != 2 {
        return Err(E_DECRYPT);
    }
    let nonce: [u8; 32] = raw[1..33].try_into().map_err(|_| E_DECRYPT)?;
    let conversation = conversation_key(&transport_secret(kp)?, sender)?;
    let keys = MessageKeys::new(&conversation, &nonce)?;
    let (body, tag) = raw[33..].split_at_mut(len - 33 - 32);
    keys.mac(&nonce, body).verify_slice(tag).map_err(|_| E_DECRYPT)?;
    keys.cipher().apply_keystream(body);
    let plain_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    if plain_len == 0 || plain_len > MAX_PLAINTEXT || body.len() != 2 + padded_len(plain_len) {
        return Err(E_DECRYPT);
    }
    if plain_len > out.len() {
        return Err(E_CAPACITY);
    }
    out[..plain_len].copy_from_slice(&body[2..2 + plain_len]);
    Ok(plain_len)
}

/// The NIP-01 id of a serialized event (`[0,pubkey,created_at,kind,tags,content]`)
/// and its BIP-340 signature by this device's transport key.
pub fn sign_event(kp: &KeyPackage, serialized: &[u8]) -> Result<([u8; 32], [u8; 64]), i32> {
    let id: [u8; 32] = Sha256::digest(serialized).into();
    let secret = transport_secret(kp)?;
    let key = SigningKey::from(secret.to_nonzero_scalar());
    let mut aux = [0u8; 32];
    DeviceRng.fill_bytes(&mut aux);
    let sig = key.sign_raw(&id, &aux);
    aux.zeroize();
    let sig = sig.map_err(|_| E_KEY)?;
    key.verifying_key().verify_raw(&id, &sig).map_err(|_| E_SELFCHECK)?;
    Ok((id, sig.to_bytes()))
}

/// keep's salted session id: BLAKE2b-512 (first 32 bytes) over the domain,
/// version, threshold, the sorted participants, the message and, when present,
/// the salt.
pub fn session_id(message: &[u8], participants: &[u16], threshold: u16, salt: &[u8]) -> [u8; 32] {
    let mut sorted = participants.to_vec();
    sorted.sort_unstable();
    let mut h = Blake2b512::new()
        .chain_update(SESSION_DOMAIN)
        .chain_update([SESSION_VERSION])
        .chain_update(threshold.to_be_bytes())
        .chain_update((sorted.len() as u16).to_be_bytes());
    for p in &sorted {
        h.update(p.to_be_bytes());
    }
    h.update((message.len() as u32).to_be_bytes());
    h.update(message);
    if !salt.is_empty() {
        h.update((salt.len() as u32).to_be_bytes());
        h.update(salt);
    }
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

/// Whether `salt` encodes the key a request signs with, as keep's `salt_binds`:
/// empty only with no path and no tweak, otherwise an 8-byte attempt counter
/// followed by each (unhardened) path index, big endian, and, for a key-path
/// spend, `ff 'T' 'R'` then `00` or `01 || merkle_root`.
pub fn salt_binds(salt: &[u8], path: &[u32], taproot: Option<Option<[u8; 32]>>) -> bool {
    // A hardened index could read as the tweak marker, so keep refuses it.
    if path.iter().any(|&i| i >= crate::bip32::HARDENED) {
        return false;
    }
    let mut suffix = Vec::with_capacity(path.len() * 4 + 36);
    for i in path {
        suffix.extend_from_slice(&i.to_be_bytes());
    }
    if let Some(root) = taproot {
        suffix.extend_from_slice(&TWEAK_MARKER);
        match root {
            None => suffix.push(0),
            Some(r) => {
                suffix.push(1);
                suffix.extend_from_slice(&r);
            }
        }
    }
    if salt.is_empty() {
        return suffix.is_empty();
    }
    salt.len() >= 8 && salt[8..] == suffix[..]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// A payload with a valid MAC around `padded`, the plaintext buffer before
    /// encryption (length prefix and padding included).
    fn authentic(kp: &KeyPackage, peer: &[u8; 32], padded: &[u8]) -> Vec<u8> {
        let nonce = [7u8; 32];
        let conversation = conversation_key(&transport_secret(kp).unwrap(), peer).unwrap();
        let keys = MessageKeys::new(&conversation, &nonce).unwrap();
        let mut buffer = padded.to_vec();
        keys.cipher().apply_keystream(&mut buffer);
        let tag = keys.mac(&nonce, &buffer).finalize().into_bytes();
        let mut raw = alloc::vec![2u8];
        raw.extend_from_slice(&nonce);
        raw.extend_from_slice(&buffer);
        raw.extend_from_slice(&tag);
        Base64::encode_string(&raw).into_bytes()
    }

    /// The length prefix must match the padding exactly; one that overruns the
    /// buffer is refused, not read past.
    #[test]
    fn open_checks_the_length_prefix_against_the_padding() {
        let v: serde_json::Value = serde_json::from_str(include_str!("../vectors/kfp.json")).unwrap();
        let g = &v["groups"][0];
        let kp = KeyPackage::deserialize(&unhex(g["key_packages"][0].as_str().unwrap())).unwrap();
        let peer: [u8; 32] = unhex(g["members"][0]["peer_pubkey"].as_str().unwrap()).try_into().unwrap();
        let buffer = |prefix: u16, body: usize| {
            let mut b = prefix.to_be_bytes().to_vec();
            b.resize(2 + body, 0x41);
            b
        };
        let opened = |payload: &[u8]| {
            let mut out = alloc::vec![0u8; MAX_PLAINTEXT];
            open(&kp, &peer, payload, &mut out).map(|n| out[..n].to_vec())
        };
        assert_eq!(opened(&authentic(&kp, &peer, &buffer(5, 32))).unwrap()[..], [0x41; 5]);
        assert_eq!(opened(&authentic(&kp, &peer, &buffer(40, 64))).unwrap()[..], [0x41; 40]);
        // Correctly padded, but longer than NIP-44 lets a sender seal.
        assert_eq!(opened(&authentic(&kp, &peer, &buffer(65_500, 65_536))).err(), Some(E_DECRYPT));
        for (prefix, body) in [(0u16, 32usize), (33, 32), (40, 32), (65_535, 32), (5, 64), (40, 96)] {
            assert_eq!(opened(&authentic(&kp, &peer, &buffer(prefix, body))).err(), Some(E_DECRYPT), "prefix {prefix}, body {body}");
        }
    }
}
