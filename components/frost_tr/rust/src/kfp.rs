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
use crate::signer::{identifier_index, E_IDENTIFIER};

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
const MAX_PAYLOAD: usize = 1 + 32 + 2 + padded_len(MAX_PLAINTEXT) + 32;

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

/// The announce proof binding `transport_xonly` to this share: keep's
/// `sign_proof`, BIP-340 by the signing share over SHA256 of the proof digest,
/// with zero auxiliary randomness.
pub fn announce_proof(kp: &KeyPackage, transport_xonly: &[u8; 32], timestamp: u64) -> Result<[u8; 64], i32> {
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
    let share = Zeroizing::new(kp.signing_share().serialize());
    let key = SigningKey::from_bytes(&share).map_err(|_| E_KEY)?;
    let sig = key.sign_raw(&Sha256::digest(digest), &[0u8; 32]).map_err(|_| E_KEY)?;
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
    let (prk, _) = Hkdf::<Sha256>::extract(Some(b"nip44-v2"), &shared_x);
    shared_x.zeroize();
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&prk);
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

/// NIP-44 v2 payload (base64) of `plaintext` from this device's transport key
/// to the x-only `recipient`, under `nonce`.
pub fn seal_with_nonce(kp: &KeyPackage, recipient: &[u8; 32], plaintext: &[u8], nonce: &[u8; 32]) -> Result<Vec<u8>, i32> {
    if plaintext.is_empty() || plaintext.len() > MAX_PLAINTEXT {
        return Err(E_CAPACITY);
    }
    let conversation = conversation_key(&transport_secret(kp)?, recipient)?;
    let keys = MessageKeys::new(&conversation, nonce)?;
    let mut buffer = Zeroizing::new(Vec::with_capacity(2 + padded_len(plaintext.len())));
    buffer.extend_from_slice(&(plaintext.len() as u16).to_be_bytes());
    buffer.extend_from_slice(plaintext);
    buffer.resize(2 + padded_len(plaintext.len()), 0);
    keys.cipher().apply_keystream(&mut buffer);
    let tag = keys.mac(nonce, &buffer).finalize().into_bytes();
    let mut payload = Vec::with_capacity(1 + 32 + buffer.len() + 32);
    payload.push(2);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(&buffer);
    payload.extend_from_slice(&tag);
    let encoded = Base64::encode_string(&payload);
    Ok(encoded.into_bytes())
}

pub fn seal(kp: &KeyPackage, recipient: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, i32> {
    let mut nonce = [0u8; 32];
    DeviceRng.fill_bytes(&mut nonce);
    seal_with_nonce(kp, recipient, plaintext, &nonce)
}

/// The plaintext of a NIP-44 v2 `payload` (base64) the x-only `sender` sealed to
/// this device's transport key. The MAC is checked before anything is
/// decrypted, so a valid result was produced by the holder of `sender`'s key
/// (or by this device).
pub fn open(kp: &KeyPackage, sender: &[u8; 32], payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, i32> {
    if payload.len() > (MAX_PAYLOAD + 2) / 3 * 4 {
        return Err(E_CAPACITY);
    }
    let raw = Base64::decode_vec(core::str::from_utf8(payload).map_err(|_| E_DECRYPT)?).map_err(|_| E_DECRYPT)?;
    if raw.len() < MIN_PAYLOAD || raw.len() > MAX_PAYLOAD || raw[0] != 2 {
        return Err(E_DECRYPT);
    }
    let nonce: [u8; 32] = raw[1..33].try_into().map_err(|_| E_DECRYPT)?;
    let (ciphertext, tag) = raw[33..].split_at(raw.len() - 33 - 32);
    let conversation = conversation_key(&transport_secret(kp)?, sender)?;
    let keys = MessageKeys::new(&conversation, &nonce)?;
    keys.mac(&nonce, ciphertext).verify_slice(tag).map_err(|_| E_DECRYPT)?;
    let mut buffer = Zeroizing::new(ciphertext.to_vec());
    keys.cipher().apply_keystream(&mut buffer);
    let len = u16::from_be_bytes([buffer[0], buffer[1]]) as usize;
    if len == 0 || buffer.len() != 2 + padded_len(len) {
        return Err(E_DECRYPT);
    }
    Ok(Zeroizing::new(buffer[2..2 + len].to_vec()))
}

/// The NIP-01 id of a serialized event (`[0,pubkey,created_at,kind,tags,content]`)
/// and its BIP-340 signature by this device's transport key.
pub fn sign_event(kp: &KeyPackage, serialized: &[u8]) -> Result<([u8; 32], [u8; 64]), i32> {
    let id: [u8; 32] = Sha256::digest(serialized).into();
    let secret = transport_secret(kp)?;
    let key = SigningKey::from(secret.to_nonzero_scalar());
    let mut aux = [0u8; 32];
    DeviceRng.fill_bytes(&mut aux);
    let sig = key.sign_raw(&id, &aux).map_err(|_| E_KEY)?;
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

/// Whether `salt` encodes the key a request signs with: empty only with no path
/// and no tweak, otherwise an 8-byte attempt counter followed by each path
/// index (big endian) and, for a key-path spend, `ff 'T' 'R'` then `00` or
/// `01 || merkle_root`.
pub fn salt_binds(salt: &[u8], path: &[u32], taproot: Option<Option<[u8; 32]>>) -> bool {
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
        assert_eq!(open(&kp, &peer, &authentic(&kp, &peer, &buffer(5, 32))).unwrap()[..], [0x41; 5]);
        assert_eq!(open(&kp, &peer, &authentic(&kp, &peer, &buffer(40, 64))).unwrap()[..], [0x41; 40]);
        for (prefix, body) in [(0u16, 32usize), (33, 32), (40, 32), (65_535, 32), (5, 64), (40, 96)] {
            assert_eq!(open(&kp, &peer, &authentic(&kp, &peer, &buffer(prefix, body))).err(), Some(E_DECRYPT), "prefix {prefix}, body {body}");
        }
    }
}
