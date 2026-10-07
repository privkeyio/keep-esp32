// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! FROST(secp256k1, SHA-256, Taproot) for keep-esp32: the Zcash Foundation's
//! `frost-secp256k1-tr` (the implementation the keep host uses) behind a C
//! interface. See `include/frost_tr.h`.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod glue;
mod rng;
mod selftest;
mod signer;
#[rustfmt::skip]
mod vectors;

/// Registers the firmware's health-checked RNG. Must be called once at boot,
/// before any other `ftr_` function. Returns 0, or -1 if an RNG was already
/// registered (the first registration stays in force).
///
/// # Safety
/// `fill` and `healthy` must stay valid for the life of the program.
#[no_mangle]
pub unsafe extern "C" fn ftr_init(fill: Option<rng::FillFn>, healthy: Option<rng::HealthyFn>) -> i32 {
    match (fill, healthy) {
        (Some(f), Some(h)) if rng::register(f, h) => 0,
        _ => -1,
    }
}

/// Runs the boot self-test: heap alignment, the ZF test vectors byte for byte,
/// and that the firmware RNG is registered and healthy. Returns 0 on success or the code of
/// the first failed check (see `selftest.rs`).
#[no_mangle]
pub extern "C" fn ftr_selftest() -> i32 {
    selftest::run()
}

/// What `ftr_key_package_import` reports about a valid key package.
#[repr(C)]
pub struct FtrKeyInfo {
    pub index: u16,
    pub min_signers: u16,
    pub verifying_share: [u8; 33],
    pub group_key: [u8; 33],
}

unsafe fn slice<'a>(p: *const u8, len: usize) -> Option<&'a [u8]> {
    (!p.is_null()).then(|| core::slice::from_raw_parts(p, len))
}

fn status(r: Result<(), i32>) -> i32 {
    match r {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// Parses and validates a frost-core `KeyPackage` (see `signer::load`).
///
/// # Safety
/// `kp` must point to `kp_len` readable bytes and `out` to a writable
/// `FtrKeyInfo`.
#[no_mangle]
pub unsafe extern "C" fn ftr_key_package_import(kp: *const u8, kp_len: usize, out: *mut FtrKeyInfo) -> i32 {
    let (Some(kp), false) = (slice(kp, kp_len), out.is_null()) else {
        return signer::E_NULL;
    };
    status(signer::import(kp).map(|info| {
        *out = FtrKeyInfo {
            index: info.index,
            min_signers: info.min_signers,
            verifying_share: info.verifying_share,
            group_key: info.group_key,
        };
    }))
}

/// Rebuilds a key package from a share stored before protocol 2 (see
/// `signer::from_legacy`), writing it to `out_kp` and its length and the
/// group's participant count to `out_len` and `out_participants`.
///
/// # Safety
/// `legacy` must point to `legacy_len` readable bytes; `out_kp` to a writable
/// `FTR_KEY_PACKAGE_MAX`-byte buffer; the other outputs must be writable.
#[no_mangle]
pub unsafe extern "C" fn ftr_key_package_from_legacy(
    legacy: *const u8,
    legacy_len: usize,
    out_kp: *mut [u8; signer::KEY_PACKAGE_MAX],
    out_len: *mut usize,
    out_participants: *mut u16,
) -> i32 {
    let (Some(legacy), Some(kp), false, false) =
        (slice(legacy, legacy_len), out_kp.as_mut(), out_len.is_null(), out_participants.is_null())
    else {
        return signer::E_NULL;
    };
    status(signer::from_legacy(legacy, kp).map(|(len, participants)| {
        *out_len = len;
        *out_participants = participants;
    }))
}

/// Draws fresh signing nonces for the key package and returns them with
/// their commitments. The nonces must stay in RAM and be passed to exactly
/// one `ftr_sign`.
///
/// # Safety
/// `kp` must point to `kp_len` readable bytes; the outputs to writable
/// buffers of their stated sizes.
#[no_mangle]
pub unsafe extern "C" fn ftr_commit(
    kp: *const u8,
    kp_len: usize,
    out_nonces: *mut [u8; signer::NONCES_LEN],
    out_commitments: *mut [u8; signer::COMMITMENTS_LEN],
) -> i32 {
    let (Some(kp), Some(nonces), Some(commitments)) = (slice(kp, kp_len), out_nonces.as_mut(), out_commitments.as_mut()) else {
        return signer::E_NULL;
    };
    status(signer::commit(kp, nonces, commitments))
}

/// Signs `signing_package` with the nonces from `ftr_commit`. Refuses unless
/// the package's message is `expected_message`. `nonces` is zeroed on every
/// path, success or failure.
///
/// # Safety
/// `kp` and `signing_package` must point to readable buffers of the given
/// lengths; the fixed-size pointers to buffers of their stated sizes.
#[no_mangle]
pub unsafe extern "C" fn ftr_sign(
    kp: *const u8,
    kp_len: usize,
    nonces: *mut [u8; signer::NONCES_LEN],
    signing_package: *const u8,
    signing_package_len: usize,
    expected_message: *const [u8; signer::MESSAGE_LEN],
    out_share: *mut [u8; signer::SIGNATURE_SHARE_LEN],
) -> i32 {
    let Some(nonces) = nonces.as_mut() else {
        return signer::E_NULL;
    };
    let (Some(kp), Some(sp), Some(msg), Some(share)) =
        (slice(kp, kp_len), slice(signing_package, signing_package_len), expected_message.as_ref(), out_share.as_mut())
    else {
        glue::wipe(nonces.as_mut_ptr(), signer::NONCES_LEN);
        return signer::E_NULL;
    };
    status(signer::sign(kp, nonces, sp, msg, share))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, MutexGuard};

    use frost_secp256k1_tr as frost;
    use frost::keys::{IdentifierList, KeyPackage, VerifyingShare};
    use frost::{Identifier, SigningPackage};

    /// Tests that touch the process-wide RNG registration run one at a time.
    static RNG_LOCK: Mutex<()> = Mutex::new(());
    static STATE: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);

    /// splitmix64: deterministic, test-only bytes behind the registered fill
    /// function, so the code under test draws exactly as on the device.
    unsafe extern "C" fn test_fill(buf: *mut u8, len: usize) -> i32 {
        for i in 0..len {
            let mut z = STATE.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::SeqCst).wrapping_add(0x9E37_79B9_7F4A_7C15);
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            *buf.add(i) = (z ^ (z >> 31)) as u8;
        }
        0
    }

    unsafe extern "C" fn test_healthy() -> u32 {
        0xAAAA_AAAA
    }

    fn with_rng() -> MutexGuard<'static, ()> {
        let g = RNG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if !rng::registered() {
            unsafe { assert_eq!(ftr_init(Some(test_fill), Some(test_healthy)), 0) };
        }
        g
    }

    #[test]
    fn vectors_match_byte_for_byte() {
        assert_eq!(selftest::vectors(), selftest::OK);
    }

    #[test]
    fn rng_registers_once() {
        let _g = RNG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        rng::reset();
        assert_eq!(selftest::rng_registered(), selftest::E_RNG_UNREGISTERED);
        unsafe {
            assert_eq!(ftr_init(None, Some(test_healthy)), -1);
            assert_eq!(ftr_init(Some(test_fill), None), -1);
            assert_eq!(ftr_init(Some(test_fill), Some(test_healthy)), 0);
            assert_eq!(ftr_init(Some(test_fill), Some(test_healthy)), -1);
        }
        assert_eq!(selftest::rng_registered(), selftest::OK);
        assert_eq!(ftr_selftest(), selftest::OK);
    }

    #[test]
    fn freed_blocks_are_wiped() {
        use core::alloc::{GlobalAlloc, Layout};
        let layout = Layout::from_size_align(64, 16).unwrap();
        unsafe {
            let p = glue::WipingAlloc.alloc(layout);
            assert_eq!(p as usize % 16, 0);
            core::ptr::write_bytes(p, 0xA5, 64);
            glue::wipe(p, 64);
            assert!((0..64).all(|i| *p.add(i) == 0));
            core::ptr::write_bytes(p, 0xA5, 64);
            glue::WipingAlloc.dealloc(p, layout);
        }
    }

    #[test]
    fn aligned_allocations_are_aligned() {
        assert_eq!(selftest::alignment(), selftest::OK);
    }

    struct Group {
        kps: BTreeMap<Identifier, KeyPackage>,
        pubkeys: frost::keys::PublicKeyPackage,
    }

    /// A dealer-generated group whose key has the requested parity.
    fn group(min: u16, max: u16, odd: bool) -> Group {
        loop {
            let (shares, pubkeys) =
                frost::keys::generate_with_dealer(max, min, IdentifierList::Default, &mut rng::DeviceRng).unwrap();
            if (pubkeys.verifying_key().serialize().unwrap()[0] == 3) != odd {
                continue;
            }
            let kps = shares.into_iter().map(|(id, s)| (id, KeyPackage::try_from(s).unwrap())).collect();
            return Group { kps, pubkeys };
        }
    }

    fn id(i: u16) -> Identifier {
        Identifier::try_from(i).unwrap()
    }

    fn import(kp: &[u8]) -> Result<FtrKeyInfo, i32> {
        let mut info = FtrKeyInfo { index: 0, min_signers: 0, verifying_share: [0; 33], group_key: [0; 33] };
        match unsafe { ftr_key_package_import(kp.as_ptr(), kp.len(), &mut info) } {
            0 => Ok(info),
            e => Err(e),
        }
    }

    fn device_commit(kp: &[u8]) -> ([u8; 64], frost::round1::SigningCommitments) {
        let (mut n, mut c) = ([0u8; 64], [0u8; 71]);
        assert_eq!(unsafe { ftr_commit(kp.as_ptr(), kp.len(), &mut n, &mut c) }, 0);
        (n, frost::round1::SigningCommitments::deserialize(&c).unwrap())
    }

    fn device_sign(kp: &[u8], nonces: &mut [u8; 64], sp: &[u8], msg: &[u8; 32]) -> Result<[u8; 32], i32> {
        let mut out = [0u8; 32];
        match unsafe { ftr_sign(kp.as_ptr(), kp.len(), nonces, sp.as_ptr(), sp.len(), msg, &mut out) } {
            0 => Ok(out),
            e => Err(e),
        }
    }

    /// One full round: participant `dev` signs through the C interface, the
    /// other `signers` with frost-secp256k1-tr directly, as keep would.
    fn round(g: &Group, dev: u16, signers: &[u16], msg: &[u8; 32]) {
        let kp = g.kps[&id(dev)].serialize().unwrap();
        let (mut dev_nonces, dev_commitments) = device_commit(&kp);
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::from([(id(dev), dev_commitments)]);
        for &i in signers.iter().filter(|&&i| i != dev) {
            let (n, c) = frost::round1::commit(g.kps[&id(i)].signing_share(), &mut rng::DeviceRng);
            nonces.insert(id(i), n);
            commitments.insert(id(i), c);
        }
        let package = SigningPackage::new(commitments, msg);
        let sp = package.serialize().unwrap();
        let share = device_sign(&kp, &mut dev_nonces, &sp, msg).unwrap();
        assert_eq!(dev_nonces, [0u8; 64]);
        let mut shares = BTreeMap::from([(id(dev), frost::round2::SignatureShare::deserialize(&share).unwrap())]);
        for (i, n) in &nonces {
            shares.insert(*i, frost::round2::sign(&package, n, &g.kps[i]).unwrap());
        }
        let sig = frost::aggregate(&package, &shares, &g.pubkeys).unwrap();
        g.pubkeys.verifying_key().verify(msg, &sig).unwrap();
    }

    #[test]
    fn signs_with_keep_in_every_shape() {
        let _g = with_rng();
        for odd in [false, true] {
            let g = group(2, 3, odd);
            round(&g, 1, &[1, 2], &[0x11; 32]);
            round(&g, 3, &[1, 3], &[0x22; 32]);
            round(&g, 2, &[1, 2, 3], &[0x33; 32]);
            let g = group(3, 5, odd);
            round(&g, 5, &[2, 4, 5], &[0x44; 32]);
            round(&g, 1, &[1, 2, 3, 4, 5], &[0x55; 32]);
        }
    }

    #[test]
    fn import_reports_the_key_package() {
        let _g = with_rng();
        let g = group(2, 3, true);
        let kp = &g.kps[&id(2)];
        let bytes = kp.serialize().unwrap();
        assert_eq!(bytes.len(), 136);
        let info = import(&bytes).unwrap();
        assert_eq!((info.index, info.min_signers), (2, 2));
        assert_eq!(info.verifying_share[..], kp.verifying_share().serialize().unwrap()[..]);
        assert_eq!(info.group_key[..], g.pubkeys.verifying_key().serialize().unwrap()[..]);
        assert_eq!(info.group_key[0], 3);
    }

    #[test]
    fn import_rejects_malformed_key_packages() {
        let _g = with_rng();
        let g = group(2, 3, false);
        let kp = &g.kps[&id(1)];
        let good = kp.serialize().unwrap();
        assert_eq!(import(&[]).err(), Some(signer::E_LENGTH));
        assert_eq!(import(&[0u8; 257]).err(), Some(signer::E_LENGTH));
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(import(&trailing).err(), Some(signer::E_NONCANONICAL));
        let mut suite = good.clone();
        suite[1] ^= 1;
        assert_eq!(import(&suite).err(), Some(signer::E_DESERIALIZE));
        assert_eq!(import(&good[..good.len() - 1]).err(), Some(signer::E_DESERIALIZE));
        assert_eq!(unsafe { ftr_key_package_import(core::ptr::null(), 0, core::ptr::null_mut()) }, signer::E_NULL);

        let vk = *kp.verifying_key();
        let other = *g.kps[&id(2)].signing_share();
        let mismatched = KeyPackage::new(id(1), other, *kp.verifying_share(), vk, 2);
        assert_eq!(import(&mismatched.serialize().unwrap()).err(), Some(signer::E_SHARE_MISMATCH));

        let s = *kp.signing_share();
        let vs = VerifyingShare::from(s);
        let wide = KeyPackage::new(Identifier::derive(b"not a u16").unwrap(), s, vs, vk, 2);
        assert_eq!(import(&wide.serialize().unwrap()).err(), Some(signer::E_IDENTIFIER));
        let big = KeyPackage::new(id(17), s, vs, vk, 2);
        assert_eq!(import(&big.serialize().unwrap()).err(), Some(signer::E_THRESHOLD));
        for t in [0u16, 1, 17] {
            let bad = KeyPackage::new(id(1), s, vs, vk, t);
            assert_eq!(import(&bad.serialize().unwrap()).err(), Some(signer::E_THRESHOLD), "min_signers {t}");
        }
        // Header 5, identifier 32, then the signing share.
        assert_eq!(good[37..69], kp.signing_share().serialize()[..]);
        let mut zero = good.clone();
        zero[37..69].fill(0);
        assert_eq!(import(&zero).err(), Some(signer::E_SHARE_MISMATCH));
    }

    /// Builds a package around a fresh device commitment for participant 1 of
    /// a 2-of-3 group, so each test can corrupt one part of it.
    struct Fixture {
        g: Group,
        kp: Vec<u8>,
        nonces: [u8; 64],
        commitments: BTreeMap<Identifier, frost::round1::SigningCommitments>,
    }

    fn fixture() -> Fixture {
        let g = group(2, 3, false);
        let kp = g.kps[&id(1)].serialize().unwrap();
        let (nonces, c1) = device_commit(&kp);
        let (_, c2) = frost::round1::commit(g.kps[&id(2)].signing_share(), &mut rng::DeviceRng);
        let commitments = BTreeMap::from([(id(1), c1), (id(2), c2)]);
        Fixture { g, kp, nonces, commitments }
    }

    #[test]
    fn sign_refuses_and_still_burns_the_nonces() {
        let _g = with_rng();
        let msg = [0x5a; 32];

        let mut f = fixture();
        let sp = SigningPackage::new(f.commitments.clone(), &[0x5b; 32]).serialize().unwrap();
        assert_eq!(device_sign(&f.kp, &mut f.nonces, &sp, &msg), Err(signer::E_MESSAGE));
        assert_eq!(f.nonces, [0u8; 64]);
        let sp = SigningPackage::new(f.commitments.clone(), &msg).serialize().unwrap();
        assert_eq!(device_sign(&f.kp, &mut f.nonces, &sp, &msg), Err(signer::E_NONCES), "replay after a refusal");

        let mut f = fixture();
        let sp = SigningPackage::new(f.commitments.clone(), &[0x5a; 33]).serialize().unwrap();
        assert_eq!(device_sign(&f.kp, &mut f.nonces, &sp, &msg), Err(signer::E_MESSAGE));

        let mut f = fixture();
        let (_, other) = frost::round1::commit(f.g.kps[&id(1)].signing_share(), &mut rng::DeviceRng);
        f.commitments.insert(id(1), other);
        let sp = SigningPackage::new(f.commitments.clone(), &msg).serialize().unwrap();
        assert_eq!(device_sign(&f.kp, &mut f.nonces, &sp, &msg), Err(signer::E_OWN_COMMITMENT));

        let mut f = fixture();
        let (_, c3) = frost::round1::commit(f.g.kps[&id(3)].signing_share(), &mut rng::DeviceRng);
        f.commitments.remove(&id(1));
        f.commitments.insert(id(3), c3);
        let sp = SigningPackage::new(f.commitments.clone(), &msg).serialize().unwrap();
        assert_eq!(device_sign(&f.kp, &mut f.nonces, &sp, &msg), Err(signer::E_OWN_COMMITMENT));

        let mut f = fixture();
        f.commitments.remove(&id(2));
        let sp = SigningPackage::new(f.commitments.clone(), &msg).serialize().unwrap();
        assert_eq!(device_sign(&f.kp, &mut f.nonces, &sp, &msg), Err(signer::E_COMMITMENT_COUNT));

        let mut f = fixture();
        let wide = Identifier::derive(b"not a u16").unwrap();
        let c = f.commitments[&id(2)];
        f.commitments.insert(wide, c);
        let sp = SigningPackage::new(f.commitments.clone(), &msg).serialize().unwrap();
        assert_eq!(device_sign(&f.kp, &mut f.nonces, &sp, &msg), Err(signer::E_IDENTIFIER));

        let mut f = fixture();
        let mut sp = SigningPackage::new(f.commitments.clone(), &msg).serialize().unwrap();
        sp.push(0);
        assert_eq!(device_sign(&f.kp, &mut f.nonces, &sp, &msg), Err(signer::E_NONCANONICAL));
        assert_eq!(f.nonces, [0u8; 64]);

        let mut f = fixture();
        let sp = SigningPackage::new(f.commitments.clone(), &msg).serialize().unwrap();
        assert_eq!(device_sign(&f.kp, &mut f.nonces, &sp[..sp.len() - 1], &msg), Err(signer::E_DESERIALIZE));

        let mut f = fixture();
        let sp = SigningPackage::new(f.commitments.clone(), &msg).serialize().unwrap();
        let mut zero = [0u8; 64];
        assert_eq!(device_sign(&f.kp, &mut zero, &sp, &msg), Err(signer::E_NONCES));
        let mut out = [0u8; 32];
        let r = unsafe { ftr_sign(f.kp.as_ptr(), f.kp.len(), &mut f.nonces, core::ptr::null(), 0, &msg, &mut out) };
        assert_eq!(r, signer::E_NULL);
        assert_eq!(f.nonces, [0u8; 64], "nonces are burned on a null argument too");
    }

    #[test]
    fn a_share_signs_once() {
        let _g = with_rng();
        let msg = [0x77; 32];
        let mut f = fixture();
        let sp = SigningPackage::new(f.commitments.clone(), &msg).serialize().unwrap();
        assert!(device_sign(&f.kp, &mut f.nonces, &sp, &msg).is_ok());
        assert_eq!(device_sign(&f.kp, &mut f.nonces, &sp, &msg), Err(signer::E_NONCES));
    }

    /// The 104-byte layout keep's `serialize_share_for_hardware` writes.
    fn legacy(kp: &KeyPackage, participants: u16, with_threshold: bool) -> Vec<u8> {
        let mut v = kp.signing_share().serialize();
        v.extend(kp.verifying_share().serialize().unwrap());
        v.extend(kp.verifying_key().serialize().unwrap());
        v.extend(identifier_u16(kp).to_le_bytes());
        v.extend(participants.to_le_bytes());
        if with_threshold {
            v.extend(kp.min_signers().to_le_bytes());
        }
        v
    }

    fn identifier_u16(kp: &KeyPackage) -> u16 {
        signer::identifier_index(kp.identifier()).unwrap()
    }

    fn from_legacy(bytes: &[u8]) -> Result<(Vec<u8>, u16), i32> {
        let (mut out, mut len, mut participants) = ([0u8; 256], 0usize, 0u16);
        match unsafe { ftr_key_package_from_legacy(bytes.as_ptr(), bytes.len(), &mut out, &mut len, &mut participants) } {
            0 => Ok((out[..len].to_vec(), participants)),
            e => Err(e),
        }
    }

    #[test]
    fn legacy_shares_become_the_same_key_package() {
        let _g = with_rng();
        for odd in [false, true] {
            let g = group(3, 5, odd);
            for kp in g.kps.values() {
                let (rebuilt, n) = from_legacy(&legacy(kp, 5, true)).unwrap();
                assert_eq!(rebuilt, kp.serialize().unwrap());
                assert_eq!(n, 5);
            }
        }
        let g = group(2, 3, false);
        let kp = &g.kps[&id(3)];
        let (rebuilt, n) = from_legacy(&legacy(kp, 3, false)).unwrap();
        assert_eq!((rebuilt, n), (kp.serialize().unwrap(), 3), "102-byte form means min_signers 2");
        round(&g, 3, &[2, 3], &[0x66; 32]);
    }

    #[test]
    fn legacy_shares_that_do_not_check_out_are_refused() {
        let _g = with_rng();
        let g = group(2, 3, false);
        let kp = &g.kps[&id(2)];
        let good = legacy(kp, 3, true);
        assert_eq!(from_legacy(&good[..103]).err(), Some(signer::E_LENGTH));
        let mut flipped = good.clone();
        flipped[0] ^= 1;
        assert_eq!(from_legacy(&flipped).err(), Some(signer::E_SHARE_MISMATCH));
        let mut vs = good.clone();
        vs[33] ^= 1;
        assert!(from_legacy(&vs).is_err());
        let set = |at: usize, v: u16| {
            let mut b = good.clone();
            b[at..at + 2].copy_from_slice(&v.to_le_bytes());
            b
        };
        assert_eq!(from_legacy(&set(98, 0)).err(), Some(signer::E_THRESHOLD), "index 0");
        assert_eq!(from_legacy(&set(98, 4)).err(), Some(signer::E_THRESHOLD), "index above participants");
        assert_eq!(from_legacy(&set(100, 17)).err(), Some(signer::E_THRESHOLD), "participants above 16");
        assert_eq!(from_legacy(&set(102, 4)).err(), Some(signer::E_THRESHOLD), "min_signers above participants");
        assert_eq!(from_legacy(&set(102, 1)).err(), Some(signer::E_THRESHOLD), "min_signers 1");
    }

    #[test]
    fn the_c_header_agrees() {
        let header = include_str!("../../include/frost_tr.h");
        let define = |name: &str| -> i64 {
            let line = header
                .lines()
                .find(|l| l.split_whitespace().nth(1) == Some(name) && l.starts_with("#define"))
                .unwrap_or_else(|| panic!("{name} missing from frost_tr.h"));
            line.split_whitespace().nth(2).unwrap().parse().unwrap()
        };
        let expected: &[(&str, i64)] = &[
            ("FTR_KEY_PACKAGE_MAX", signer::KEY_PACKAGE_MAX as i64),
            ("FTR_NONCES_LEN", signer::NONCES_LEN as i64),
            ("FTR_COMMITMENTS_LEN", signer::COMMITMENTS_LEN as i64),
            ("FTR_SIGNATURE_SHARE_LEN", signer::SIGNATURE_SHARE_LEN as i64),
            ("FTR_MESSAGE_LEN", signer::MESSAGE_LEN as i64),
            ("FTR_MAX_SIGNERS", signer::MAX_SIGNERS as i64),
            ("FTR_SIGNING_PACKAGE_MAX", signer::SIGNING_PACKAGE_MAX as i64),
            ("FTR_E_NULL", signer::E_NULL as i64),
            ("FTR_E_LENGTH", signer::E_LENGTH as i64),
            ("FTR_E_DESERIALIZE", signer::E_DESERIALIZE as i64),
            ("FTR_E_NONCANONICAL", signer::E_NONCANONICAL as i64),
            ("FTR_E_SHARE_MISMATCH", signer::E_SHARE_MISMATCH as i64),
            ("FTR_E_IDENTIFIER", signer::E_IDENTIFIER as i64),
            ("FTR_E_THRESHOLD", signer::E_THRESHOLD as i64),
            ("FTR_E_MESSAGE", signer::E_MESSAGE as i64),
            ("FTR_E_COMMITMENT_COUNT", signer::E_COMMITMENT_COUNT as i64),
            ("FTR_E_OWN_COMMITMENT", signer::E_OWN_COMMITMENT as i64),
            ("FTR_E_NONCES", signer::E_NONCES as i64),
            ("FTR_E_SIGN", signer::E_SIGN as i64),
            ("FTR_E_SELFCHECK", signer::E_SELFCHECK as i64),
        ];
        for (name, value) in expected {
            assert_eq!(define(name), *value, "{name}");
        }
        assert_eq!(core::mem::size_of::<FtrKeyInfo>(), 70);
        assert!(header.contains("_Static_assert(sizeof(ftr_key_info_t) == 70"));
    }

    #[test]
    fn sizes_are_pinned() {
        let _g = with_rng();
        let g = group(2, 16, false);
        let mut commitments = BTreeMap::new();
        for i in 1..=16u16 {
            let (_, c) = frost::round1::commit(g.kps[&id(i)].signing_share(), &mut rng::DeviceRng);
            assert_eq!(c.serialize().unwrap().len(), signer::COMMITMENTS_LEN);
            commitments.insert(id(i), c);
        }
        let sp = SigningPackage::new(commitments, &[0u8; 32]).serialize().unwrap();
        assert_eq!(sp.len(), signer::SIGNING_PACKAGE_MAX);
        assert_eq!(signer::SIGNING_PACKAGE_MAX, 1687);
        assert_eq!(g.kps[&id(16)].serialize().unwrap().len(), 136);
    }
}
