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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vectors_match_byte_for_byte() {
        assert_eq!(selftest::vectors(), selftest::OK);
    }

    unsafe extern "C" fn test_fill(_buf: *mut u8, _len: usize) -> i32 {
        0
    }

    unsafe extern "C" fn test_healthy() -> u32 {
        0xAAAA_AAAA
    }

    #[test]
    fn rng_registers_once() {
        assert_eq!(selftest::rng_registered(), selftest::E_RNG_UNREGISTERED);
        unsafe {
            assert_eq!(ftr_init(None, Some(test_healthy)), -1);
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
}
