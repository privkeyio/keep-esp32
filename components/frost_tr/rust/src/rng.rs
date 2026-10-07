// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! The firmware's health-checked RNG, which every FROST nonce is drawn from.
//! Registration happens once at boot and cannot be replaced afterwards.
//!
//! frost-core draws through the infallible `RngCore::fill_bytes`, so a failed
//! draw cannot be reported as an error. Returning anything instead (zeros, a
//! retry loop) would make nonces predictable, so every failure stops the
//! device.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::glue::{fatal, wipe};

pub type FillFn = unsafe extern "C" fn(buf: *mut u8, len: usize) -> i32;
pub type HealthyFn = unsafe extern "C" fn() -> u32;

/// `SECRESULT_TRUE` from components/crypto_asm/include/secresult.h.
const SECRESULT_TRUE: u32 = 0xAAAA_AAAA;

static FILL: AtomicUsize = AtomicUsize::new(0);
static HEALTHY: AtomicUsize = AtomicUsize::new(0);
/// Set only after both pointers are stored, so a reader that sees it also sees
/// both pointers.
static READY: AtomicBool = AtomicBool::new(false);

/// Registers the firmware's RNG. Only the first registration takes effect, so
/// nothing can later swap the source.
pub fn register(fill: FillFn, healthy: HealthyFn) -> bool {
    let first = FILL
        .compare_exchange(0, fill as usize, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok();
    if first {
        HEALTHY.store(healthy as usize, Ordering::SeqCst);
        READY.store(true, Ordering::Release);
    }
    first
}

pub fn registered() -> bool {
    READY.load(Ordering::Acquire)
}

/// The registered health check, or `None` before registration.
fn healthy_fn() -> Option<HealthyFn> {
    if !registered() {
        return None;
    }
    // SAFETY: stored from a `HealthyFn` before READY was set; `Option` of a
    // function pointer has the same layout as a nullable address.
    unsafe { core::mem::transmute::<usize, Option<HealthyFn>>(HEALTHY.load(Ordering::Acquire)) }
}

/// The registered fill function, or `None` before registration.
fn fill_fn() -> Option<FillFn> {
    if !registered() {
        return None;
    }
    // SAFETY: as for `healthy_fn`.
    unsafe { core::mem::transmute::<usize, Option<FillFn>>(FILL.load(Ordering::Acquire)) }
}

/// True only when an RNG is registered and reports itself healthy.
pub fn healthy() -> bool {
    match healthy_fn() {
        Some(f) => (unsafe { f() }) == SECRESULT_TRUE,
        None => false,
    }
}

/// Draws are made in blocks this size: the firmware's health check rejects a
/// noticeable share of short draws, which would turn into device resets.
const BLOCK: usize = 32;

fn draw_block(out: &mut [u8; BLOCK]) {
    let Some(fill) = fill_fn() else { fatal() };
    if !healthy() {
        fatal();
    }
    if unsafe { fill(out.as_mut_ptr(), BLOCK) } != 0 {
        unsafe { wipe(out.as_mut_ptr(), BLOCK) };
        fatal();
    }
}

/// The device RNG as a `rand_core` source.
pub struct DeviceRng;

impl rand_core::RngCore for DeviceRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut block = [0u8; BLOCK];
        for chunk in dest.chunks_mut(BLOCK) {
            draw_block(&mut block);
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        unsafe { wipe(block.as_mut_ptr(), BLOCK) };
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for DeviceRng {}

/// Clears the registration so a test can observe the unregistered state.
#[cfg(test)]
pub fn reset() {
    READY.store(false, Ordering::SeqCst);
    HEALTHY.store(0, Ordering::SeqCst);
    FILL.store(0, Ordering::SeqCst);
}
