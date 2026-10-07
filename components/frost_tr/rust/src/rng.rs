// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Registration of the firmware's health-checked RNG, which every FROST
//! nonce will be drawn from. Registration happens once at boot and cannot be
//! replaced afterwards.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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

/// True only when an RNG is registered and reports itself healthy.
pub fn healthy() -> bool {
    match healthy_fn() {
        Some(f) => (unsafe { f() }) == SECRESULT_TRUE,
        None => false,
    }
}
