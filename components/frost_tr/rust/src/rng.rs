// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Registration of the firmware's health-checked RNG, which every FROST
//! nonce will be drawn from. Registration happens once at boot and cannot be
//! replaced afterwards.

use core::sync::atomic::{AtomicUsize, Ordering};

pub type FillFn = unsafe extern "C" fn(buf: *mut u8, len: usize) -> i32;
pub type HealthyFn = unsafe extern "C" fn() -> u32;

static FILL: AtomicUsize = AtomicUsize::new(0);
static HEALTHY: AtomicUsize = AtomicUsize::new(0);

/// Registers the firmware's RNG. Only the first registration takes effect, so
/// nothing can later swap the source.
pub fn register(fill: FillFn, healthy: HealthyFn) -> bool {
    let first = FILL
        .compare_exchange(0, fill as usize, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok();
    if first {
        HEALTHY.store(healthy as usize, Ordering::SeqCst);
    }
    first
}

pub fn registered() -> bool {
    FILL.load(Ordering::SeqCst) != 0 && HEALTHY.load(Ordering::SeqCst) != 0
}
