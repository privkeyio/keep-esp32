// SPDX-FileCopyrightText: © 2026 PrivKey LLC
// SPDX-License-Identifier: MIT

//! Platform glue for the no_std build: a heap that wipes freed memory, a panic
//! handler, and the fatal path. On the device these use ESP-IDF; host builds
//! (the crate's own tests, and any host program linking the archive) use libc.

use core::alloc::{GlobalAlloc, Layout};

#[cfg(target_os = "none")]
mod sys {
    pub const MALLOC_CAP_8BIT: u32 = 1 << 2;
    pub const MALLOC_CAP_INTERNAL: u32 = 1 << 11;
    extern "C" {
        pub fn heap_caps_malloc(size: usize, caps: u32) -> *mut u8;
        pub fn heap_caps_aligned_alloc(alignment: usize, size: usize, caps: u32) -> *mut u8;
        pub fn heap_caps_free(ptr: *mut u8);
        pub fn esp_restart() -> !;
    }

    /// The IDF heap only guarantees 4-byte alignment, so larger alignments go
    /// through the aligned allocator.
    pub unsafe fn alloc(size: usize, align: usize) -> *mut u8 {
        let caps = MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT;
        if align <= 4 {
            heap_caps_malloc(size, caps)
        } else {
            heap_caps_aligned_alloc(align, size, caps)
        }
    }

    pub unsafe fn free(ptr: *mut u8) {
        heap_caps_free(ptr)
    }

    pub fn fatal() -> ! {
        unsafe { esp_restart() }
    }
}

#[cfg(not(target_os = "none"))]
mod sys {
    extern "C" {
        fn aligned_alloc(alignment: usize, size: usize) -> *mut u8;
        #[link_name = "free"]
        fn libc_free(ptr: *mut u8);
        fn abort() -> !;
    }

    pub unsafe fn alloc(size: usize, align: usize) -> *mut u8 {
        let align = align.max(core::mem::size_of::<usize>());
        aligned_alloc(align, size.div_ceil(align) * align)
    }

    pub unsafe fn free(ptr: *mut u8) {
        libc_free(ptr)
    }

    pub fn fatal() -> ! {
        unsafe { abort() }
    }
}

/// Stops the device without returning. Used where continuing could leak or
/// misuse secret material (RNG failure, allocation failure, panic).
pub fn fatal() -> ! {
    sys::fatal()
}

/// Overwrites `len` bytes with zeros in a way the optimizer cannot elide.
pub unsafe fn wipe(ptr: *mut u8, len: usize) {
    for i in 0..len {
        core::ptr::write_volatile(ptr.add(i), 0);
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Wipes every block before returning it, so secrets copied into temporaries,
/// serialization buffers or grown vectors never linger in freed heap. `realloc`
/// keeps the default alloc, copy and dealloc, so the old block is wiped too.
pub struct WipingAlloc;

unsafe impl GlobalAlloc for WipingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = sys::alloc(layout.size().max(1), layout.align());
        if p.is_null() {
            fatal();
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        wipe(ptr, layout.size());
        sys::free(ptr)
    }
}

#[cfg(not(test))]
#[global_allocator]
static ALLOC: WipingAlloc = WipingAlloc;

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    fatal()
}
