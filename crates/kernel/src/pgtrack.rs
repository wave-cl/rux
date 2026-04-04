/// Page tracking — re-exports from rux-mm.
///
/// The implementation lives in `rux_mm::pgtrack`. This module provides
/// a convenience wrapper for `begin_child` that supplies the arch-specific
/// page table root write function.

#[allow(unused_imports)]
pub use rux_mm::pgtrack::{set_kernel_pt, track, TrackingAllocator, kernel_pt_root};

/// Wrapper that supplies the arch-specific `write_pt_root` callback.
pub fn begin_child(alloc: &mut dyn rux_mm::FrameAllocator) {
    use rux_arch::PageTableRootOps;
    rux_mm::pgtrack::begin_child(alloc, crate::arch::Arch::write);
}
