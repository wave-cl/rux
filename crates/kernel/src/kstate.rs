/// Kernel global state — holds pointers to the VFS and frame allocator
/// so syscall handlers can access them without passing arguments through
/// the interrupt frame.
///
/// SMP safety: ALLOC_LOCK protects the frame allocator. Currently single-CPU,
/// so the lock is never contended. When APs start, all alloc()/dealloc() paths
/// must acquire the lock.

use rux_fs::vfs::Vfs;
use rux_mm::frame::BuddyAllocator;
use core::sync::atomic::{AtomicBool, Ordering};

pub struct KernelState {
    pub fs: *mut Vfs,
    pub alloc: *mut BuddyAllocator,
}

static mut KSTATE: KernelState = KernelState {
    fs: core::ptr::null_mut(),
    alloc: core::ptr::null_mut(),
};

/// Spinlock protecting the frame allocator for SMP.
/// Currently unused (single-CPU). Will be acquired by alloc() when SMP is active.
pub static ALLOC_LOCK: AtomicBool = AtomicBool::new(false);

/// Initialize the kernel state with pointers to the VFS and allocator.
///
/// # Safety
/// Must be called exactly once, after both `fs` and `alloc` are initialized.
pub unsafe fn init(fs: *mut Vfs, alloc: *mut BuddyAllocator) {
    KSTATE.fs = fs;
    KSTATE.alloc = alloc;
}

/// Get a mutable reference to the VFS.
///
/// # Safety
/// Must only be called after `init`. Not thread-safe.
pub unsafe fn fs() -> &'static mut Vfs {
    &mut *KSTATE.fs
}

/// Get a mutable reference to the frame allocator.
///
/// # Safety
/// Must only be called after `init`. Not thread-safe.
pub unsafe fn alloc() -> &'static mut BuddyAllocator {
    &mut *KSTATE.alloc
}
