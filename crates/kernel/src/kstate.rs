/// Kernel global state — holds pointers to the VFS and frame allocator
/// so syscall handlers can access them without passing arguments through
/// the interrupt frame.

use rux_fs::ramfs::RamFs;
use rux_mm::frame::BuddyAllocator;

pub struct KernelState {
    pub fs: *mut RamFs,
    pub alloc: *mut BuddyAllocator,
}

static mut KSTATE: KernelState = KernelState {
    fs: core::ptr::null_mut(),
    alloc: core::ptr::null_mut(),
};

/// Initialize the kernel state with pointers to the VFS and allocator.
///
/// # Safety
/// Must be called exactly once, after both `fs` and `alloc` are initialized.
pub unsafe fn init(fs: *mut RamFs, alloc: *mut BuddyAllocator) {
    KSTATE.fs = fs;
    KSTATE.alloc = alloc;
}

/// Get a mutable reference to the RamFs.
///
/// # Safety
/// Must only be called after `init`. Not thread-safe.
pub unsafe fn fs() -> &'static mut RamFs {
    &mut *KSTATE.fs
}

/// Get a mutable reference to the frame allocator.
///
/// # Safety
/// Must only be called after `init`. Not thread-safe.
pub unsafe fn alloc() -> &'static mut BuddyAllocator {
    &mut *KSTATE.alloc
}
