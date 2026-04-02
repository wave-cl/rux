/// Copy-on-write support: frame refcount table and COW fault handler.
///
/// When fork uses COW, parent and child share physical frames with
/// read-only+COW PTEs. On write fault, handle_cow_fault either:
/// - Makes the page writable (sole owner, refcount==1)
/// - Copies the page to a new frame (shared, refcount>1)

use rux_klib::{PhysAddr, VirtAddr};
use rux_mm::cow::FrameRefTable;

/// Maximum physical frames to track (128 MiB / 4K = 32768 frames).
const MAX_FRAMES: usize = 32768;

/// Static storage for frame reference counts.
static mut REF_COUNTS: [u32; MAX_FRAMES] = [0; MAX_FRAMES];

/// Global frame reference table. Initialized once at boot.
static mut FRAME_REFS: FrameRefTable = FrameRefTable {
    counts: core::ptr::null_mut(),
    base: PhysAddr::new(0),
    max_frames: 0,
};

/// Initialize the frame reference table. Called once during boot.
///
/// # Safety
/// Must be called before any COW fork operations.
pub unsafe fn init(alloc_base: PhysAddr) {
    let refs = &raw mut FRAME_REFS;
    (*refs).counts = (&raw mut REF_COUNTS) as *mut u32;
    (*refs).base = alloc_base;
    (*refs).max_frames = MAX_FRAMES;
}

/// Get a mutable reference to the global frame reference table.
pub unsafe fn refs() -> &'static mut FrameRefTable {
    &mut *(&raw mut FRAME_REFS)
}

/// Handle a COW page fault at `fault_addr`.
///
/// Single page table walk via `resolve_cow_fault`: checks COW bit, reads
/// the refcount, and either makes writable (sole owner) or copies the page
/// (shared). Previous implementation did 4 separate walks.
///
/// Returns Ok(()) if resolved, Err if the fault is not a COW fault.
pub unsafe fn handle_cow_fault(fault_addr: usize) -> Result<(), ()> {
    let va = VirtAddr::new(fault_addr & !0xFFF);

    use rux_arch::PageTableRootOps;
    let root = crate::arch::Arch::read();
    let pt = crate::arch::PageTable::from_root(PhysAddr::new(root as usize));
    let alloc = crate::kstate::alloc();
    let refs = &mut *(&raw mut FRAME_REFS);

    match pt.resolve_cow_fault(va, alloc, |pa| refs.count(pa))? {
        Some(old_pa) => { refs.dec(old_pa); }
        None => {}
    }

    Ok(())
}

/// Increment refcount for a physical frame (called during COW fork).
pub unsafe fn inc_ref(pa: PhysAddr) {
    (*(&raw mut FRAME_REFS)).inc(pa);
}

/// Decrement refcount for a physical frame. Returns true if the
/// frame can be freed (refcount reached 0).
pub unsafe fn dec_ref(pa: PhysAddr) -> bool {
    (*(&raw mut FRAME_REFS)).dec(pa)
}
