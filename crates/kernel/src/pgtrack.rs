/// Saved kernel page table root (CR3/TTBR0) for switching back before freeing pages.
static mut KERNEL_PT_ROOT: u64 = 0;

/// Store the kernel page table root. Called once after kernel page tables are set up.
pub fn set_kernel_pt(root: u64) {
    unsafe { KERNEL_PT_ROOT = root; }
}

/// Track pages allocated for user processes to prevent leaks.
///
/// Two-level tracking: parent (shell) pages and child (exec'd) pages.
/// On each new exec, the previous child's pages are freed.
/// The parent's pages are preserved across vfork cycles.

use rux_klib::PhysAddr;
use rux_mm::{FrameAllocator, MemoryError, PageSize};

const MAX_PAGES: usize = 512;

/// Pages allocated by the parent process (shell). Never freed during normal operation.
static mut PARENT_PAGES: [u64; MAX_PAGES] = [0; MAX_PAGES];
static mut PARENT_COUNT: usize = 0;

/// Pages allocated by the most recent child exec. Freed before the next exec.
static mut CHILD_PAGES: [u64; MAX_PAGES] = [0; MAX_PAGES];
static mut CHILD_COUNT: usize = 0;

/// Whether we're tracking for the parent (first load) or child (subsequent execs).
static mut IS_CHILD: bool = false;

/// Record a page allocation into the active tracker.
pub fn track(phys: PhysAddr) {
    unsafe {
        if IS_CHILD {
            if CHILD_COUNT < MAX_PAGES {
                CHILD_PAGES[CHILD_COUNT] = phys.as_usize() as u64;
                CHILD_COUNT += 1;
            }
        } else {
            if PARENT_COUNT < MAX_PAGES {
                PARENT_PAGES[PARENT_COUNT] = phys.as_usize() as u64;
                PARENT_COUNT += 1;
            }
        }
    }
}

/// Mark that subsequent allocations are for a child process.
/// Switches to kernel page table and frees any previous child's pages.
pub fn begin_child(alloc: &mut dyn FrameAllocator) {
    unsafe {
        // Switch to kernel page table before freeing child pages,
        // because the child's page table pages are about to be freed.
        if KERNEL_PT_ROOT != 0 {
            #[cfg(target_arch = "x86_64")]
            core::arch::asm!("mov cr3, {}", in(reg) KERNEL_PT_ROOT, options(nostack));
            #[cfg(target_arch = "aarch64")]
            core::arch::asm!(
                "msr ttbr0_el1, {}", "isb", "tlbi vmalle1is", "dsb ish", "isb",
                in(reg) KERNEL_PT_ROOT, options(nostack)
            );
        }

        // Free previous child's pages
        for i in 0..CHILD_COUNT {
            if CHILD_PAGES[i] != 0 {
                alloc.dealloc(PhysAddr::new(CHILD_PAGES[i] as usize), PageSize::FourK);
            }
        }
        CHILD_COUNT = 0;
        IS_CHILD = true;
    }
}

/// A wrapper allocator that tracks all allocations.
pub struct TrackingAllocator<'a> {
    inner: &'a mut dyn FrameAllocator,
}

impl<'a> TrackingAllocator<'a> {
    pub fn new(inner: &'a mut dyn FrameAllocator) -> Self {
        Self { inner }
    }
}

impl<'a> FrameAllocator for TrackingAllocator<'a> {
    fn alloc(&mut self, size: PageSize) -> Result<PhysAddr, MemoryError> {
        let page = self.inner.alloc(size)?;
        track(page);
        Ok(page)
    }

    fn dealloc(&mut self, addr: PhysAddr, size: PageSize) {
        self.inner.dealloc(addr, size);
    }

    fn available_frames(&self, size: PageSize) -> usize {
        self.inner.available_frames(size)
    }
}
