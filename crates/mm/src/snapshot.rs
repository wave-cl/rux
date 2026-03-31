//! Page snapshot: save and restore writable user pages across vfork.
//!
//! Used by the vfork implementation to snapshot the parent's writable
//! pages before the child runs, then restore them after exec/exit.

use rux_klib::{PhysAddr, VirtAddr};
use crate::pt4::PageTable4Level;
use crate::{ArchPaging, FrameAllocator};

/// Maximum number of pages that can be snapshotted.
pub const SNAP_MAX: usize = 1024;

/// Holds the state for a set of snapshotted pages.
pub struct PageSnapshot {
    va: [usize; SNAP_MAX],
    orig_phys: [usize; SNAP_MAX],
    copy_phys: [usize; SNAP_MAX],
    count: usize,
}

impl PageSnapshot {
    pub const fn new() -> Self {
        Self {
            va: [0; SNAP_MAX],
            orig_phys: [0; SNAP_MAX],
            copy_phys: [0; SNAP_MAX],
            count: 0,
        }
    }

    /// Snapshot one writable page: copy the physical frame and record the mapping.
    pub unsafe fn snap_page<A: ArchPaging>(
        &mut self,
        page_va: usize,
        upt: &mut PageTable4Level<A>,
        alloc: &mut dyn FrameAllocator,
        alloc_base: usize,
    ) {
        if let Ok(orig_pa) = upt.translate_writable(VirtAddr::new(page_va)) {
            let orig_page = orig_pa.as_usize() & !0xFFF;
            if orig_page >= alloc_base && self.count < SNAP_MAX {
                if let Ok(snap_pa) = alloc.alloc(crate::PageSize::FourK) {
                    core::ptr::copy_nonoverlapping(
                        orig_page as *const u8, snap_pa.as_usize() as *mut u8, 4096);
                    self.va[self.count] = page_va;
                    self.orig_phys[self.count] = orig_page;
                    self.copy_phys[self.count] = snap_pa.as_usize();
                    self.count += 1;
                }
            }
        }
    }

    /// Snapshot all writable user pages across three ranges:
    /// 1. ELF data/BSS (0x1000..program_brk)
    /// 2. mmap'd heap/TLS (0x10000000..mmap_base)
    /// 3. User stack area (stack canary protection)
    pub unsafe fn snapshot_ranges<A: ArchPaging>(
        &mut self,
        upt: &mut PageTable4Level<A>,
        alloc: &mut dyn FrameAllocator,
        program_brk: usize,
        mmap_base: usize,
        stack_page: usize,
        stack_pages: usize,
    ) {
        self.count = 0;
        let alloc_base = alloc.alloc_base().as_usize();

        let mut va = 0x1000usize;
        while va < program_brk { self.snap_page(va, upt, alloc, alloc_base); va += 4096; }

        va = 0x10000000usize;
        while va < mmap_base { self.snap_page(va, upt, alloc, alloc_base); va += 4096; }

        va = stack_page.saturating_sub(stack_pages * 4096);
        while va <= stack_page { self.snap_page(va, upt, alloc, alloc_base); va += 4096; }
    }

    /// Restore all snapshotted pages and free the snapshot copies.
    pub unsafe fn restore_and_free(&mut self, alloc: &mut dyn FrameAllocator) {
        for i in 0..self.count {
            core::ptr::copy_nonoverlapping(
                self.copy_phys[i] as *const u8,
                self.orig_phys[i] as *mut u8, 4096);
            alloc.dealloc(PhysAddr::new(self.copy_phys[i]), crate::PageSize::FourK);
        }
        self.count = 0;
    }
}
