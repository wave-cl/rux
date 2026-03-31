/// Generic 4-level page table walker, parameterized over architecture.
///
/// The walking algorithm is identical on x86_64 and aarch64 (both use
/// 4-level 4KB-granule page tables with 512 entries per level).
/// Only PTE encoding, TLB flush, and flag conversion differ — those
/// are provided by the `ArchPaging` trait.

use core::marker::PhantomData;
use rux_klib::{PhysAddr, VirtAddr};
use rux_arch::pte::{PageTableEntry, PageTableEntryOps};
use crate::{ArchPaging, MappingFlags, MemoryError, PageSize, FrameAllocator};
use crate::pt::{PageTablePage, PT_ENTRIES, pt_index, PageLevel};

/// A 4-level page table rooted at a physical address.
/// Generic over `A: ArchPaging` which provides PTE encoding and TLB ops.
pub struct PageTable4Level<A: ArchPaging> {
    root: PhysAddr,
    _arch: PhantomData<A>,
}

impl<A: ArchPaging> PageTable4Level<A> {
    /// Create a new empty page table. Allocates the root page.
    pub fn new(alloc: &mut dyn FrameAllocator) -> Result<Self, MemoryError> {
        let root = alloc.alloc(PageSize::FourK)?;
        unsafe {
            let page = root.as_usize() as *mut PageTablePage;
            for i in 0..PT_ENTRIES {
                (*page).entries[i] = PageTableEntry::EMPTY;
            }
        }
        Ok(Self { root, _arch: PhantomData })
    }

    /// Wrap an existing page table root (e.g., from CR3 or TTBR0_EL1).
    pub fn from_root(root: PhysAddr) -> Self {
        Self { root, _arch: PhantomData }
    }

    /// Alias for `from_root` — legacy name.
    pub fn from_cr3(root: PhysAddr) -> Self {
        Self::from_root(root)
    }

    /// Get the root physical address.
    pub fn root_phys(&self) -> PhysAddr {
        self.root
    }

    /// Map a single 4K page: virt → phys with the given flags.
    pub fn map_4k(
        &mut self,
        virt: VirtAddr,
        phys: PhysAddr,
        flags: MappingFlags,
        alloc: &mut dyn FrameAllocator,
    ) -> Result<(), MemoryError> {
        let pte_flags = A::mapping_to_pte_flags(flags);

        // Walk levels 3 → 1, creating intermediate tables as needed
        let l3_entry = self.ensure_table(self.root, virt, PageLevel::L3, alloc)?;
        let l2_phys = A::Pte::phys_addr(l3_entry);

        let l2_entry = self.ensure_table(l2_phys, virt, PageLevel::L2, alloc)?;
        let l1_phys = A::Pte::phys_addr(l2_entry);

        let l1_entry = self.ensure_table(l1_phys, virt, PageLevel::L1, alloc)?;
        let l0_phys = A::Pte::phys_addr(l1_entry);

        // Level 0: write the leaf PTE
        let idx = pt_index(virt, PageLevel::L0);
        unsafe {
            let page = l0_phys.as_usize() as *mut PageTablePage;
            let existing = (*page).entries[idx];
            if A::Pte::is_present(existing) {
                return Err(MemoryError::AlreadyMapped);
            }
            (*page).entries[idx] = A::Pte::encode(phys, pte_flags | A::leaf_extra_flags());
        }
        Ok(())
    }

    /// Translate a virtual address to its physical address, but only if
    /// the leaf PTE is writable. Returns `NotMapped` if not present or read-only.
    pub fn translate_writable(&self, virt: VirtAddr) -> Result<PhysAddr, MemoryError> {
        unsafe {
            let l3 = self.root.as_usize() as *const PageTablePage;
            let l3e = (*l3).entries[pt_index(virt, PageLevel::L3)];
            if !A::Pte::is_present(l3e) { return Err(MemoryError::NotMapped); }

            let l2 = A::Pte::phys_addr(l3e).as_usize() as *const PageTablePage;
            let l2e = (*l2).entries[pt_index(virt, PageLevel::L2)];
            if !A::Pte::is_present(l2e) { return Err(MemoryError::NotMapped); }
            if A::Pte::is_huge(l2e) {
                if !A::Pte::is_writable(l2e) { return Err(MemoryError::NotMapped); }
                let base = A::Pte::phys_addr(l2e).as_usize() & !0x3FFFFFFF;
                return Ok(PhysAddr::new(base + (virt.as_usize() & 0x3FFFFFFF)));
            }

            let l1 = A::Pte::phys_addr(l2e).as_usize() as *const PageTablePage;
            let l1e = (*l1).entries[pt_index(virt, PageLevel::L1)];
            if !A::Pte::is_present(l1e) { return Err(MemoryError::NotMapped); }
            if A::Pte::is_huge(l1e) {
                if !A::Pte::is_writable(l1e) { return Err(MemoryError::NotMapped); }
                let base = A::Pte::phys_addr(l1e).as_usize() & !0x1FFFFF;
                return Ok(PhysAddr::new(base + (virt.as_usize() & 0x1FFFFF)));
            }

            let l0 = A::Pte::phys_addr(l1e).as_usize() as *const PageTablePage;
            let l0e = (*l0).entries[pt_index(virt, PageLevel::L0)];
            if !A::Pte::is_present(l0e) { return Err(MemoryError::NotMapped); }
            if !A::Pte::is_writable(l0e) { return Err(MemoryError::NotMapped); }

            let phys = A::Pte::phys_addr(l0e).as_usize();
            Ok(PhysAddr::new(phys + (virt.as_usize() & 0xFFF)))
        }
    }

    /// Translate a virtual address to its physical address.
    pub fn translate(&self, virt: VirtAddr) -> Result<PhysAddr, MemoryError> {
        unsafe {
            // Level 3
            let l3 = self.root.as_usize() as *const PageTablePage;
            let l3e = (*l3).entries[pt_index(virt, PageLevel::L3)];
            if !A::Pte::is_present(l3e) { return Err(MemoryError::NotMapped); }

            // Level 2
            let l2 = A::Pte::phys_addr(l3e).as_usize() as *const PageTablePage;
            let l2e = (*l2).entries[pt_index(virt, PageLevel::L2)];
            if !A::Pte::is_present(l2e) { return Err(MemoryError::NotMapped); }
            if A::Pte::is_huge(l2e) {
                let base = A::Pte::phys_addr(l2e).as_usize() & !0x3FFFFFFF;
                return Ok(PhysAddr::new(base + (virt.as_usize() & 0x3FFFFFFF)));
            }

            // Level 1
            let l1 = A::Pte::phys_addr(l2e).as_usize() as *const PageTablePage;
            let l1e = (*l1).entries[pt_index(virt, PageLevel::L1)];
            if !A::Pte::is_present(l1e) { return Err(MemoryError::NotMapped); }
            if A::Pte::is_huge(l1e) {
                let base = A::Pte::phys_addr(l1e).as_usize() & !0x1FFFFF;
                return Ok(PhysAddr::new(base + (virt.as_usize() & 0x1FFFFF)));
            }

            // Level 0
            let l0 = A::Pte::phys_addr(l1e).as_usize() as *const PageTablePage;
            let l0e = (*l0).entries[pt_index(virt, PageLevel::L0)];
            if !A::Pte::is_present(l0e) { return Err(MemoryError::NotMapped); }

            let phys = A::Pte::phys_addr(l0e).as_usize();
            Ok(PhysAddr::new(phys + (virt.as_usize() & 0xFFF)))
        }
    }

    /// Unmap a single 4K page. Returns the physical address that was mapped.
    pub fn unmap_4k(&mut self, virt: VirtAddr) -> Result<PhysAddr, MemoryError> {
        unsafe {
            let l3 = self.root.as_usize() as *const PageTablePage;
            let l3e = (*l3).entries[pt_index(virt, PageLevel::L3)];
            if !A::Pte::is_present(l3e) { return Err(MemoryError::NotMapped); }

            let l2 = A::Pte::phys_addr(l3e).as_usize() as *const PageTablePage;
            let l2e = (*l2).entries[pt_index(virt, PageLevel::L2)];
            if !A::Pte::is_present(l2e) { return Err(MemoryError::NotMapped); }

            let l1 = A::Pte::phys_addr(l2e).as_usize() as *const PageTablePage;
            let l1e = (*l1).entries[pt_index(virt, PageLevel::L1)];
            if !A::Pte::is_present(l1e) { return Err(MemoryError::NotMapped); }

            let l0 = A::Pte::phys_addr(l1e).as_usize() as *mut PageTablePage;
            let idx = pt_index(virt, PageLevel::L0);
            let entry = (*l0).entries[idx];
            if !A::Pte::is_present(entry) { return Err(MemoryError::NotMapped); }

            let phys = A::Pte::phys_addr(entry);
            (*l0).entries[idx] = PageTableEntry::EMPTY;

            A::flush_tlb(virt);

            Ok(phys)
        }
    }

    /// Map a contiguous range of 4K pages: identity map phys → phys.
    pub fn identity_map_range(
        &mut self,
        start: PhysAddr,
        size: usize,
        flags: MappingFlags,
        alloc: &mut dyn FrameAllocator,
    ) -> Result<(), MemoryError> {
        let mut addr = start.as_usize() & !0xFFF;
        let end = (start.as_usize() + size + 0xFFF) & !0xFFF;
        while addr < end {
            let virt = VirtAddr::new(addr);
            if self.translate(virt).is_err() {
                let _ = self.map_4k(virt, PhysAddr::new(addr), flags, alloc);
            }
            addr += 4096;
        }
        Ok(())
    }

    // ── Internal ─────────────────────────────────────────────────────

    fn ensure_table(
        &self,
        table_phys: PhysAddr,
        virt: VirtAddr,
        level: PageLevel,
        alloc: &mut dyn FrameAllocator,
    ) -> Result<PageTableEntry, MemoryError> {
        let idx = pt_index(virt, level);
        unsafe {
            let table = table_phys.as_usize() as *mut PageTablePage;
            let entry = (*table).entries[idx];
            if A::Pte::is_present(entry) {
                return Ok(entry);
            }

            let new_page = alloc.alloc(PageSize::FourK)?;
            let new_ptr = new_page.as_usize() as *mut PageTablePage;
            for i in 0..PT_ENTRIES {
                (*new_ptr).entries[i] = PageTableEntry::EMPTY;
            }

            let new_entry = A::Pte::encode(new_page, A::table_entry_flags());
            (*table).entries[idx] = new_entry;
            Ok(new_entry)
        }
    }

    /// Walk all user-space 4K page mappings. Calls `f(va, pa, raw_pte_flags)`
    /// for each present leaf entry in the lower half of the address space
    /// (L3 indices 0..256 on x86_64, or 0..256 on aarch64 — user space).
    ///
    /// # Safety
    /// Page table must be valid and accessible via physical addresses.
    pub unsafe fn walk_user_pages<F>(&self, mut f: F)
    where F: FnMut(VirtAddr, PhysAddr, u64)
    {
        let l3 = self.root.as_usize() as *const PageTablePage;
        // User space: L3 indices 0..256 (lower 128 TiB of canonical 48-bit space)
        for l3i in 0..256 {
            let l3e = (*l3).entries[l3i];
            if !A::Pte::is_present(l3e) { continue; }

            let l2 = A::Pte::phys_addr(l3e).as_usize() as *const PageTablePage;
            for l2i in 0..PT_ENTRIES {
                let l2e = (*l2).entries[l2i];
                if !A::Pte::is_present(l2e) { continue; }
                if A::Pte::is_huge(l2e) { continue; } // skip 1G pages (kernel identity map)

                let l1 = A::Pte::phys_addr(l2e).as_usize() as *const PageTablePage;
                for l1i in 0..PT_ENTRIES {
                    let l1e = (*l1).entries[l1i];
                    if !A::Pte::is_present(l1e) { continue; }
                    if A::Pte::is_huge(l1e) { continue; } // skip 2M pages

                    let l0 = A::Pte::phys_addr(l1e).as_usize() as *const PageTablePage;
                    for l0i in 0..PT_ENTRIES {
                        let l0e = (*l0).entries[l0i];
                        if !A::Pte::is_present(l0e) { continue; }
                        if !A::Pte::is_user(l0e) { continue; } // skip kernel pages

                        let va = (l3i << 39) | (l2i << 30) | (l1i << 21) | (l0i << 12);
                        let pa = A::Pte::phys_addr(l0e);
                        let flags = A::Pte::flags(l0e);
                        f(VirtAddr::new(va), pa, flags);
                    }
                }
            }
        }
    }
}
