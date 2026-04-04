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

    /// Map a 4K page with pre-computed raw PTE flags in a single walk.
    ///
    /// Unlike `map_4k`, this overwrites any existing mapping (no `AlreadyMapped`
    /// check) and takes raw arch-specific PTE flags instead of `MappingFlags`.
    /// Used by COW fork where the child PT is freshly created and the caller
    /// has pre-computed flags including the COW bit.
    pub fn map_4k_raw(
        &mut self,
        virt: VirtAddr,
        phys: PhysAddr,
        raw_flags: u64,
        alloc: &mut dyn FrameAllocator,
    ) -> Result<(), MemoryError> {
        let l3_entry = self.ensure_table(self.root, virt, PageLevel::L3, alloc)?;
        let l2_entry = self.ensure_table(A::Pte::phys_addr(l3_entry), virt, PageLevel::L2, alloc)?;
        let l1_entry = self.ensure_table(A::Pte::phys_addr(l2_entry), virt, PageLevel::L1, alloc)?;
        let l0_phys = A::Pte::phys_addr(l1_entry);
        let idx = pt_index(virt, PageLevel::L0);
        unsafe {
            let page = l0_phys.as_usize() as *mut PageTablePage;
            (*page).entries[idx] = A::Pte::encode(phys, raw_flags);
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

    /// Change the permissions of an existing 4K page mapping.
    /// Preserves the physical address, only updates flags.
    pub unsafe fn protect_4k(
        &mut self,
        virt: VirtAddr,
        flags: MappingFlags,
    ) -> Result<(), MemoryError> {
        let pte_flags = A::mapping_to_pte_flags(flags) | A::leaf_extra_flags();

        let l3 = self.root.as_usize() as *mut PageTablePage;
        let l3e = (*l3).entries[pt_index(virt, PageLevel::L3)];
        if !A::Pte::is_present(l3e) { return Err(MemoryError::NotMapped); }

        let l2 = A::Pte::phys_addr(l3e).as_usize() as *mut PageTablePage;
        let l2e = (*l2).entries[pt_index(virt, PageLevel::L2)];
        if !A::Pte::is_present(l2e) { return Err(MemoryError::NotMapped); }
        if A::Pte::is_huge(l2e) { return Err(MemoryError::InvalidSize); }

        let l1 = A::Pte::phys_addr(l2e).as_usize() as *mut PageTablePage;
        let l1e = (*l1).entries[pt_index(virt, PageLevel::L1)];
        if !A::Pte::is_present(l1e) { return Err(MemoryError::NotMapped); }
        if A::Pte::is_huge(l1e) { return Err(MemoryError::InvalidSize); }

        let l0 = A::Pte::phys_addr(l1e).as_usize() as *mut PageTablePage;
        let idx = pt_index(virt, PageLevel::L0);
        let l0e = (*l0).entries[idx];
        if !A::Pte::is_present(l0e) { return Err(MemoryError::NotMapped); }

        let phys = A::Pte::phys_addr(l0e);
        (*l0).entries[idx] = A::Pte::encode(phys, pte_flags);
        A::flush_tlb(virt);
        Ok(())
    }

    /// Map a single 1GB huge page: virt → phys.
    ///
    /// Writes a huge PTE at L2 (PDPT level). Both addresses must be 1GB-aligned.
    pub fn map_1g(
        &mut self,
        virt: VirtAddr,
        phys: PhysAddr,
        flags: MappingFlags,
        alloc: &mut dyn FrameAllocator,
    ) -> Result<(), MemoryError> {
        if virt.as_usize() & 0x3FFFFFFF != 0 || phys.as_usize() & 0x3FFFFFFF != 0 {
            return Err(MemoryError::MisalignedAddress);
        }
        let pte_flags = A::mapping_to_pte_flags(flags);

        let l3_entry = self.ensure_table(self.root, virt, PageLevel::L3, alloc)?;
        let l2_phys = A::Pte::phys_addr(l3_entry);

        let idx = pt_index(virt, PageLevel::L2);
        unsafe {
            let page = l2_phys.as_usize() as *mut PageTablePage;
            let existing = (*page).entries[idx];
            if A::Pte::is_present(existing) {
                return Err(MemoryError::AlreadyMapped);
            }
            (*page).entries[idx] = A::Pte::encode(phys, pte_flags | A::huge_page_flags());
        }
        Ok(())
    }

    /// Map a single 2MB huge page: virt → phys.
    ///
    /// Writes a huge PTE at L1 (PD level). Both addresses must be 2MB-aligned.
    pub fn map_2m(
        &mut self,
        virt: VirtAddr,
        phys: PhysAddr,
        flags: MappingFlags,
        alloc: &mut dyn FrameAllocator,
    ) -> Result<(), MemoryError> {
        if virt.as_usize() & 0x1FFFFF != 0 || phys.as_usize() & 0x1FFFFF != 0 {
            return Err(MemoryError::MisalignedAddress);
        }
        let pte_flags = A::mapping_to_pte_flags(flags);

        let l3_entry = self.ensure_table(self.root, virt, PageLevel::L3, alloc)?;
        let l2_entry = self.ensure_table(A::Pte::phys_addr(l3_entry), virt, PageLevel::L2, alloc)?;
        let l1_phys = A::Pte::phys_addr(l2_entry);

        let idx = pt_index(virt, PageLevel::L1);
        unsafe {
            let page = l1_phys.as_usize() as *mut PageTablePage;
            let existing = (*page).entries[idx];
            if A::Pte::is_present(existing) {
                return Err(MemoryError::AlreadyMapped);
            }
            (*page).entries[idx] = A::Pte::encode(phys, pte_flags | A::huge_page_flags());
        }
        Ok(())
    }

    /// Split a huge page into the next smaller page size.
    ///
    /// - L1 huge (2MB) → 512 × 4KB entries in a new L0 table.
    /// - L2 huge (1GB) → 512 × 2MB entries in a new L1 table.
    ///
    /// Preserves all permissions from the huge PTE on each child entry.
    /// After splitting, individual small pages can be unmapped or re-protected.
    pub unsafe fn split_huge_page(
        &mut self,
        virt: VirtAddr,
        level: PageLevel,
        alloc: &mut dyn FrameAllocator,
    ) -> Result<(), MemoryError> {
        // Walk to the parent table containing the huge entry
        let l3 = self.root.as_usize() as *mut PageTablePage;
        let l3e = (*l3).entries[pt_index(virt, PageLevel::L3)];
        if !A::Pte::is_present(l3e) { return Err(MemoryError::NotMapped); }

        match level {
            PageLevel::L1 => {
                // Split 2MB → 512 × 4KB
                let l2 = A::Pte::phys_addr(l3e).as_usize() as *mut PageTablePage;
                let l2e = (*l2).entries[pt_index(virt, PageLevel::L2)];
                if !A::Pte::is_present(l2e) { return Err(MemoryError::NotMapped); }

                let l1 = A::Pte::phys_addr(l2e).as_usize() as *mut PageTablePage;
                let idx = pt_index(virt, PageLevel::L1);
                let huge_entry = (*l1).entries[idx];
                if !A::Pte::is_present(huge_entry) || !A::Pte::is_huge(huge_entry) {
                    return Err(MemoryError::NotMapped);
                }

                let huge_phys = A::Pte::phys_addr(huge_entry).as_usize() & !0x1FFFFF;
                // Get permission flags: raw flags minus HUGE bit, plus leaf flags
                let raw_flags = A::Pte::flags(huge_entry);
                let child_flags = (raw_flags & !A::huge_page_flags()) | A::leaf_extra_flags();

                // Allocate new L0 table
                let new_table = alloc.alloc(PageSize::FourK)?;
                let new_ptr = new_table.as_usize() as *mut PageTablePage;
                for i in 0..PT_ENTRIES {
                    let child_phys = PhysAddr::new(huge_phys + i * 4096);
                    (*new_ptr).entries[i] = A::Pte::encode(child_phys, child_flags);
                }

                // Replace huge entry with table entry
                (*l1).entries[idx] = A::Pte::encode(new_table, A::table_entry_flags());
                A::flush_tlb_all();
            }
            PageLevel::L2 => {
                // Split 1GB → 512 × 2MB
                let l2 = A::Pte::phys_addr(l3e).as_usize() as *mut PageTablePage;
                let idx = pt_index(virt, PageLevel::L2);
                let huge_entry = (*l2).entries[idx];
                if !A::Pte::is_present(huge_entry) || !A::Pte::is_huge(huge_entry) {
                    return Err(MemoryError::NotMapped);
                }

                let huge_phys = A::Pte::phys_addr(huge_entry).as_usize() & !0x3FFFFFFF;
                let raw_flags = A::Pte::flags(huge_entry);
                // Children are 2MB huge pages — keep HUGE bit, add leaf flags
                let child_flags = raw_flags | A::leaf_extra_flags();

                let new_table = alloc.alloc(PageSize::FourK)?;
                let new_ptr = new_table.as_usize() as *mut PageTablePage;
                for i in 0..PT_ENTRIES {
                    let child_phys = PhysAddr::new(huge_phys + i * 2 * 1024 * 1024);
                    (*new_ptr).entries[i] = A::Pte::encode(child_phys, child_flags);
                }

                (*l2).entries[idx] = A::Pte::encode(new_table, A::table_entry_flags());
                A::flush_tlb_all();
            }
            _ => return Err(MemoryError::InvalidSize),
        }
        Ok(())
    }

    /// Identity map a range using 1GB/2MB/4K pages where possible.
    pub fn identity_map_range_huge(
        &mut self,
        start: PhysAddr,
        size: usize,
        flags: MappingFlags,
        alloc: &mut dyn FrameAllocator,
    ) -> Result<(), MemoryError> {
        let mut addr = start.as_usize() & !0xFFF;
        let end = (start.as_usize() + size + 0xFFF) & !0xFFF;
        const TWO_MB: usize = 2 * 1024 * 1024;
        const ONE_GB: usize = 1024 * 1024 * 1024;
        let use_1g = A::supports_1g_pages();

        // Lead-in: 4K pages until 2MB-aligned (or 1GB-aligned if using 1G)
        let min_align = if use_1g { ONE_GB } else { TWO_MB };
        let _aligned_start = (addr + min_align - 1) & !(min_align - 1);

        // 4K until first large-page boundary
        let first_2m = (addr + TWO_MB - 1) & !(TWO_MB - 1);
        while addr < first_2m.min(end) {
            let virt = VirtAddr::new(addr);
            if self.translate(virt).is_err() {
                let _ = self.map_4k(virt, PhysAddr::new(addr), flags, alloc);
            }
            addr += 4096;
        }

        // 2MB pages until 1GB-aligned (if using 1G pages)
        if use_1g {
            let first_1g = (addr + ONE_GB - 1) & !(ONE_GB - 1);
            while addr + TWO_MB <= first_1g.min(end) {
                let virt = VirtAddr::new(addr);
                if self.translate(virt).is_err() {
                    let _ = self.map_2m(virt, PhysAddr::new(addr), flags, alloc);
                }
                addr += TWO_MB;
            }

            // Core: 1GB huge pages
            while addr + ONE_GB <= end {
                let virt = VirtAddr::new(addr);
                if self.translate(virt).is_err() {
                    let _ = self.map_1g(virt, PhysAddr::new(addr), flags, alloc);
                }
                addr += ONE_GB;
            }
        }

        // Core: 2MB huge pages
        while addr + TWO_MB <= end {
            let virt = VirtAddr::new(addr);
            if self.translate(virt).is_err() {
                let _ = self.map_2m(virt, PhysAddr::new(addr), flags, alloc);
            }
            addr += TWO_MB;
        }

        // Tail: remaining 4K pages
        while addr < end {
            let virt = VirtAddr::new(addr);
            if self.translate(virt).is_err() {
                let _ = self.map_4k(virt, PhysAddr::new(addr), flags, alloc);
            }
            addr += 4096;
        }
        Ok(())
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

    /// Walk all user-space 4K page mappings with mutable PTE access.
    ///
    /// Like `walk_user_pages` but yields `&mut PageTableEntry` so callers can
    /// modify PTEs in-place (e.g., marking COW) without a separate re-walk.
    /// Also provides the COW bit value for convenience.
    ///
    /// # Safety
    /// Page table must be valid and accessible via physical addresses.
    pub unsafe fn walk_user_pages_mut<F>(&self, mut f: F)
    where F: FnMut(VirtAddr, PhysAddr, &mut PageTableEntry)
    {
        let l3 = self.root.as_usize() as *const PageTablePage;
        for l3i in 0..256 {
            let l3e = (*l3).entries[l3i];
            if !A::Pte::is_present(l3e) { continue; }

            let l2 = A::Pte::phys_addr(l3e).as_usize() as *const PageTablePage;
            for l2i in 0..PT_ENTRIES {
                let l2e = (*l2).entries[l2i];
                if !A::Pte::is_present(l2e) { continue; }
                if A::Pte::is_huge(l2e) { continue; }

                let l1 = A::Pte::phys_addr(l2e).as_usize() as *const PageTablePage;
                for l1i in 0..PT_ENTRIES {
                    let l1e = (*l1).entries[l1i];
                    if !A::Pte::is_present(l1e) { continue; }
                    if A::Pte::is_huge(l1e) { continue; }

                    let l0 = A::Pte::phys_addr(l1e).as_usize() as *mut PageTablePage;
                    for l0i in 0..PT_ENTRIES {
                        let pte = &mut (*l0).entries[l0i];
                        if !A::Pte::is_present(*pte) { continue; }
                        if !A::Pte::is_user(*pte) { continue; }

                        let va = (l3i << 39) | (l2i << 30) | (l1i << 21) | (l0i << 12);
                        let pa = A::Pte::phys_addr(*pte);
                        f(VirtAddr::new(va), pa, pte);
                    }
                }
            }
        }
    }

    /// Return the architecture's COW bit value (delegates to `A::cow_bit()`).
    pub fn cow_bit() -> u64 { A::cow_bit() }

    /// Convert MappingFlags to raw PTE flags (delegates to `A::mapping_to_pte_flags`).
    pub fn pte_flags(flags: MappingFlags) -> u64 {
        A::mapping_to_pte_flags(flags) | A::leaf_extra_flags()
    }

    /// Flush the TLB for a single page (delegates to `A::flush_tlb()`).
    pub unsafe fn flush_tlb(virt: VirtAddr) { A::flush_tlb(virt); }

    /// Flush all non-global TLB entries (delegates to `A::flush_tlb_all()`).
    pub unsafe fn flush_tlb_all() { A::flush_tlb_all(); }

    /// Free the user-space address mapping created during fork.
    ///
    /// Walks user-space L3 entries (0..256), frees all user leaf page frames
    /// (those with the USER flag), then frees the page-table structure pages
    /// (L0/L1/L2 tables and the root PML4 frame).
    ///
    /// Kernel identity-mapped frames (no USER flag) are never freed.
    ///
    /// # Safety
    /// Page table must be a per-process copy. Must NOT be called on the
    /// boot/kernel page table.
    pub unsafe fn free_user_address_space(&self, alloc: &mut dyn FrameAllocator) {
        self.free_user_address_space_inner(alloc, &mut |_| true);
    }

    /// COW-aware variant: calls `should_free_leaf(pa)` for each user leaf frame.
    /// Only deallocates the leaf frame if the closure returns `true`.
    /// Page-table structure pages (L0/L1/L2/root) are always freed — they are
    /// per-process and never shared via COW.
    ///
    /// Use this after a COW fork so that shared frames are only freed when the
    /// last owner releases them (i.e. `dec_ref` returns `true`).
    pub unsafe fn free_user_address_space_cow(
        &self,
        alloc: &mut dyn FrameAllocator,
        should_free_leaf: &mut dyn FnMut(PhysAddr) -> bool,
    ) {
        self.free_user_address_space_inner(alloc, should_free_leaf);
    }

    unsafe fn free_user_address_space_inner(
        &self,
        alloc: &mut dyn FrameAllocator,
        should_free_leaf: &mut dyn FnMut(PhysAddr) -> bool,
    ) {
        let l3 = self.root.as_usize() as *const PageTablePage;
        for l3i in 0..256usize {
            let l3e = (*l3).entries[l3i];
            if !A::Pte::is_present(l3e) { continue; }

            let l2_pa = A::Pte::phys_addr(l3e);
            let l2 = l2_pa.as_usize() as *const PageTablePage;
            for l2i in 0..PT_ENTRIES {
                let l2e = (*l2).entries[l2i];
                if !A::Pte::is_present(l2e) { continue; }
                if A::Pte::is_huge(l2e) { continue; } // skip 1GB pages

                let l1_pa = A::Pte::phys_addr(l2e);
                let l1 = l1_pa.as_usize() as *const PageTablePage;
                for l1i in 0..PT_ENTRIES {
                    let l1e = (*l1).entries[l1i];
                    if !A::Pte::is_present(l1e) { continue; }
                    if A::Pte::is_huge(l1e) { continue; } // skip 2MB pages

                    let l0_pa = A::Pte::phys_addr(l1e);
                    let l0 = l0_pa.as_usize() as *const PageTablePage;
                    for l0i in 0..PT_ENTRIES {
                        let l0e = (*l0).entries[l0i];
                        if !A::Pte::is_present(l0e) { continue; }
                        if !A::Pte::is_user(l0e) { continue; }
                        let leaf_pa = A::Pte::phys_addr(l0e);
                        if should_free_leaf(leaf_pa) {
                            alloc.dealloc(leaf_pa, PageSize::FourK);
                        }
                    }
                    // Page-table structure pages are always per-process — always free.
                    alloc.dealloc(l0_pa, PageSize::FourK);
                }
                alloc.dealloc(l1_pa, PageSize::FourK);
            }
            alloc.dealloc(l2_pa, PageSize::FourK);
        }
        alloc.dealloc(self.root, PageSize::FourK);
    }

    // ── COW (copy-on-write) helpers ─────────────────────────────────

    /// Get a mutable pointer to the leaf (L0) PTE for a 4K virtual address.
    /// Returns None if the mapping doesn't exist at any level.
    unsafe fn leaf_pte_mut(&self, virt: VirtAddr) -> Option<*mut PageTableEntry> {
        self.leaf_pte_and_pa(virt).map(|(pte, _)| pte)
    }

    /// Single walk: return mutable PTE pointer + physical address of the
    /// mapped frame. Avoids redundant walks when callers need both.
    pub unsafe fn leaf_pte_and_pa(&self, virt: VirtAddr) -> Option<(*mut PageTableEntry, PhysAddr)> {
        let l3 = self.root.as_usize() as *const PageTablePage;
        let l3e = (*l3).entries[pt_index(virt, PageLevel::L3)];
        if !A::Pte::is_present(l3e) { return None; }

        let l2 = A::Pte::phys_addr(l3e).as_usize() as *const PageTablePage;
        let l2e = (*l2).entries[pt_index(virt, PageLevel::L2)];
        if !A::Pte::is_present(l2e) || A::Pte::is_huge(l2e) { return None; }

        let l1 = A::Pte::phys_addr(l2e).as_usize() as *const PageTablePage;
        let l1e = (*l1).entries[pt_index(virt, PageLevel::L1)];
        if !A::Pte::is_present(l1e) || A::Pte::is_huge(l1e) { return None; }

        let l0 = A::Pte::phys_addr(l1e).as_usize() as *mut PageTablePage;
        let pte = &mut (*l0).entries[pt_index(virt, PageLevel::L0)];
        let pa = A::Pte::phys_addr(*pte);
        Some((pte as *mut PageTableEntry, pa))
    }

    /// Mark a leaf PTE as COW: clear writable, set COW software bit, flush TLB.
    ///
    /// The TLB flush is mandatory: without it, the CPU may keep using the stale
    /// writable TLB entry and write to the shared frame without triggering a fault.
    pub unsafe fn mark_cow(&self, virt: VirtAddr) {
        if let Some(pte) = self.leaf_pte_mut(virt) {
            A::Pte::set_writable(&mut *pte, false);
            (*pte).0 |= A::cow_bit();
            A::flush_tlb(virt);
        }
    }

    /// Check if a leaf PTE has the COW bit set.
    pub unsafe fn is_cow(&self, virt: VirtAddr) -> bool {
        if let Some(pte) = self.leaf_pte_mut(virt) {
            (*pte).0 & A::cow_bit() != 0
        } else {
            false
        }
    }

    /// Resolve a COW fault: allocate a new page, copy the old page's contents,
    /// remap the VA to the new page as writable, clear COW bit, flush TLB.
    /// Returns the old physical address (caller may need to decrement refcount).
    pub unsafe fn resolve_cow(
        &self, virt: VirtAddr, alloc: &mut dyn FrameAllocator,
    ) -> Result<PhysAddr, MemoryError> {
        let pte = self.leaf_pte_mut(virt).ok_or(MemoryError::NotMapped)?;
        let old_pa = A::Pte::phys_addr(*pte);

        // Allocate new frame and copy
        let new_frame = alloc.alloc(PageSize::FourK)?;
        let src = old_pa.as_usize() as *const u8;
        let dst = new_frame.as_usize() as *mut u8;
        core::ptr::copy_nonoverlapping(src, dst, 4096);

        // Update PTE: new frame, writable, clear COW
        let old_flags = A::Pte::flags(*pte);
        *pte = A::Pte::encode(new_frame, old_flags & !A::cow_bit());
        A::Pte::set_writable(&mut *pte, true);

        A::flush_tlb(virt);

        Ok(old_pa)
    }

    /// Make a COW page writable without copying (refcount == 1 fast path).
    /// Clears COW bit and sets writable. Flushes TLB.
    pub unsafe fn make_writable(&self, virt: VirtAddr) {
        if let Some(pte) = self.leaf_pte_mut(virt) {
            (*pte).0 &= !A::cow_bit();
            A::Pte::set_writable(&mut *pte, true);
            A::flush_tlb(virt);
        }
    }

    /// Single-walk COW fault resolution.
    ///
    /// Walks L3→L0 once to get the PTE. If the COW bit is set, calls
    /// `refcount_fn(pa)` to determine the sharing count, then resolves:
    /// - `refcount <= 1` (sole owner): clears COW, sets writable. Returns `Ok(None)`.
    /// - `refcount > 1` (shared): copies page to new frame, remaps writable,
    ///   clears COW. Returns `Ok(Some(old_pa))` so the caller can `dec_ref`.
    /// - Not COW: returns `Err(())`.
    pub unsafe fn resolve_cow_fault(
        &self,
        virt: VirtAddr,
        alloc: &mut dyn FrameAllocator,
        refcount_fn: impl Fn(PhysAddr) -> u32,
    ) -> Result<Option<PhysAddr>, ()> {
        let (pte, old_pa) = self.leaf_pte_and_pa(virt).ok_or(())?;

        if (*pte).0 & A::cow_bit() == 0 {
            return Err(()); // Not a COW page
        }

        let refcount = refcount_fn(old_pa);
        if refcount <= 1 {
            // Sole owner: just make writable, no copy needed
            (*pte).0 &= !A::cow_bit();
            A::Pte::set_writable(&mut *pte, true);
            A::flush_tlb(virt);
            Ok(None)
        } else {
            // Shared: allocate new frame and copy
            let new_frame = alloc.alloc(PageSize::FourK).map_err(|_| ())?;
            core::ptr::copy_nonoverlapping(
                old_pa.as_usize() as *const u8,
                new_frame.as_usize() as *mut u8,
                4096,
            );
            // Update PTE: new frame, writable, no COW
            let old_flags = A::Pte::flags(*pte);
            *pte = A::Pte::encode(new_frame, old_flags & !A::cow_bit());
            A::Pte::set_writable(&mut *pte, true);
            A::flush_tlb(virt);
            Ok(Some(old_pa))
        }
    }

    /// Remap an existing mapping to a new physical frame with new flags.
    pub unsafe fn remap(&self, virt: VirtAddr, new_phys: PhysAddr, new_flags: u64) {
        if let Some(pte) = self.leaf_pte_mut(virt) {
            *pte = A::Pte::encode(new_phys, new_flags);
            A::flush_tlb(virt);
        }
    }
}
