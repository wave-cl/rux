/// 4-level x86_64 page table walker.
///
/// Operates on identity-mapped physical memory — reads/writes page table
/// entries directly at their physical addresses. Uses the arch PTE types
/// from rux-arch and allocates page table pages from a frame allocator.

use rux_klib::{PhysAddr, VirtAddr};
use rux_arch::pte::{PageTableEntry, PageTableEntryOps};
use rux_arch::pte::x86_64::{self as pte, X86_64Pte};
use rux_mm::{MappingFlags, MemoryError, PageSize, FrameAllocator};
use rux_mm::pt::{PageTablePage, PT_ENTRIES, pt_index, PageLevel};

/// A 4-level page table rooted at a physical PML4 address.
/// All page table pages are allocated from the provided frame allocator.
pub struct PageTable4Level {
    /// Physical address of the PML4 (top-level page table page).
    root: PhysAddr,
}

impl PageTable4Level {
    /// Create a new empty page table. Allocates a PML4 page.
    pub fn new(alloc: &mut dyn FrameAllocator) -> Result<Self, MemoryError> {
        let root = alloc.alloc(PageSize::FourK)?;
        // Zero the PML4 page
        unsafe {
            let page = root.as_usize() as *mut PageTablePage;
            for i in 0..PT_ENTRIES {
                (*page).entries[i] = PageTableEntry::EMPTY;
            }
        }
        Ok(Self { root })
    }

    /// Get the root physical address (for CR3).
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
        let pte_flags = mapping_to_pte_flags(flags);

        // Walk levels 3 → 1, creating intermediate tables as needed
        let pml4_entry = self.ensure_table(self.root, virt, PageLevel::L3, alloc)?;
        let pdpt_phys = X86_64Pte::phys_addr(pml4_entry);

        let pdpt_entry = self.ensure_table(pdpt_phys, virt, PageLevel::L2, alloc)?;
        let pd_phys = X86_64Pte::phys_addr(pdpt_entry);

        let pd_entry = self.ensure_table(pd_phys, virt, PageLevel::L1, alloc)?;
        let pt_phys = X86_64Pte::phys_addr(pd_entry);

        // Level 0: write the leaf PTE
        let pt_idx = pt_index(virt, PageLevel::L0);
        unsafe {
            let pt_page = pt_phys.as_usize() as *mut PageTablePage;
            let existing = (*pt_page).entries[pt_idx];
            if X86_64Pte::is_present(existing) {
                return Err(MemoryError::AlreadyMapped);
            }
            (*pt_page).entries[pt_idx] = X86_64Pte::encode(phys, pte_flags);
        }

        Ok(())
    }

    /// Translate a virtual address to its physical address.
    pub fn translate(&self, virt: VirtAddr) -> Result<PhysAddr, MemoryError> {
        unsafe {
            // Level 3: PML4
            let pml4 = self.root.as_usize() as *const PageTablePage;
            let pml4e = (*pml4).entries[pt_index(virt, PageLevel::L3)];
            if !X86_64Pte::is_present(pml4e) { return Err(MemoryError::NotMapped); }

            // Level 2: PDPT
            let pdpt = X86_64Pte::phys_addr(pml4e).as_usize() as *const PageTablePage;
            let pdpte = (*pdpt).entries[pt_index(virt, PageLevel::L2)];
            if !X86_64Pte::is_present(pdpte) { return Err(MemoryError::NotMapped); }
            // Check for 1G huge page
            if X86_64Pte::is_huge(pdpte) {
                let base = X86_64Pte::phys_addr(pdpte).as_usize() & !0x3FFFFFFF;
                return Ok(PhysAddr::new(base + (virt.as_usize() & 0x3FFFFFFF)));
            }

            // Level 1: PD
            let pd = X86_64Pte::phys_addr(pdpte).as_usize() as *const PageTablePage;
            let pde = (*pd).entries[pt_index(virt, PageLevel::L1)];
            if !X86_64Pte::is_present(pde) { return Err(MemoryError::NotMapped); }
            // Check for 2M huge page
            if X86_64Pte::is_huge(pde) {
                let base = X86_64Pte::phys_addr(pde).as_usize() & !0x1FFFFF;
                return Ok(PhysAddr::new(base + (virt.as_usize() & 0x1FFFFF)));
            }

            // Level 0: PT
            let pt = X86_64Pte::phys_addr(pde).as_usize() as *const PageTablePage;
            let pte_entry = (*pt).entries[pt_index(virt, PageLevel::L0)];
            if !X86_64Pte::is_present(pte_entry) { return Err(MemoryError::NotMapped); }

            let page_phys = X86_64Pte::phys_addr(pte_entry).as_usize();
            let offset = virt.as_usize() & 0xFFF;
            Ok(PhysAddr::new(page_phys + offset))
        }
    }

    /// Unmap a single 4K page. Returns the physical address that was mapped.
    pub fn unmap_4k(&mut self, virt: VirtAddr) -> Result<PhysAddr, MemoryError> {
        unsafe {
            let pml4 = self.root.as_usize() as *const PageTablePage;
            let pml4e = (*pml4).entries[pt_index(virt, PageLevel::L3)];
            if !X86_64Pte::is_present(pml4e) { return Err(MemoryError::NotMapped); }

            let pdpt = X86_64Pte::phys_addr(pml4e).as_usize() as *const PageTablePage;
            let pdpte = (*pdpt).entries[pt_index(virt, PageLevel::L2)];
            if !X86_64Pte::is_present(pdpte) { return Err(MemoryError::NotMapped); }

            let pd = X86_64Pte::phys_addr(pdpte).as_usize() as *const PageTablePage;
            let pde = (*pd).entries[pt_index(virt, PageLevel::L1)];
            if !X86_64Pte::is_present(pde) { return Err(MemoryError::NotMapped); }

            let pt = X86_64Pte::phys_addr(pde).as_usize() as *mut PageTablePage;
            let idx = pt_index(virt, PageLevel::L0);
            let entry = (*pt).entries[idx];
            if !X86_64Pte::is_present(entry) { return Err(MemoryError::NotMapped); }

            let phys = X86_64Pte::phys_addr(entry);
            (*pt).entries[idx] = PageTableEntry::EMPTY;

            // TLB flush for this page
            core::arch::asm!("invlpg [{}]", in(reg) virt.as_usize(), options(nostack, preserves_flags));

            Ok(phys)
        }
    }

    // ── Internal helpers ────────────────────────────────────────────────

    /// Ensure an intermediate page table entry exists at the given level.
    /// If it doesn't exist, allocate a new page table page and create it.
    /// Returns the entry (which points to the next-level table).
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
            if X86_64Pte::is_present(entry) {
                return Ok(entry);
            }

            // Allocate a new page table page
            let new_page = alloc.alloc(PageSize::FourK)?;
            // Zero it
            let new_ptr = new_page.as_usize() as *mut PageTablePage;
            for i in 0..PT_ENTRIES {
                (*new_ptr).entries[i] = PageTableEntry::EMPTY;
            }

            // Create the entry pointing to the new page
            let new_entry = X86_64Pte::encode(
                new_page,
                pte::PRESENT | pte::WRITABLE | pte::USER,
            );
            (*table).entries[idx] = new_entry;
            Ok(new_entry)
        }
    }
}

/// Convert MappingFlags to x86_64 PTE flags.
fn mapping_to_pte_flags(flags: MappingFlags) -> u64 {
    let mut pte_flags = pte::PRESENT;
    if flags.contains(MappingFlags::WRITE) {
        pte_flags |= pte::WRITABLE;
    }
    if flags.contains(MappingFlags::USER) {
        pte_flags |= pte::USER;
    }
    if !flags.contains(MappingFlags::EXECUTE) {
        pte_flags |= pte::NO_EXECUTE;
    }
    if flags.contains(MappingFlags::GLOBAL) {
        pte_flags |= pte::GLOBAL;
    }
    if flags.contains(MappingFlags::NO_CACHE) {
        pte_flags |= pte::PCD;
    }
    if flags.contains(MappingFlags::WRITE_THROUGH) {
        pte_flags |= pte::PWT;
    }
    pte_flags
}
