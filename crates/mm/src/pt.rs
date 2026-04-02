use rux_klib::{PhysAddr, VirtAddr};
use crate::{MappingFlags, MemoryError};
use rux_arch::pte::PageTableEntry;

/// Page table levels (for 4-level paging on both x86_64 and aarch64).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PageLevel {
    /// 4K page (leaf of level 0 / PT on x86_64 / L3 on aarch64)
    L0 = 0,
    /// 2M huge page (level 1 / PD on x86_64 / L2 on aarch64)
    L1 = 1,
    /// 1G huge page (level 2 / PDPT on x86_64 / L1 on aarch64)
    L2 = 2,
    /// 512G root (level 3 / PML4 on x86_64 / L0 on aarch64)
    L3 = 3,
}

/// Number of entries per page table page (4K / 8 bytes = 512).
pub const PT_ENTRIES: usize = 512;

/// A single page of page table entries (4096 bytes, page-aligned).
#[repr(C, align(4096))]
pub struct PageTablePage {
    pub entries: [PageTableEntry; PT_ENTRIES],
}

const _: () = assert!(core::mem::size_of::<PageTablePage>() == 4096);

impl PageTablePage {
    pub const EMPTY: Self = Self {
        entries: [PageTableEntry::EMPTY; PT_ENTRIES],
    };
}

/// Result of translating a virtual address.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct TranslateResult {
    /// Physical address the virtual address maps to.
    pub phys: PhysAddr,
    /// Mapping flags on this page.
    pub flags: MappingFlags,
    /// Page table level where the mapping was found (L0=4K, L1=2M, L2=1G).
    pub level: PageLevel,
    pub _pad: [u8; 2],
}

/// Extended page table operations beyond the basic PageTable trait.
///
/// # Safety
/// All methods manipulate page table structures that directly control
/// hardware address translation.
pub unsafe trait PageTableWalker {
    /// Walk the page table to translate a virtual address.
    fn walk(&self, vaddr: VirtAddr) -> Result<TranslateResult, MemoryError>;

    /// Map a range of virtual addresses to physical addresses.
    fn map_range(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        size: usize,
        flags: MappingFlags,
    ) -> Result<(), MemoryError>;

    /// Unmap a range of virtual addresses.
    fn unmap_range(
        &mut self,
        vaddr: VirtAddr,
        size: usize,
    ) -> Result<(), MemoryError>;

    /// Change protection flags on a range of pages.
    fn protect(
        &mut self,
        vaddr: VirtAddr,
        size: usize,
        flags: MappingFlags,
    ) -> Result<(), MemoryError>;

    /// Get the physical address of the root page table page.
    /// Used for CR3 (x86_64) or TTBR0_EL1 (aarch64) writes.
    fn root_phys(&self) -> PhysAddr;
}

// ── Index extraction helpers ────────────────────────────────────────────

/// Extract the page table index at a given level from a virtual address.
/// Level 0: bits 12-20 (PT index)
/// Level 1: bits 21-29 (PD index)
/// Level 2: bits 30-38 (PDPT index)
/// Level 3: bits 39-47 (PML4 index)
#[inline(always)]
pub const fn pt_index(vaddr: VirtAddr, level: PageLevel) -> usize {
    let shift = 12 + (level as usize) * 9;
    (vaddr.as_usize() >> shift) & 0x1FF
}

/// Page offset within a 4K page (bits 0-11).
#[inline(always)]
pub const fn page_offset(vaddr: VirtAddr) -> usize {
    vaddr.as_usize() & 0xFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pt_index_extracts_correctly() {
        // Virtual address 0x0000_7F80_0020_1000:
        // Level 0 (PT):   bits 12-20 = 0x001 = 1
        // Level 1 (PD):   bits 21-29 = 0x001 = 1
        // Level 2 (PDPT): bits 30-38 = 0x000 = 0
        // Level 3 (PML4): bits 39-47 = 0x0FF = 255
        let vaddr = VirtAddr::new(0x0000_7F80_0020_1000);
        assert_eq!(pt_index(vaddr, PageLevel::L0), 1);
        assert_eq!(pt_index(vaddr, PageLevel::L1), 1);
        assert_eq!(pt_index(vaddr, PageLevel::L2), 0);
        assert_eq!(pt_index(vaddr, PageLevel::L3), 255);
    }

    #[test]
    fn page_offset_extracts_correctly() {
        let vaddr = VirtAddr::new(0xDEAD_BEEF_1ABC);
        assert_eq!(page_offset(vaddr), 0xABC);
    }

    #[test]
    fn pt_index_zero_address() {
        let vaddr = VirtAddr::new(0);
        assert_eq!(pt_index(vaddr, PageLevel::L0), 0);
        assert_eq!(pt_index(vaddr, PageLevel::L3), 0);
    }

    #[test]
    fn pt_index_max_values() {
        // All index bits set: 0x1FF at each level
        // Level 0: bits 12-20 all set → address has 0x1FF_000
        let vaddr = VirtAddr::new(0x0000_FFFF_FFFF_F000);
        assert_eq!(pt_index(vaddr, PageLevel::L0), 0x1FF);
        assert_eq!(pt_index(vaddr, PageLevel::L1), 0x1FF);
        assert_eq!(pt_index(vaddr, PageLevel::L2), 0x1FF);
        assert_eq!(pt_index(vaddr, PageLevel::L3), 0x1FF);
    }

    #[test]
    fn page_table_page_size() {
        assert_eq!(core::mem::size_of::<PageTablePage>(), 4096);
        assert_eq!(core::mem::align_of::<PageTablePage>(), 4096);
    }
}
