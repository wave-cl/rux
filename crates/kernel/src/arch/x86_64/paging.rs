/// x86_64 page table support.
///
/// Implements `ArchPaging` for x86_64, providing PTE flag conversion,
/// TLB flush (invlpg), and page table activation (CR3 write).
/// The generic 4-level walker lives in `rux_mm::pt4`.

use rux_klib::{PhysAddr, VirtAddr};
use rux_arch::pte::x86_64::{self as pte, X86_64Pte};
use rux_mm::{ArchPaging, MappingFlags};

/// x86_64 architecture paging configuration.
pub struct X86Paging;

impl ArchPaging for X86Paging {
    type Pte = X86_64Pte;

    fn mapping_to_pte_flags(flags: MappingFlags) -> u64 {
        let mut f = pte::PRESENT;
        if flags.contains(MappingFlags::WRITE) {
            f |= pte::WRITABLE;
        }
        if flags.contains(MappingFlags::USER) {
            f |= pte::USER;
        }
        if !flags.contains(MappingFlags::EXECUTE) {
            f |= pte::NO_EXECUTE;
        }
        if flags.contains(MappingFlags::GLOBAL) {
            f |= pte::GLOBAL;
        }
        if flags.contains(MappingFlags::NO_CACHE) {
            f |= pte::PCD;
        }
        if flags.contains(MappingFlags::WRITE_THROUGH) {
            f |= pte::PWT;
        }
        f
    }

    fn leaf_extra_flags() -> u64 {
        0 // x86_64 leaf PTEs need no extra flags beyond mapping_to_pte_flags
    }

    fn table_entry_flags() -> u64 {
        pte::PRESENT | pte::WRITABLE | pte::USER
    }

    unsafe fn flush_tlb(virt: VirtAddr) {
        core::arch::asm!(
            "invlpg [{}]",
            in(reg) virt.as_usize(),
            options(nostack, preserves_flags)
        );
    }
}

/// Concrete x86_64 page table type.
pub type PageTable4Level = rux_mm::PageTable4Level<X86Paging>;

/// Load a page table into CR3, activating it.
///
/// # Safety
/// The page table must identity-map all memory currently in use.
pub unsafe fn activate(pt: &PageTable4Level) {
    core::arch::asm!(
        "mov cr3, {}",
        in(reg) pt.root_phys().as_usize(),
        options(nostack, preserves_flags)
    );
}
