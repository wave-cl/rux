/// aarch64 page table support.
///
/// Implements `ArchPaging` for aarch64, providing PTE flag conversion,
/// TLB flush (tlbi + barriers), and page table activation (TTBR0/TCR/MAIR/SCTLR).
/// The generic 4-level walker lives in `rux_mm::pt4`.

use rux_klib::{PhysAddr, VirtAddr};
use rux_arch::aarch64::pte::{self as pte, Aarch64Pte};
use rux_mm::{ArchPaging, MappingFlags};

/// aarch64 architecture paging configuration.
pub struct Aarch64Paging;

impl ArchPaging for Aarch64Paging {
    type Pte = Aarch64Pte;

    fn mapping_to_pte_flags(flags: MappingFlags) -> u64 {
        let mut f = pte::VALID | pte::AF | pte::SH_INNER | pte::ATTR_NORMAL;

        if flags.contains(MappingFlags::WRITE) {
            f |= pte::AP_EL1_RW;
        } else {
            f |= pte::AP_EL1_RO;
        }

        if flags.contains(MappingFlags::USER) {
            if flags.contains(MappingFlags::WRITE) {
                f &= !pte::AP_MASK;
                f |= pte::AP_EL0_RW;
            } else {
                f &= !pte::AP_MASK;
                f |= pte::AP_EL0_RO;
            }
        }

        if !flags.contains(MappingFlags::EXECUTE) {
            f |= pte::PXN | pte::UXN;
        }

        if flags.contains(MappingFlags::NO_CACHE) {
            f &= !pte::ATTR_MASK;
            f |= pte::ATTR_DEVICE;
        }

        f
    }

    fn leaf_extra_flags() -> u64 {
        pte::AF | pte::TABLE  // aarch64 leaf PTEs need AF + TABLE (page descriptor)
    }

    fn table_entry_flags() -> u64 {
        pte::VALID | pte::TABLE
    }

    unsafe fn flush_tlb(virt: VirtAddr) {
        core::arch::asm!(
            "tlbi vale1is, {}",
            "dsb ish",
            "isb",
            in(reg) virt.as_usize() >> 12,
            options(nostack)
        );
    }
}

/// Concrete aarch64 page table type.
pub type PageTable4Level = rux_mm::PageTable4Level<Aarch64Paging>;

/// Write TTBR0_EL1 + set up TCR/MAIR, then enable MMU.
///
/// # Safety
/// The page table must identity-map all memory currently in use.
pub unsafe fn activate(pt: &PageTable4Level) {
    // MAIR_EL1: attr0 = normal memory (WB cacheable), attr1 = device nGnRnE
    let mair: u64 = 0xFF | (0x00 << 8);
    core::arch::asm!("msr mair_el1, {}", in(reg) mair, options(nostack));

    // TCR_EL1: T0SZ=16 (48-bit VA), 4KB granule, inner shareable
    let tcr: u64 = 16          // T0SZ = 16 (48-bit)
        | (0b00 << 14)         // TG0 = 4KB
        | (0b11 << 8)          // SH0 = inner shareable
        | (0b01 << 10)         // ORGN0 = WB WA
        | (0b01 << 12);        // IRGN0 = WB WA
    core::arch::asm!("msr tcr_el1, {}", in(reg) tcr, options(nostack));

    // TTBR0_EL1
    core::arch::asm!("msr ttbr0_el1, {}", in(reg) pt.root_phys().as_usize(), options(nostack));
    core::arch::asm!("isb", options(nostack));

    // Enable MMU (SCTLR_EL1.M=1, C=1, I=1)
    let mut sctlr: u64;
    core::arch::asm!("mrs {}, sctlr_el1", out(reg) sctlr, options(nostack));
    sctlr |= 1 << 0;   // M: MMU enable
    sctlr |= 1 << 2;   // C: data cache enable
    sctlr |= 1 << 12;  // I: instruction cache enable
    core::arch::asm!("msr sctlr_el1, {}", in(reg) sctlr, options(nostack));
    core::arch::asm!("isb", options(nostack));
}

unsafe impl rux_arch::PageTableRootOps for super::Aarch64 {
    fn read() -> u64 {
        let val: u64;
        unsafe { core::arch::asm!("mrs {}, ttbr0_el1", out(reg) val, options(nostack)); }
        val
    }
    unsafe fn write(root: u64) {
        core::arch::asm!(
            "msr ttbr0_el1, {}", "isb", "tlbi vmalle1is", "dsb ish", "isb",
            in(reg) root, options(nostack)
        );
    }
}
