use rux_klib::PhysAddr;
use crate::pte::{PageTableEntry, PageTableEntryOps};

pub const PRESENT: u64     = 1 << 0;
pub const WRITABLE: u64    = 1 << 1;
pub const USER: u64        = 1 << 2;
pub const PWT: u64         = 1 << 3;
pub const PCD: u64         = 1 << 4;
pub const ACCESSED: u64    = 1 << 5;
pub const DIRTY: u64       = 1 << 6;
pub const HUGE: u64        = 1 << 7;
pub const GLOBAL: u64      = 1 << 8;
/// Software-defined COW (copy-on-write) bit. OS-available bit 9.
pub const COW: u64         = 1 << 9;
pub const NO_EXECUTE: u64  = 1 << 63;

/// Mask for the physical address field (bits 12-51).
pub const ADDR_MASK: u64   = 0x000F_FFFF_FFFF_F000;

/// Mask for all flag bits (everything except the address field).
pub const FLAGS_MASK: u64  = !ADDR_MASK;

pub struct X86_64Pte;

impl PageTableEntryOps for X86_64Pte {
    #[inline(always)]
    fn encode(phys: PhysAddr, flags: u64) -> PageTableEntry {
        PageTableEntry((phys.as_usize() as u64 & ADDR_MASK) | (flags & FLAGS_MASK))
    }

    #[inline(always)]
    fn phys_addr(entry: PageTableEntry) -> PhysAddr {
        PhysAddr::new((entry.0 & ADDR_MASK) as usize)
    }

    #[inline(always)]
    fn flags(entry: PageTableEntry) -> u64 {
        entry.0 & FLAGS_MASK
    }

    #[inline(always)]
    fn is_present(entry: PageTableEntry) -> bool { entry.0 & PRESENT != 0 }
    #[inline(always)]
    fn is_writable(entry: PageTableEntry) -> bool { entry.0 & WRITABLE != 0 }
    #[inline(always)]
    fn is_user(entry: PageTableEntry) -> bool { entry.0 & USER != 0 }
    #[inline(always)]
    fn is_huge(entry: PageTableEntry) -> bool { entry.0 & HUGE != 0 }
    #[inline(always)]
    fn is_global(entry: PageTableEntry) -> bool { entry.0 & GLOBAL != 0 }
    #[inline(always)]
    fn is_dirty(entry: PageTableEntry) -> bool { entry.0 & DIRTY != 0 }
    #[inline(always)]
    fn is_accessed(entry: PageTableEntry) -> bool { entry.0 & ACCESSED != 0 }
    #[inline(always)]
    fn is_executable(entry: PageTableEntry) -> bool { entry.0 & NO_EXECUTE == 0 }

    #[inline(always)]
    fn set_present(entry: &mut PageTableEntry, val: bool) {
        if val { entry.0 |= PRESENT; } else { entry.0 &= !PRESENT; }
    }
    #[inline(always)]
    fn set_writable(entry: &mut PageTableEntry, val: bool) {
        if val { entry.0 |= WRITABLE; } else { entry.0 &= !WRITABLE; }
    }
}
