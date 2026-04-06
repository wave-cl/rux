use rux_klib::PhysAddr;
use crate::pte::{PageTableEntry, PageTableEntryOps};

pub const VALID: u64       = 1 << 0;
pub const TABLE: u64       = 1 << 1;
pub const AF: u64          = 1 << 10;
pub const NG: u64          = 1 << 11;
pub const DBM: u64         = 1 << 51;
/// Software-defined COW (copy-on-write) bit. PBHA bit 55.
pub const COW: u64         = 1 << 55;
/// Software-defined PROT_NONE marker. PBHA bit 56.
/// Descriptor is INVALID (no VALID bit), but this bit marks it as
/// intentionally inaccessible. Fault handler checks this to deliver
/// SIGSEGV instead of demand-paging.
pub const PROT_NONE: u64   = 1 << 56;
/// Software prot marker: descriptor has encoded prot bits (invalid, demand-pageable).
pub const PROT_MARKER: u64 = 1 << 57;
/// Software prot bits: R=bit58, W=bit59, X=bit60 (in invalid descriptors).
pub const PROT_R: u64      = 1 << 58;
pub const PROT_W: u64      = 1 << 59;
pub const PROT_X: u64      = 1 << 60;
pub const PXN: u64         = 1 << 53;
pub const UXN: u64         = 1 << 54;

// AP (access permission) bits 6-7
pub const AP_SHIFT: u64    = 6;
pub const AP_MASK: u64     = 0b11 << AP_SHIFT;
pub const AP_EL1_RW: u64   = 0b00 << AP_SHIFT;
pub const AP_EL0_RW: u64   = 0b01 << AP_SHIFT;
pub const AP_EL1_RO: u64   = 0b10 << AP_SHIFT;
pub const AP_EL0_RO: u64   = 0b11 << AP_SHIFT;

// SH (shareability) bits 8-9
pub const SH_SHIFT: u64    = 8;
pub const SH_INNER: u64    = 0b11 << SH_SHIFT;
pub const SH_OUTER: u64    = 0b10 << SH_SHIFT;

// AttrIndx bits 2-4 (index into MAIR_EL1)
pub const ATTR_SHIFT: u64  = 2;
pub const ATTR_MASK: u64   = 0b111 << ATTR_SHIFT;
pub const ATTR_NORMAL: u64 = 0b000 << ATTR_SHIFT;
pub const ATTR_DEVICE: u64 = 0b001 << ATTR_SHIFT;

/// Mask for the output address field (bits 12-47 for 4K granule).
pub const ADDR_MASK: u64   = 0x0000_FFFF_FFFF_F000;

pub struct Aarch64Pte;

impl PageTableEntryOps for Aarch64Pte {
    #[inline(always)]
    fn encode(phys: PhysAddr, flags: u64) -> PageTableEntry {
        PageTableEntry((phys.as_usize() as u64 & ADDR_MASK) | flags)
    }

    #[inline(always)]
    fn phys_addr(entry: PageTableEntry) -> PhysAddr {
        PhysAddr::new((entry.0 & ADDR_MASK) as usize)
    }

    #[inline(always)]
    fn flags(entry: PageTableEntry) -> u64 {
        entry.0 & !ADDR_MASK
    }

    #[inline(always)]
    fn is_present(entry: PageTableEntry) -> bool { entry.0 & VALID != 0 }
    #[inline(always)]
    fn is_writable(entry: PageTableEntry) -> bool {
        entry.0 & VALID != 0 && (entry.0 & AP_MASK) & (0b10 << AP_SHIFT) == 0
    }
    #[inline(always)]
    fn is_user(entry: PageTableEntry) -> bool {
        (entry.0 & AP_MASK) == AP_EL0_RW || (entry.0 & AP_MASK) == AP_EL0_RO
    }
    #[inline(always)]
    fn is_huge(entry: PageTableEntry) -> bool {
        entry.0 & VALID != 0 && entry.0 & TABLE == 0
    }
    #[inline(always)]
    fn is_global(entry: PageTableEntry) -> bool { entry.0 & NG == 0 }
    #[inline(always)]
    fn is_dirty(entry: PageTableEntry) -> bool { entry.0 & DBM != 0 }
    #[inline(always)]
    fn is_accessed(entry: PageTableEntry) -> bool { entry.0 & AF != 0 }
    #[inline(always)]
    fn is_executable(entry: PageTableEntry) -> bool {
        entry.0 & (PXN | UXN) == 0
    }

    #[inline(always)]
    fn set_present(entry: &mut PageTableEntry, val: bool) {
        if val { entry.0 |= VALID; } else { entry.0 &= !VALID; }
    }
    #[inline(always)]
    fn set_writable(entry: &mut PageTableEntry, val: bool) {
        // Preserve USER status: if AP was EL0_*, keep EL0; else use EL1.
        let was_user = (entry.0 & AP_MASK) == AP_EL0_RW || (entry.0 & AP_MASK) == AP_EL0_RO;
        entry.0 &= !AP_MASK;
        if was_user {
            entry.0 |= if val { AP_EL0_RW } else { AP_EL0_RO };
        } else {
            entry.0 |= if val { AP_EL1_RW } else { AP_EL1_RO };
        }
    }
}
