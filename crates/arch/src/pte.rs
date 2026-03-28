use rux_klib::PhysAddr;

/// A single page table entry — 8 bytes, architecture-specific bit layout.
/// The encoding differs between x86_64 and aarch64, but the newtype and
/// trait interface are shared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct PageTableEntry(pub u64);

const _: () = assert!(core::mem::size_of::<PageTableEntry>() == 8);

impl PageTableEntry {
    pub const EMPTY: Self = Self(0);

    #[inline(always)]
    pub const fn new(raw: u64) -> Self { Self(raw) }

    #[inline(always)]
    pub const fn raw(self) -> u64 { self.0 }

    #[inline(always)]
    pub const fn is_zero(self) -> bool { self.0 == 0 }
}

/// Operations on page table entries. Implemented per-architecture
/// because the bit layout differs between x86_64 and aarch64.
pub trait PageTableEntryOps {
    /// Create a PTE mapping `phys` with the given flags.
    fn encode(phys: PhysAddr, flags: u64) -> PageTableEntry;

    /// Extract the physical address from this PTE.
    fn phys_addr(entry: PageTableEntry) -> PhysAddr;

    /// Extract the raw flags (architecture-specific bits).
    fn flags(entry: PageTableEntry) -> u64;

    fn is_present(entry: PageTableEntry) -> bool;
    fn is_writable(entry: PageTableEntry) -> bool;
    fn is_user(entry: PageTableEntry) -> bool;
    fn is_huge(entry: PageTableEntry) -> bool;
    fn is_global(entry: PageTableEntry) -> bool;
    fn is_dirty(entry: PageTableEntry) -> bool;
    fn is_accessed(entry: PageTableEntry) -> bool;
    fn is_executable(entry: PageTableEntry) -> bool;

    fn set_present(entry: &mut PageTableEntry, val: bool);
    fn set_writable(entry: &mut PageTableEntry, val: bool);
}

// ── x86_64 PTE flags ───────────────────────────────────────────────────

/// x86_64 4-level page table entry bit layout.
#[cfg(any(target_arch = "x86_64", test))]
pub mod x86_64 {
    use super::*;

    pub const PRESENT: u64     = 1 << 0;
    pub const WRITABLE: u64    = 1 << 1;
    pub const USER: u64        = 1 << 2;
    pub const PWT: u64         = 1 << 3;  // page-level write-through
    pub const PCD: u64         = 1 << 4;  // page-level cache disable
    pub const ACCESSED: u64    = 1 << 5;
    pub const DIRTY: u64       = 1 << 6;
    pub const HUGE: u64        = 1 << 7;  // PS bit — 2M/1G page
    pub const GLOBAL: u64      = 1 << 8;
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
}

// ── aarch64 PTE flags ──────────────────────────────────────────────────

/// AArch64 stage 1 EL1 page table entry bit layout.
#[cfg(any(target_arch = "aarch64", test))]
pub mod aarch64 {
    use super::*;

    pub const VALID: u64       = 1 << 0;
    pub const TABLE: u64       = 1 << 1;  // table descriptor (vs block)
    pub const AF: u64          = 1 << 10; // access flag
    pub const NG: u64          = 1 << 11; // not global
    pub const DBM: u64         = 1 << 51; // dirty bit modifier
    pub const PXN: u64         = 1 << 53; // privileged execute-never
    pub const UXN: u64         = 1 << 54; // user execute-never

    // AP (access permission) bits 6-7:
    // 00 = EL1 RW, EL0 none
    // 01 = EL1 RW, EL0 RW
    // 10 = EL1 RO, EL0 none
    // 11 = EL1 RO, EL0 RO
    pub const AP_SHIFT: u64    = 6;
    pub const AP_MASK: u64     = 0b11 << AP_SHIFT;
    pub const AP_EL1_RW: u64   = 0b00 << AP_SHIFT;
    pub const AP_EL0_RW: u64   = 0b01 << AP_SHIFT;
    pub const AP_EL1_RO: u64   = 0b10 << AP_SHIFT;
    pub const AP_EL0_RO: u64   = 0b11 << AP_SHIFT;

    // SH (shareability) bits 8-9:
    pub const SH_SHIFT: u64    = 8;
    pub const SH_INNER: u64    = 0b11 << SH_SHIFT;
    pub const SH_OUTER: u64    = 0b10 << SH_SHIFT;

    // AttrIndx bits 2-4 (index into MAIR_EL1):
    pub const ATTR_SHIFT: u64  = 2;
    pub const ATTR_MASK: u64   = 0b111 << ATTR_SHIFT;
    pub const ATTR_NORMAL: u64 = 0b000 << ATTR_SHIFT; // MAIR index 0
    pub const ATTR_DEVICE: u64 = 0b001 << ATTR_SHIFT; // MAIR index 1

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
            // Writable if AP bits are 00 (EL1 RW) or 01 (EL0 RW)
            entry.0 & VALID != 0 && (entry.0 & AP_MASK) & (0b10 << AP_SHIFT) == 0
        }
        #[inline(always)]
        fn is_user(entry: PageTableEntry) -> bool {
            (entry.0 & AP_MASK) == AP_EL0_RW || (entry.0 & AP_MASK) == AP_EL0_RO
        }
        #[inline(always)]
        fn is_huge(entry: PageTableEntry) -> bool {
            // Block descriptor: bit 1 (TABLE) is 0, but bit 0 (VALID) is 1
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
            // Executable if neither PXN nor UXN is set
            entry.0 & (PXN | UXN) == 0
        }

        #[inline(always)]
        fn set_present(entry: &mut PageTableEntry, val: bool) {
            if val { entry.0 |= VALID; } else { entry.0 &= !VALID; }
        }
        #[inline(always)]
        fn set_writable(entry: &mut PageTableEntry, val: bool) {
            entry.0 &= !AP_MASK;
            if val {
                entry.0 |= AP_EL1_RW;
            } else {
                entry.0 |= AP_EL1_RO;
            }
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── x86_64 PTE tests ────────────────────────────────────────────────

    mod x86_64_tests {
        use super::*;
        use crate::pte::x86_64::*;

        #[test]
        fn encode_decode_roundtrip() {
            let phys = PhysAddr::new(0x1000);
            let flags = PRESENT | WRITABLE | USER;
            let pte = X86_64Pte::encode(phys, flags);
            assert_eq!(X86_64Pte::phys_addr(pte).as_usize(), 0x1000);
            assert!(X86_64Pte::is_present(pte));
            assert!(X86_64Pte::is_writable(pte));
            assert!(X86_64Pte::is_user(pte));
        }

        #[test]
        fn encode_high_address() {
            let phys = PhysAddr::new(0x000F_FFFF_FFFF_F000);
            let pte = X86_64Pte::encode(phys, PRESENT);
            assert_eq!(X86_64Pte::phys_addr(pte).as_usize(), 0x000F_FFFF_FFFF_F000);
        }

        #[test]
        fn address_strips_low_bits() {
            // Physical address with low bits set (misaligned) — should be masked
            let phys = PhysAddr::new(0x1ABC);
            let pte = X86_64Pte::encode(phys, PRESENT);
            assert_eq!(X86_64Pte::phys_addr(pte).as_usize(), 0x1000);
        }

        #[test]
        fn all_flags_individually() {
            let phys = PhysAddr::new(0x2000);

            let pte = X86_64Pte::encode(phys, PRESENT);
            assert!(X86_64Pte::is_present(pte));

            let pte = X86_64Pte::encode(phys, PRESENT | WRITABLE);
            assert!(X86_64Pte::is_writable(pte));

            let pte = X86_64Pte::encode(phys, PRESENT | USER);
            assert!(X86_64Pte::is_user(pte));

            let pte = X86_64Pte::encode(phys, PRESENT | HUGE);
            assert!(X86_64Pte::is_huge(pte));

            let pte = X86_64Pte::encode(phys, PRESENT | GLOBAL);
            assert!(X86_64Pte::is_global(pte));

            let pte = X86_64Pte::encode(phys, PRESENT | DIRTY);
            assert!(X86_64Pte::is_dirty(pte));

            let pte = X86_64Pte::encode(phys, PRESENT | ACCESSED);
            assert!(X86_64Pte::is_accessed(pte));

            // Executable = NO_EXECUTE bit NOT set
            let pte = X86_64Pte::encode(phys, PRESENT);
            assert!(X86_64Pte::is_executable(pte));
            let pte = X86_64Pte::encode(phys, PRESENT | NO_EXECUTE);
            assert!(!X86_64Pte::is_executable(pte));
        }

        #[test]
        fn set_present_and_writable() {
            let mut pte = PageTableEntry::EMPTY;
            assert!(!X86_64Pte::is_present(pte));
            X86_64Pte::set_present(&mut pte, true);
            assert!(X86_64Pte::is_present(pte));
            X86_64Pte::set_present(&mut pte, false);
            assert!(!X86_64Pte::is_present(pte));

            X86_64Pte::set_writable(&mut pte, true);
            assert!(X86_64Pte::is_writable(pte));
            X86_64Pte::set_writable(&mut pte, false);
            assert!(!X86_64Pte::is_writable(pte));
        }

        #[test]
        fn empty_pte_is_not_present() {
            let pte = PageTableEntry::EMPTY;
            assert!(!X86_64Pte::is_present(pte));
            assert!(!X86_64Pte::is_writable(pte));
            assert!(pte.is_zero());
        }

        #[test]
        fn flags_do_not_leak_into_address() {
            let phys = PhysAddr::new(0x0);
            let pte = X86_64Pte::encode(phys, PRESENT | WRITABLE | USER | NO_EXECUTE);
            assert_eq!(X86_64Pte::phys_addr(pte).as_usize(), 0x0);
        }

        #[test]
        fn address_does_not_leak_into_flags() {
            let phys = PhysAddr::new(0x000F_FFFF_FFFF_F000);
            let pte = X86_64Pte::encode(phys, 0);
            assert!(!X86_64Pte::is_present(pte));
            assert!(!X86_64Pte::is_writable(pte));
        }
    }

    // ── aarch64 PTE tests ───────────────────────────────────────────────

    mod aarch64_tests {
        use super::*;
        use crate::pte::aarch64::*;

        #[test]
        fn encode_decode_roundtrip() {
            let phys = PhysAddr::new(0x1000);
            let flags = VALID | TABLE | AF | SH_INNER | ATTR_NORMAL;
            let pte = Aarch64Pte::encode(phys, flags);
            assert_eq!(Aarch64Pte::phys_addr(pte).as_usize(), 0x1000);
            assert!(Aarch64Pte::is_present(pte));
            assert!(Aarch64Pte::is_accessed(pte));
        }

        #[test]
        fn writable_check() {
            let phys = PhysAddr::new(0x2000);
            // AP=00 (EL1 RW) → writable
            let pte = Aarch64Pte::encode(phys, VALID | AF | AP_EL1_RW);
            assert!(Aarch64Pte::is_writable(pte));
            // AP=10 (EL1 RO) → not writable
            let pte = Aarch64Pte::encode(phys, VALID | AF | AP_EL1_RO);
            assert!(!Aarch64Pte::is_writable(pte));
        }

        #[test]
        fn user_check() {
            let phys = PhysAddr::new(0x3000);
            let pte = Aarch64Pte::encode(phys, VALID | AF | AP_EL0_RW);
            assert!(Aarch64Pte::is_user(pte));
            let pte = Aarch64Pte::encode(phys, VALID | AF | AP_EL1_RW);
            assert!(!Aarch64Pte::is_user(pte));
        }

        #[test]
        fn executable_check() {
            let phys = PhysAddr::new(0x4000);
            let pte = Aarch64Pte::encode(phys, VALID | AF);
            assert!(Aarch64Pte::is_executable(pte));
            let pte = Aarch64Pte::encode(phys, VALID | AF | PXN);
            assert!(!Aarch64Pte::is_executable(pte));
            let pte = Aarch64Pte::encode(phys, VALID | AF | UXN);
            assert!(!Aarch64Pte::is_executable(pte));
        }

        #[test]
        fn huge_page_is_block_descriptor() {
            let phys = PhysAddr::new(0x20_0000); // 2M aligned
            // Block: VALID=1, TABLE=0
            let pte = Aarch64Pte::encode(phys, VALID | AF);
            assert!(Aarch64Pte::is_huge(pte));
            // Table: VALID=1, TABLE=1
            let pte = Aarch64Pte::encode(phys, VALID | TABLE | AF);
            assert!(!Aarch64Pte::is_huge(pte));
        }

        #[test]
        fn global_check() {
            let phys = PhysAddr::new(0x5000);
            // Global = nG bit NOT set
            let pte = Aarch64Pte::encode(phys, VALID | AF);
            assert!(Aarch64Pte::is_global(pte));
            let pte = Aarch64Pte::encode(phys, VALID | AF | NG);
            assert!(!Aarch64Pte::is_global(pte));
        }

        #[test]
        fn set_writable() {
            let phys = PhysAddr::new(0x6000);
            let mut pte = Aarch64Pte::encode(phys, VALID | AF | AP_EL1_RO);
            assert!(!Aarch64Pte::is_writable(pte));
            Aarch64Pte::set_writable(&mut pte, true);
            assert!(Aarch64Pte::is_writable(pte));
            Aarch64Pte::set_writable(&mut pte, false);
            assert!(!Aarch64Pte::is_writable(pte));
        }
    }
}
