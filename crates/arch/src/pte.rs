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
///
/// Implementations are in x86_64/pte.rs and aarch64/pte.rs.
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

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    mod x86_64_tests {
        use super::*;
        use crate::x86_64::pte::*;

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

    mod aarch64_tests {
        use super::*;
        use crate::aarch64::pte::*;

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
            let pte = Aarch64Pte::encode(phys, VALID | AF | AP_EL1_RW);
            assert!(Aarch64Pte::is_writable(pte));
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
        }

        #[test]
        fn huge_page_is_block_descriptor() {
            let phys = PhysAddr::new(0x20_0000);
            let pte = Aarch64Pte::encode(phys, VALID | AF);
            assert!(Aarch64Pte::is_huge(pte));
            let pte = Aarch64Pte::encode(phys, VALID | TABLE | AF);
            assert!(!Aarch64Pte::is_huge(pte));
        }

        #[test]
        fn global_check() {
            let phys = PhysAddr::new(0x5000);
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
