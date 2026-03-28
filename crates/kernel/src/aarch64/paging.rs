/// 4-level aarch64 page table walker for QEMU virt machine.
///
/// Uses 4KB granule, 48-bit virtual address space.
/// Identity-mapped physical memory (no MMU enabled — direct PA access).

use rux_klib::{PhysAddr, VirtAddr};
use rux_arch::pte::{PageTableEntry, PageTableEntryOps};
use rux_arch::pte::aarch64::{self as pte, Aarch64Pte};
use rux_mm::{MappingFlags, MemoryError, PageSize, FrameAllocator};
use rux_mm::pt::{PageTablePage, PT_ENTRIES, pt_index, PageLevel};

pub struct PageTable4Level {
    root: PhysAddr,
}

impl PageTable4Level {
    pub fn new(alloc: &mut dyn FrameAllocator) -> Result<Self, MemoryError> {
        let root = alloc.alloc(PageSize::FourK)?;
        unsafe {
            let page = root.as_usize() as *mut PageTablePage;
            for i in 0..PT_ENTRIES {
                (*page).entries[i] = PageTableEntry::EMPTY;
            }
        }
        Ok(Self { root })
    }

    pub fn root_phys(&self) -> PhysAddr { self.root }

    pub fn map_4k(
        &mut self,
        virt: VirtAddr,
        phys: PhysAddr,
        flags: MappingFlags,
        alloc: &mut dyn FrameAllocator,
    ) -> Result<(), MemoryError> {
        let pte_flags = mapping_to_pte_flags(flags);

        let l3_entry = self.ensure_table(self.root, virt, PageLevel::L3, alloc)?;
        let l2_phys = Aarch64Pte::phys_addr(l3_entry);

        let l2_entry = self.ensure_table(l2_phys, virt, PageLevel::L2, alloc)?;
        let l1_phys = Aarch64Pte::phys_addr(l2_entry);

        let l1_entry = self.ensure_table(l1_phys, virt, PageLevel::L1, alloc)?;
        let l0_phys = Aarch64Pte::phys_addr(l1_entry);

        let idx = pt_index(virt, PageLevel::L0);
        unsafe {
            let page = l0_phys.as_usize() as *mut PageTablePage;
            let existing = (*page).entries[idx];
            if Aarch64Pte::is_present(existing) {
                return Err(MemoryError::AlreadyMapped);
            }
            // Leaf PTE: VALID + AF + attributes (no TABLE bit for leaf)
            (*page).entries[idx] = Aarch64Pte::encode(phys, pte_flags | pte::AF | pte::TABLE);
        }
        Ok(())
    }

    pub fn translate(&self, virt: VirtAddr) -> Result<PhysAddr, MemoryError> {
        unsafe {
            let l3 = self.root.as_usize() as *const PageTablePage;
            let l3e = (*l3).entries[pt_index(virt, PageLevel::L3)];
            if !Aarch64Pte::is_present(l3e) { return Err(MemoryError::NotMapped); }

            let l2 = Aarch64Pte::phys_addr(l3e).as_usize() as *const PageTablePage;
            let l2e = (*l2).entries[pt_index(virt, PageLevel::L2)];
            if !Aarch64Pte::is_present(l2e) { return Err(MemoryError::NotMapped); }
            if Aarch64Pte::is_huge(l2e) {
                let base = Aarch64Pte::phys_addr(l2e).as_usize() & !0x3FFFFFFF;
                return Ok(PhysAddr::new(base + (virt.as_usize() & 0x3FFFFFFF)));
            }

            let l1 = Aarch64Pte::phys_addr(l2e).as_usize() as *const PageTablePage;
            let l1e = (*l1).entries[pt_index(virt, PageLevel::L1)];
            if !Aarch64Pte::is_present(l1e) { return Err(MemoryError::NotMapped); }
            if Aarch64Pte::is_huge(l1e) {
                let base = Aarch64Pte::phys_addr(l1e).as_usize() & !0x1FFFFF;
                return Ok(PhysAddr::new(base + (virt.as_usize() & 0x1FFFFF)));
            }

            let l0 = Aarch64Pte::phys_addr(l1e).as_usize() as *const PageTablePage;
            let l0e = (*l0).entries[pt_index(virt, PageLevel::L0)];
            if !Aarch64Pte::is_present(l0e) { return Err(MemoryError::NotMapped); }

            let phys = Aarch64Pte::phys_addr(l0e).as_usize();
            Ok(PhysAddr::new(phys + (virt.as_usize() & 0xFFF)))
        }
    }

    pub fn unmap_4k(&mut self, virt: VirtAddr) -> Result<PhysAddr, MemoryError> {
        unsafe {
            let l3 = self.root.as_usize() as *const PageTablePage;
            let l3e = (*l3).entries[pt_index(virt, PageLevel::L3)];
            if !Aarch64Pte::is_present(l3e) { return Err(MemoryError::NotMapped); }

            let l2 = Aarch64Pte::phys_addr(l3e).as_usize() as *const PageTablePage;
            let l2e = (*l2).entries[pt_index(virt, PageLevel::L2)];
            if !Aarch64Pte::is_present(l2e) { return Err(MemoryError::NotMapped); }

            let l1 = Aarch64Pte::phys_addr(l2e).as_usize() as *const PageTablePage;
            let l1e = (*l1).entries[pt_index(virt, PageLevel::L1)];
            if !Aarch64Pte::is_present(l1e) { return Err(MemoryError::NotMapped); }

            let l0 = Aarch64Pte::phys_addr(l1e).as_usize() as *mut PageTablePage;
            let idx = pt_index(virt, PageLevel::L0);
            let entry = (*l0).entries[idx];
            if !Aarch64Pte::is_present(entry) { return Err(MemoryError::NotMapped); }

            let phys = Aarch64Pte::phys_addr(entry);
            (*l0).entries[idx] = PageTableEntry::EMPTY;

            // TLB invalidate
            core::arch::asm!(
                "tlbi vale1is, {}",
                "dsb ish",
                "isb",
                in(reg) virt.as_usize() >> 12,
                options(nostack)
            );

            Ok(phys)
        }
    }

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

    /// Write TTBR0_EL1 + set up TCR/MAIR, then enable MMU.
    pub unsafe fn activate(&self) {
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
        core::arch::asm!("msr ttbr0_el1, {}", in(reg) self.root.as_usize(), options(nostack));
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
            if Aarch64Pte::is_present(entry) {
                return Ok(entry);
            }

            let new_page = alloc.alloc(PageSize::FourK)?;
            let new_ptr = new_page.as_usize() as *mut PageTablePage;
            for i in 0..PT_ENTRIES {
                (*new_ptr).entries[i] = PageTableEntry::EMPTY;
            }

            // Table descriptor: VALID + TABLE
            let new_entry = Aarch64Pte::encode(new_page, pte::VALID | pte::TABLE);
            (*table).entries[idx] = new_entry;
            Ok(new_entry)
        }
    }
}

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
