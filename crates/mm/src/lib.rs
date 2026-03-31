#![no_std]

use rux_klib::{PhysAddr, VirtAddr};

pub mod frame;
pub mod pt;
pub mod pt4;
pub mod vma;
pub mod addr_space;
pub mod slab;
pub mod slab_simple;
pub mod fault;
pub mod cow;
pub mod pgtrack;
pub mod snapshot;

// ── Page sizes ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PageSize {
    FourK,
    TwoM,
    OneG,
}

impl PageSize {
    #[inline(always)]
    pub const fn bytes(self) -> usize {
        match self {
            Self::FourK => 4096,
            Self::TwoM => 2 * 1024 * 1024,
            Self::OneG => 1024 * 1024 * 1024,
        }
    }

    #[inline(always)]
    pub const fn shift(self) -> u8 {
        match self {
            Self::FourK => 12,
            Self::TwoM => 21,
            Self::OneG => 30,
        }
    }
}

// ── Mapping flags ───────────────────────────────────────────────────────

/// Page mapping flags. `#[repr(transparent)]` newtype over u32 so flags
/// can be combined with OR. Replaces the old enum which couldn't be OR'd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct MappingFlags(pub u32);

impl MappingFlags {
    pub const NONE: Self         = Self(0);
    pub const READ: Self         = Self(1 << 0);
    pub const WRITE: Self        = Self(1 << 1);
    pub const EXECUTE: Self      = Self(1 << 2);
    pub const USER: Self         = Self(1 << 3);
    pub const GLOBAL: Self       = Self(1 << 4);
    pub const NO_CACHE: Self     = Self(1 << 5);
    pub const WRITE_COMBINE: Self = Self(1 << 6);
    pub const WRITE_THROUGH: Self = Self(1 << 7);
    pub const COW: Self          = Self(1 << 8);

    #[inline(always)]
    pub const fn or(self, other: Self) -> Self { Self(self.0 | other.0) }
    #[inline(always)]
    pub const fn and(self, other: Self) -> Self { Self(self.0 & other.0) }
    #[inline(always)]
    pub const fn contains(self, flag: Self) -> bool { self.0 & flag.0 == flag.0 }
    #[inline(always)]
    pub const fn is_empty(self) -> bool { self.0 == 0 }
}

// ── Memory errors ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MemoryError {
    OutOfFrames,
    InvalidAddress,
    AlreadyMapped,
    NotMapped,
    MisalignedAddress,
    InvalidSize,
    PermissionDenied,
    OutOfVmas,
    OverlappingVma,
    SlabExhausted,
}

// ── VMA permissions ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VmaPermission {
    ReadOnly,
    ReadWrite,
    ReadExecute,
    ReadWriteExecute,
}

// ── Traits ──────────────────────────────────────────────────────────────

/// # Safety
/// Implementations operate on hardware page tables. Incorrect mappings
/// can corrupt memory, violate isolation, or crash the system.
pub unsafe trait PageTable {
    fn map(
        &mut self,
        virt: VirtAddr,
        phys: PhysAddr,
        size: PageSize,
        flags: MappingFlags,
    ) -> Result<(), MemoryError>;

    fn unmap(&mut self, virt: VirtAddr, size: PageSize) -> Result<PhysAddr, MemoryError>;

    fn translate(&self, virt: VirtAddr) -> Result<PhysAddr, MemoryError>;
}

/// Architecture-specific page table operations.
///
/// Implemented per-arch to provide PTE encoding, flag conversion,
/// and TLB maintenance. The generic `pt4::PageTable4Level` is
/// parameterized over this trait.
pub trait ArchPaging {
    /// The PTE ops type (e.g., X86_64Pte or Aarch64Pte).
    type Pte: rux_arch::pte::PageTableEntryOps;

    /// Convert generic MappingFlags to arch-specific PTE flag bits.
    fn mapping_to_pte_flags(flags: MappingFlags) -> u64;

    /// Extra flags to OR into leaf (4K page) PTE entries.
    /// aarch64 needs AF | TABLE; x86_64 returns 0.
    fn leaf_extra_flags() -> u64;

    /// Flags for intermediate (table) PTE entries.
    /// x86_64: PRESENT | WRITABLE | USER; aarch64: VALID | TABLE.
    fn table_entry_flags() -> u64;

    /// Flush TLB for a single page.
    unsafe fn flush_tlb(virt: VirtAddr);
}

pub trait FrameAllocator {
    fn alloc(&mut self, size: PageSize) -> Result<PhysAddr, MemoryError>;
    fn dealloc(&mut self, addr: PhysAddr, size: PageSize);
    fn available_frames(&self, size: PageSize) -> usize;
    /// Base physical address of the allocator's managed region.
    fn alloc_base(&self) -> PhysAddr;
}

// ── Utility: map zeroed pages ────────────────────────────────────────────

/// Map zeroed pages into a page table.
///
/// Allocates a frame for each 4K page in `[start_va, end_va)`, zeros it,
/// and maps it with the given flags. Used by brk() and mmap().
///
/// `map_fn` and `unmap_fn` abstract over the page table type.
///
/// # Safety
/// Modifies page table mappings and writes to physical memory.
pub unsafe fn map_zeroed_pages(
    alloc: &mut dyn FrameAllocator,
    start_va: u64,
    end_va: u64,
    flags: MappingFlags,
    map_fn: &mut dyn FnMut(VirtAddr, PhysAddr, MappingFlags, &mut dyn FrameAllocator),
    unmap_fn: &mut dyn FnMut(VirtAddr),
) {
    for pa in (start_va..end_va).step_by(4096) {
        let frame = alloc.alloc(PageSize::FourK).expect("map page");
        let ptr = frame.as_usize() as *mut u8;
        for j in 0..4096 { core::ptr::write_volatile(ptr.add(j), 0); }
        let va = VirtAddr::new(pa as usize);
        unmap_fn(va);
        map_fn(va, frame, flags, alloc);
    }
}

// ── Re-exports ───────────────────────────────��──────────────────────────
pub use frame::BuddyAllocator;
pub use pt::{PageLevel, PageTablePage, TranslateResult, PageTableWalker};
pub use pt4::PageTable4Level;
pub use slab_simple::Slab;
pub use vma::{Vma, VmaKind, VmaList, VmaOps};
pub use addr_space::{AddressSpace, AddressSpaceOps};
pub use slab::SlabCache;
pub use fault::{FaultAction, PageFaultHandler};
pub use cow::CowOps;
