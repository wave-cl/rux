#![no_std]

use rux_klib::{PhysAddr, VirtAddr};

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MappingFlags {
    Read = 1 << 0,
    Write = 1 << 1,
    Execute = 1 << 2,
    User = 1 << 3,
    Global = 1 << 4,
    NoCache = 1 << 5,
    WriteCombine = 1 << 6,
    WriteThrough = 1 << 7,
}

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VmaPermission {
    ReadOnly,
    ReadWrite,
    ReadExecute,
    ReadWriteExecute,
}

/// # Safety
/// Implementations operate on hardware page tables. Incorrect mappings
/// can corrupt memory, violate isolation, or crash the system.
pub unsafe trait PageTable {
    fn map(
        &mut self,
        virt: VirtAddr,
        phys: PhysAddr,
        size: PageSize,
        flags: u32,
    ) -> Result<(), MemoryError>;

    fn unmap(&mut self, virt: VirtAddr, size: PageSize) -> Result<PhysAddr, MemoryError>;

    fn translate(&self, virt: VirtAddr) -> Result<PhysAddr, MemoryError>;
}

pub trait FrameAllocator {
    fn alloc(&mut self, size: PageSize) -> Result<PhysAddr, MemoryError>;

    fn dealloc(&mut self, addr: PhysAddr, size: PageSize);

    fn available_frames(&self, size: PageSize) -> usize;
}
