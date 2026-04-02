use rux_klib::{PhysAddr, VirtAddr};
use crate::MappingFlags;
use crate::vma::VmaList;

/// Flags for mmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MapFlags {
    /// Shared mapping (changes visible to other processes).
    Shared    = 1 << 0,
    /// Private mapping (copy-on-write).
    Private   = 1 << 1,
    /// Map at the exact address (fail if not available).
    Fixed     = 1 << 4,
    /// Anonymous mapping (no file backing).
    Anonymous = 1 << 5,
}

/// Per-process address space descriptor (analogous to Linux's mm_struct).
#[repr(C)]
pub struct AddressSpace {
    /// Physical address of the root page table (CR3 / TTBR0_EL1).
    pub pgd: PhysAddr,
    /// Virtual memory areas.
    pub vmas: VmaList,
    /// Total mapped virtual memory in bytes.
    pub total_vm: u64,
    /// Current program break (heap end).
    pub brk: VirtAddr,
    /// Initial program break (heap start, set by exec).
    pub start_brk: VirtAddr,
    /// Top of the user stack.
    pub start_stack: VirtAddr,
    /// Reference count (shared between CLONE_VM threads).
    pub refcount: u32,
    pub _pad: [u8; 4],
}

/// Address space operations.
///
/// # Safety
/// Methods manipulate page tables and control hardware address translation.
pub unsafe trait AddressSpaceOps {
    type Error;

    /// Create a new empty address space.
    fn new_empty() -> Result<Self, Self::Error> where Self: Sized;

    /// Fork this address space with copy-on-write.
    /// Returns a new AddressSpace sharing physical pages with COW flags.
    fn fork(&self) -> Result<Self, Self::Error> where Self: Sized;

    /// Destroy this address space, releasing all frames.
    fn destroy(&mut self);

    /// Map a region of virtual memory (mmap).
    fn mmap(
        &mut self,
        addr: VirtAddr,
        size: usize,
        prot: MappingFlags,
        flags: u32,
    ) -> Result<VirtAddr, Self::Error>;

    /// Unmap a region of virtual memory (munmap).
    fn munmap(&mut self, addr: VirtAddr, size: usize) -> Result<(), Self::Error>;

    /// Change protection on a region (mprotect).
    fn mprotect(
        &mut self,
        addr: VirtAddr,
        size: usize,
        prot: MappingFlags,
    ) -> Result<(), Self::Error>;

    /// Adjust the program break (brk).
    fn brk(&mut self, new_brk: VirtAddr) -> Result<VirtAddr, Self::Error>;

    /// Activate this address space (write CR3 / TTBR0_EL1).
    unsafe fn activate(&self);
}
