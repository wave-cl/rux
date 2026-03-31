//! Architecture-specific kernel implementations.
//!
//! Each submodule contains the hardware-specific glue between
//! the generic kernel and the target architecture. The `Arch` type
//! alias selects the concrete implementation — adding a new arch
//! means implementing the traits and adding cfg lines here.

#[cfg(all(target_arch = "x86_64", not(feature = "native")))]
pub mod x86_64;
#[cfg(all(target_arch = "aarch64", not(feature = "native")))]
pub mod aarch64;
#[cfg(feature = "native")]
pub mod native;

/// The concrete architecture type. Implements all arch traits.
#[cfg(all(target_arch = "x86_64", not(feature = "native")))]
pub type Arch = x86_64::X86_64;
#[cfg(all(target_arch = "aarch64", not(feature = "native")))]
pub type Arch = aarch64::Aarch64;
#[cfg(feature = "native")]
pub type Arch = native::NativeArch;

/// The concrete page table type for the current architecture.
#[cfg(all(target_arch = "x86_64", not(feature = "native")))]
pub type PageTable = x86_64::paging::PageTable4Level;
#[cfg(all(target_arch = "aarch64", not(feature = "native")))]
pub type PageTable = aarch64::paging::PageTable4Level;
#[cfg(feature = "native")]
pub type PageTable = native::FlatPageTable;

pub use rux_arch::StatLayout;

/// Fill a Linux struct stat buffer from VFS InodeStat.
/// Delegates to the `StatLayout::fill_stat` default method in rux-arch.
pub unsafe fn fill_linux_stat<A: StatLayout>(buf: usize, s: &rux_fs::InodeStat) {
    A::fill_stat(buf, s.ino, s.nlink, s.mode, s.uid, s.gid, s.size, s.blocks);
}

/// Map kernel identity pages into a user page table.
/// Each arch has different physical ranges and device maps.
///
/// # Safety
/// Modifies page table mappings.
pub unsafe trait KernelMapOps {
    unsafe fn map_kernel_pages(
        pt: &mut PageTable,
        alloc: &mut dyn rux_mm::FrameAllocator,
    );
}

