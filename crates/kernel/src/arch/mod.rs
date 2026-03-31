//! Architecture-specific kernel implementations.
//!
//! Each submodule contains the hardware-specific glue between
//! the generic kernel and the target architecture. The `Arch` type
//! alias selects the concrete implementation — adding a new arch
//! means implementing the traits and adding cfg lines here.

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "aarch64")]
pub mod aarch64;

/// The concrete architecture type. Implements all arch traits.
#[cfg(target_arch = "x86_64")]
pub type Arch = x86_64::X86_64;
#[cfg(target_arch = "aarch64")]
pub type Arch = aarch64::Aarch64;

/// The concrete page table type for the current architecture.
#[cfg(target_arch = "x86_64")]
pub type PageTable = x86_64::paging::PageTable4Level;
#[cfg(target_arch = "aarch64")]
pub type PageTable = aarch64::paging::PageTable4Level;

pub use rux_arch::StatLayout;

/// Fill a Linux struct stat buffer from VFS InodeStat using arch layout constants.
pub unsafe fn fill_linux_stat<A: StatLayout>(buf: usize, s: &rux_fs::InodeStat) {
    let p = buf as *mut u8;
    for i in 0..A::STAT_SIZE { *p.add(i) = 0; }
    *((buf + A::INO_OFF) as *mut u64) = s.ino;
    if A::NLINK_IS_U64 {
        *((buf + A::NLINK_OFF) as *mut u64) = s.nlink as u64;
    } else {
        *((buf + A::NLINK_OFF) as *mut u32) = s.nlink;
    }
    *((buf + A::MODE_OFF) as *mut u32) = s.mode;
    *((buf + A::UID_OFF) as *mut u32) = s.uid;
    *((buf + A::GID_OFF) as *mut u32) = s.gid;
    if A::RDEV_OFF > 0 {
        *((buf + A::RDEV_OFF) as *mut u64) = 0;
    }
    *((buf + A::SIZE_OFF) as *mut i64) = s.size as i64;
    if A::BLKSIZE_IS_I64 {
        *((buf + A::BLKSIZE_OFF) as *mut i64) = 4096;
    } else {
        *((buf + A::BLKSIZE_OFF) as *mut i32) = 4096;
    }
    *((buf + A::BLOCKS_OFF) as *mut i64) = s.blocks as i64;
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

