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

