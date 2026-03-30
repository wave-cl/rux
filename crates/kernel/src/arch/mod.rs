//! Architecture-specific kernel implementations.
//!
//! Each submodule contains the hardware-specific glue between
//! the generic kernel and the target architecture.

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "aarch64")]
pub mod aarch64;

// Re-export commonly used items so callers can use `crate::arch::serial`
// instead of `crate::arch::x86_64::serial`.
#[cfg(target_arch = "x86_64")]
pub use x86_64::{serial, exit};
#[cfg(target_arch = "aarch64")]
pub use aarch64::{serial, exit};
