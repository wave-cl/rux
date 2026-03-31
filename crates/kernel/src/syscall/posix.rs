/// POSIX.1-2008 standardized syscall implementations.
///
/// Split into focused modules; this file re-exports everything so the
/// dispatch table (`posix::read`, `posix::exit`, etc.) continues to work.

pub use super::file::*;
pub use super::fs_ops::*;
pub use super::process::*;
pub use super::signal::*;
pub use super::memory::*;
