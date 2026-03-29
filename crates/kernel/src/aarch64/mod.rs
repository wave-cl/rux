pub mod init;
pub mod serial;
pub mod exit;
pub mod exception;
pub mod gic;
pub mod timer;
pub mod context;
pub mod devicetree;
pub mod paging;
pub mod syscall;

core::arch::global_asm!(include_str!("boot.S"));
core::arch::global_asm!(include_str!("exception.S"));
