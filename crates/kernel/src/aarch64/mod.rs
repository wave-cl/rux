pub mod serial;
pub mod exit;
pub mod exception;
pub mod gic;
pub mod timer;
pub mod context;

// Include boot assembly + exception vector table
core::arch::global_asm!(include_str!("boot.S"));
core::arch::global_asm!(include_str!("exception.S"));
