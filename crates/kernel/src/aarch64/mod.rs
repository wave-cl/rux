pub mod serial;
pub mod exit;

// Include boot assembly
core::arch::global_asm!(include_str!("boot.S"));
