pub mod serial;
pub mod exit;

// Include boot assembly: multiboot1 header + 32→64 bit transition
core::arch::global_asm!(include_str!("boot.S"));
