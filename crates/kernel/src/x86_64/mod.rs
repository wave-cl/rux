pub mod serial;
pub mod exit;
pub mod gdt;
pub mod idt;
pub mod pit;
pub mod context;

// Include boot assembly: multiboot1 header + 32→64 bit transition
core::arch::global_asm!(include_str!("boot.S"));
