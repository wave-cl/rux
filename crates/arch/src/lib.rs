#![no_std]

// ── Per-architecture modules ────────────────────────────────────────────
#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::*;
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

// ── Architecture-independent modules ────────────────────────────────────
pub mod pte;
pub mod cpu;
pub mod syscall;
pub mod stack;
pub mod barrier;
pub mod tlb;
pub mod timer;
pub mod serial;
pub mod irq;

// ── Re-exports ──────────────────────────────────────────────────────────
pub use pte::PageTableEntry;
pub use cpu::CpuFeatures;
pub use syscall::SyscallFrame;
pub use stack::KernelStack;

// ── Shared types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Arch {
    X86_64,
    Aarch64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Exception {
    DivideByZero,
    Debug,
    Breakpoint,
    Overflow,
    BoundRangeExceeded,
    InvalidOpcode,
    DeviceNotAvailable,
    DoubleFault,
    InvalidTss,
    SegmentNotPresent,
    StackSegmentFault,
    GeneralProtectionFault,
    PageFault,
    AlignmentCheck,
    MachineCheck,
    SimdException,
}

/// # Safety
/// Implementations must correctly save and restore all registers
/// that the ABI requires to be preserved across calls.
pub unsafe trait ContextSwitch {
    type Context;

    unsafe fn switch(old: &mut Self::Context, new: &Self::Context);
}

/// Enter user mode. Used by exec to jump to the new program's entry point.
///
/// # Safety
/// `enter_user` transitions the CPU to user-mode (ring 3 on x86_64, EL0 on
/// aarch64). The caller must ensure the address space is set up correctly
/// with valid user-mode mappings at `entry` and `user_stack`.
pub unsafe trait UserModeEntry {
    /// Jump to user-mode. Never returns.
    /// - `entry`: user-mode instruction pointer (ELF entry point)
    /// - `user_stack`: user-mode stack pointer (top of stack)
    /// - `arg`: first argument (argc on x86_64, x0 on aarch64)
    unsafe fn enter_user(entry: usize, user_stack: usize, arg: usize) -> !;
}
