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

// ── Architecture abstraction traits ─────────────────────────────────
//
// Each arch (x86_64, aarch64, armv7, i386, ...) implements these traits
// on a zero-sized marker struct. The kernel uses `type Arch = x86_64::X86_64;`
// and calls `Arch::write_byte(b)` etc. for zero-cost dispatch.

/// Serial I/O (UART/COM port).
///
/// # Safety
/// `init()` may configure hardware registers.
pub unsafe trait SerialOps {
    unsafe fn init();
    fn write_byte(b: u8);
    fn read_byte() -> u8;
    fn write_bytes(buf: &[u8]) {
        for &b in buf {
            if b == b'\n' { Self::write_byte(b'\r'); }
            Self::write_byte(b);
        }
    }
    fn write_str(s: &str) { Self::write_bytes(s.as_bytes()); }
}

/// Context switching between kernel tasks.
///
/// # Safety
/// Implementations must correctly save and restore all callee-saved registers.
pub unsafe trait ContextOps {
    /// Switch from current task to another. Saves SP to `old_sp`, loads `new_sp`.
    unsafe fn context_switch(old_sp: *mut u64, new_sp: u64);
    /// Initialize a new task's kernel stack to "return" to `entry(arg)`.
    unsafe fn init_task_stack(stack_top: u64, entry: u64, arg: u64) -> u64;
}

/// Enter user mode (ring 3 / EL0).
///
/// # Safety
/// Caller must ensure user page table is active with valid mappings.
pub unsafe trait UserModeOps {
    unsafe fn enter_user_mode(entry: u64, user_stack: u64) -> !;
}

/// Exit the emulator/machine.
pub trait ExitOps {
    const EXIT_SUCCESS: u32;
    const EXIT_FAILURE: u32;
    fn exit(code: u32) -> !;
}

/// Read/write the page table root register (CR3 / TTBR0_EL1).
///
/// # Safety
/// Writing the page table root switches the active address space.
pub unsafe trait PageTableRootOps {
    fn read() -> u64;
    unsafe fn write(root: u64);
}
