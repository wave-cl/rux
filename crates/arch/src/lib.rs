#![no_std]

// ── Per-architecture modules ────────────────────────────────────────────
// Each contains context.rs, cpu.rs, pte.rs with arch-specific types.
#[cfg(any(target_arch = "x86_64", test))]
pub mod x86_64;
#[cfg(any(target_arch = "aarch64", test))]
pub mod aarch64;

// Re-export the current arch's types at the crate root for convenience.
#[cfg(target_arch = "x86_64")]
pub use x86_64::context::*;
#[cfg(target_arch = "aarch64")]
pub use aarch64::context::*;

// ── Architecture-independent modules ────────────────────────────────────
pub mod pte;
pub mod cpu;
pub mod syscall;
pub mod stack;
pub mod barrier;
pub mod tlb;
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

/// Architecture boot initialization (GDT/IDT, GIC, timer, frame allocator, etc.).
pub trait BootOps {
    fn boot_init(arg: usize);
}

/// Timer tick counter.
pub trait TimerOps {
    fn ticks() -> u64;
}

/// Architecture metadata (machine name for uname, etc.).
pub trait ArchInfo {
    const MACHINE_NAME: &'static [u8];
}

/// Architecture-specific syscalls (e.g., arch_prctl on x86_64).
/// Returns Some(result) if handled, None if not recognized.
pub trait ArchSpecificOps {
    fn arch_syscall(nr: usize, a0: usize, a1: usize) -> Option<isize>;
}

/// Vfork/exec context: save and restore arch-specific process state.
///
/// Each architecture implements this to handle:
/// - Register frame save/restore (exception frame or syscall stack)
/// - User stack pointer (RSP / SP_EL0)
/// - TLS base register (FS_BASE MSR / TPIDR_EL0)
/// - Page table root (CR3 / TTBR0_EL1) with TLB management
/// - Return-to-user mechanism (sysretq / eret)
///
/// The generic vfork algorithm calls these methods; the arch provides
/// only the hardware-specific primitives.
///
/// # Safety
/// All methods manipulate hardware state (registers, MSRs, page tables).
pub unsafe trait VforkContext {
    /// Virtual address base for the child's copied stack pages.
    const CHILD_STACK_VA: u64;

    /// Save the parent's register frame (from syscall stack or exception frame).
    unsafe fn save_regs();
    /// Save the user stack pointer.
    unsafe fn save_user_sp() -> u64;
    /// Set the user stack pointer (for child stack adjustment).
    unsafe fn set_user_sp(sp: u64);
    /// Save the TLS base register. Returns the saved value.
    unsafe fn save_tls() -> u64;
    /// Restore the TLS base register.
    unsafe fn restore_tls(val: u64);
    /// Read the current page table root register.
    unsafe fn read_pt_root() -> u64;
    /// Write the page table root register (with arch-appropriate TLB flush).
    unsafe fn write_pt_root(root: u64);
    /// Clear the setjmp state to prevent double-longjmp.
    unsafe fn clear_jmp();
    /// Perform setjmp. Returns 0 on first call, child PID on longjmp return.
    unsafe fn setjmp() -> i64;
    /// Check if a vfork parent is waiting (setjmp state is active).
    fn jmp_active() -> bool;
    /// Resume the vfork parent with the given child PID. Does not return.
    unsafe fn longjmp(child_pid: i64) -> !;
    /// Restore parent registers and return to user mode with the given value.
    /// Does not return.
    unsafe fn restore_and_return_to_user(return_val: i64, user_sp: u64) -> !;
}
