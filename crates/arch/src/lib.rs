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
pub mod numa;
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
pub unsafe trait ConsoleOps {
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
    unsafe fn context_switch(old_sp: *mut usize, new_sp: usize);
    /// Initialize a new task's kernel stack to "return" to `entry(arg)`.
    unsafe fn init_task_stack(stack_top: usize, entry: usize, arg: usize) -> usize;
}

/// Enter user mode (ring 3 / EL0).
///
/// # Safety
/// Caller must ensure user page table is active with valid mappings.
pub unsafe trait UserModeOps {
    unsafe fn enter_user_mode(entry: usize, user_stack: usize) -> !;
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

/// Halt the CPU until the next interrupt.
/// Enables interrupts, halts, then re-disables.
///
/// # Safety
/// Must be called with interrupts masked (they will be temporarily unmasked).
pub unsafe trait HaltOps {
    unsafe fn halt_until_interrupt();
}

/// Timer control for tickless idle.
///
/// # Safety
/// Manipulates hardware timer registers.
pub unsafe trait TimerControl {
    /// Stop the periodic timer (enter tickless idle).
    unsafe fn stop_timer();
    /// Restart the periodic timer (exit tickless idle).
    unsafe fn start_timer();
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
    const CHILD_STACK_VA: usize;

    /// Save the parent's register frame (from syscall stack or exception frame).
    unsafe fn save_regs();
    /// Save the user stack pointer.
    unsafe fn save_user_sp() -> usize;
    /// Set the user stack pointer (for child stack adjustment).
    unsafe fn set_user_sp(sp: usize);
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
    unsafe fn setjmp() -> isize;
    /// Check if a vfork parent is waiting (setjmp state is active).
    fn jmp_active() -> bool;
    /// Resume the vfork parent with the given child PID. Does not return.
    unsafe fn longjmp(child_pid: isize) -> !;
    /// Restore parent registers and return to user mode with the given value.
    /// Does not return.
    unsafe fn restore_and_return_to_user(return_val: isize, user_sp: usize) -> !;

    /// Reset arch-specific state on exec.
    /// Default: no-op. aarch64 overrides to reset signal trampoline mapping.
    unsafe fn on_exec_reset() {}
}

/// Signal delivery and sigreturn: arch-specific user-stack frame operations.
///
/// Each architecture implements this to handle:
/// - Signal frame layout on user stack (register save format differs per ISA)
/// - User stack pointer access (RSP via global / SP_EL0 via MSR)
/// - Redirecting execution to signal handler (RCX on syscall stack / ELR in frame)
/// - Sigreturn trampoline setup (aarch64 needs a mapped code page)
///
/// The generic algorithm (`generic_deliver_signal`, `generic_sigreturn`)
/// calls these methods; the arch provides only the hardware-specific primitives.
///
/// # Safety
/// All methods manipulate user-space stack and kernel register save areas.
pub unsafe trait SignalOps {
    /// Size of the arch-specific signal frame pushed onto the user stack.
    const SIGNAL_FRAME_SIZE: usize;

    /// Read the current user stack pointer.
    unsafe fn sig_read_user_sp() -> usize;
    /// Write the user stack pointer.
    unsafe fn sig_write_user_sp(sp: usize);

    /// Write an arch-specific signal frame at `frame_addr` on the user stack.
    /// Saves the current PC, flags, syscall result, and blocked mask.
    unsafe fn sig_write_frame(
        frame_addr: usize,
        syscall_result: i64,
        blocked_mask: u64,
        restorer: usize,
        signum: u8,
    );

    /// Redirect execution to the signal handler with signum as first argument.
    unsafe fn sig_redirect_to_handler(handler: usize, signum: u8);

    /// Read the signal frame at `frame_addr`, restore arch-specific registers.
    /// Returns (original_syscall_result, saved_blocked_mask).
    unsafe fn sig_restore_frame(frame_addr: usize) -> (i64, u64);

    /// Optional pre-delivery setup (e.g., aarch64 maps sigreturn trampoline page).
    unsafe fn sig_pre_deliver() {}
}

/// Linux struct stat layout constants — differs per architecture.
///
/// x86_64: st_nlink is u64 at offset 16, st_mode is u32 at offset 24.
/// aarch64: st_mode is u32 at offset 16, st_nlink is u32 at offset 20.
pub trait StatLayout {
    const STAT_SIZE: usize;
    const INO_OFF: usize;
    const NLINK_OFF: usize;
    const NLINK_IS_U64: bool;
    const MODE_OFF: usize;
    const UID_OFF: usize;
    const GID_OFF: usize;
    const RDEV_OFF: usize;
    const SIZE_OFF: usize;
    const BLKSIZE_OFF: usize;
    const BLKSIZE_IS_I64: bool;
    const BLOCKS_OFF: usize;

    /// Fill a Linux `struct stat` buffer with the given field values.
    /// Zeroes the buffer first, then writes each field at the arch-specific offset.
    ///
    /// # Safety
    /// `buf` must point to a writable buffer of at least `STAT_SIZE` bytes.
    unsafe fn fill_stat(
        buf: usize, ino: u64, nlink: u32, mode: u32,
        uid: u32, gid: u32, size: u64, blocks: u64,
    ) {
        let p = buf as *mut u8;
        for i in 0..Self::STAT_SIZE { *p.add(i) = 0; }
        *((buf + Self::INO_OFF) as *mut u64) = ino;
        if Self::NLINK_IS_U64 {
            *((buf + Self::NLINK_OFF) as *mut u64) = nlink as u64;
        } else {
            *((buf + Self::NLINK_OFF) as *mut u32) = nlink;
        }
        *((buf + Self::MODE_OFF) as *mut u32) = mode;
        *((buf + Self::UID_OFF) as *mut u32) = uid;
        *((buf + Self::GID_OFF) as *mut u32) = gid;
        if Self::RDEV_OFF > 0 {
            *((buf + Self::RDEV_OFF) as *mut u64) = 0;
        }
        *((buf + Self::SIZE_OFF) as *mut i64) = size as i64;
        if Self::BLKSIZE_IS_I64 {
            *((buf + Self::BLKSIZE_OFF) as *mut i64) = 4096;
        } else {
            *((buf + Self::BLKSIZE_OFF) as *mut i32) = 4096;
        }
        *((buf + Self::BLOCKS_OFF) as *mut i64) = blocks as i64;
    }
}

/// Per-CPU register setup and access.
///
/// Each architecture uses a dedicated register to point to the current
/// CPU's PerCpu struct: GS_BASE on x86_64, TPIDR_EL1 on aarch64.
///
/// # Safety
/// Implementations write hardware registers (MSRs, system registers).
pub unsafe trait PerCpuOps {
    /// Point the per-CPU hardware register at the given CPU's PerCpu struct.
    unsafe fn init_percpu(id: usize, base: *mut u8);

    /// Read the per-CPU base pointer from the hardware register.
    /// Returns null if not yet initialized.
    unsafe fn percpu_base() -> *mut u8;
}

/// User memory access protection (SMAP on x86_64, PAN on aarch64).
///
/// x86_64 uses STAC/CLAC instructions to toggle RFLAGS.AC for SMAP.
/// aarch64 will use PAN (deferred — currently no-ops).
/// riscv64 would use SUM bit in sstatus.
///
/// # Safety
/// Implementations manipulate CPU flags controlling supervisor access to user pages.
pub unsafe trait UserAccessOps {
    /// Begin user memory access (e.g., x86_64 STAC sets RFLAGS.AC).
    unsafe fn user_access_begin();

    /// End user memory access (e.g., x86_64 CLAC clears RFLAGS.AC).
    unsafe fn user_access_end();

    /// Enable the protection mechanism. Called once during boot after
    /// the relevant CPU feature is detected and enabled (e.g., CR4.SMAP).
    unsafe fn enable_user_access_protection() {}
}

/// Task context switch: save/restore arch hardware state around scheduler switches.
///
/// # Safety
/// Implementations manipulate MSRs, system registers, and page table roots.
pub unsafe trait TaskSwitchOps {
    /// Return the kernel stack top for PID 1 (init).
    /// x86_64: top of SYSCALL_STACK. aarch64: KSTACKS[0] + KSTACK_SIZE.
    unsafe fn pid1_kstack_top() -> usize;

    /// Initialize arch hardware state for PID 1 (e.g., set CURRENT_KSTACK_TOP).
    unsafe fn init_pid1_hw(kstack_top: usize);

    /// Save the outgoing task's user SP and TLS register.
    unsafe fn save_task_hw(saved_user_sp: &mut usize, tls: &mut u64);

    /// Restore the incoming task's user SP, TLS register, and kernel stack top.
    unsafe fn restore_task_hw(saved_user_sp: usize, tls: u64, kstack_top: usize);

    /// Switch page tables with ASID/PCID tagging to avoid full TLB flush.
    unsafe fn switch_page_table(new_root: u64, asid: u16);

    /// Save the current FPU/SIMD state to the given buffer.
    unsafe fn save_fpu(buf: *mut u8);

    /// Restore FPU/SIMD state from the given buffer.
    unsafe fn restore_fpu(buf: *const u8);
}

/// Process fork: arch-specific kernel stack setup and hardware state snapshot.
///
/// # Safety
/// Implementations manipulate kernel stacks and read hardware registers.
pub unsafe trait ForkOps {
    /// Snapshot the current hardware state (user SP, TLS register, page table root).
    unsafe fn snapshot_hw_state(saved_user_sp: &mut usize, tls: &mut u64, pt_root: &mut u64);

    /// Set up a child's kernel stack so that context_switch into it
    /// will return to userspace with return value 0 (fork child).
    /// Returns the child's initial saved kernel SP.
    unsafe fn setup_child_kstack(kstack_top: usize) -> usize;
}

/// Syscall entry state: access to arguments saved by the arch entry point.
pub trait SyscallArgOps {
    /// Read the 6th syscall argument saved by the arch-specific entry code.
    /// x86_64: R9 saved in percpu. aarch64: x5 saved in global.
    fn saved_syscall_arg5() -> usize;
}

/// Linux `kernel_sigaction` struct layout — differs per architecture.
///
/// x86_64: `[handler(8), flags(8), restorer(8), mask(8)]` = 32 bytes
/// aarch64: `[handler(8), flags(8), mask(8)]` = 24 bytes (no restorer)
pub trait SigactionLayout {
    /// Offset of `sa_mask` field (24 on x86_64, 16 on aarch64).
    const MASK_OFF: usize;
    /// Whether the struct has an `sa_restorer` field.
    const HAS_RESTORER: bool;
    /// Offset of `sa_restorer` field (16 on x86_64; unused on aarch64).
    const RESTORER_OFF: usize;

    /// Read a kernel_sigaction struct from user memory.
    /// Returns (handler_addr, flags, mask, restorer).
    ///
    /// # Safety
    /// `ptr` must point to a valid kernel_sigaction in user memory.
    unsafe fn read_sigaction(ptr: usize) -> (usize, u32, u64, usize) {
        let handler = *(ptr as *const usize);
        let flags = *((ptr + 8) as *const u64) as u32;
        let mask = *((ptr + Self::MASK_OFF) as *const u64);
        let restorer = if Self::HAS_RESTORER {
            *((ptr + Self::RESTORER_OFF) as *const usize)
        } else {
            0
        };
        (handler, flags, mask, restorer)
    }

    /// Write a kernel_sigaction struct to user memory.
    ///
    /// # Safety
    /// `ptr` must point to a writable kernel_sigaction buffer in user memory.
    unsafe fn write_sigaction(ptr: usize, handler: usize, flags: u32, mask: u64, restorer: usize) {
        *(ptr as *mut usize) = handler;
        *((ptr + 8) as *mut u64) = flags as u64;
        *((ptr + Self::MASK_OFF) as *mut u64) = mask;
        if Self::HAS_RESTORER {
            *((ptr + Self::RESTORER_OFF) as *mut usize) = restorer;
        }
    }
}

/// Architecture-specific memory layout constants.
///
/// Provides virtual address limits and base addresses that differ per arch.
/// Used by demand paging, ELF loading, and address space management.
pub trait MemoryLayout {
    /// Upper limit of user-space virtual addresses (exclusive).
    /// x86_64: 0x0000_8000_0000_0000 (128 TiB), aarch64: 0x1_0000_0000 (4 GiB)
    const USER_ADDR_LIMIT: u64;
    /// Base virtual address for the dynamic linker (ld.so).
    /// Must not overlap kernel identity map or user binary.
    const INTERP_BASE: u64;
}
