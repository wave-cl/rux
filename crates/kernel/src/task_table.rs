//! Per-process task table for multi-process support.
//!
//! Each process gets a `TaskSlot` containing all per-process state.
//! The "active" process's state is also mirrored in the globals
//! (`PROCESS`, `FD_TABLE`) for backward compatibility with syscall handlers.
//! On context switch, `swap_process_state()` swaps between slot and globals.

use rux_proc::fs::FsContext;
use rux_proc::signal::SignalHot;
use rux_fs::fdtable::{OpenFile, EMPTY_FD};

/// Maximum number of concurrent processes.
pub const MAX_PROCS: usize = 16;

/// Process lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TaskState {
    /// Not allocated.
    Free = 0,
    /// Currently executing on the CPU.
    Running = 1,
    /// Runnable, waiting in scheduler queue.
    Ready = 2,
    /// Sleeping (e.g., nanosleep).
    Sleeping = 3,
    /// Blocked in waitpid().
    WaitingForChild = 4,
    /// Exited, waiting to be reaped by parent.
    Zombie = 5,
    /// Blocked on pipe read/write.
    WaitingForPipe = 6,
    /// Blocked on futex (FUTEX_WAIT).
    WaitingForFutex = 7,
}

/// Per-process state container.
///
/// On context switch, the active process's fields are swapped with the
/// `PROCESS` and `FD_TABLE` globals so syscall handlers don't need changes.
pub struct TaskSlot {
    // ── Identity ──────────────────────────────────────────────────────
    pub active: bool,
    pub pid: u32,
    pub ppid: u32,
    pub pgid: u32,
    pub state: TaskState,

    // ── Process state (mirrors PROCESS global) ────────────────────────
    pub program_brk: usize,
    pub mmap_base: usize,
    pub fs_ctx: FsContext,
    pub signal_hot: SignalHot,
    // TODO: per-process signal_cold. Currently all processes share PROCESS.signal_cold.
    // 3KB per slot (16 × 3KB = 48KB BSS) overflows aarch64 memory layout.
    pub signal_restorer: [usize; 32],

    // ── File descriptors (mirrors FD_TABLE global) ────────────────────
    pub fds: [OpenFile; 64],

    // ── Hardware context ──────────────────────────────────────────────
    pub pt_root: u64,          // CR3 / TTBR0_EL1
    pub kstack_top: usize,     // top of this task's kernel stack
    pub saved_ksp: usize,      // saved kernel SP for context_switch
    pub saved_user_sp: usize,  // user stack pointer
    pub tls: u64,              // FS_BASE / TPIDR_EL0
    pub asid: u16,             // ASID (aarch64) / PCID (x86_64), 0 = kernel

    // ── Wait/exit state ──────────────────────────────────────────────
    pub exit_code: i32,
    pub wake_at: u64,           // tick count for sleep wakeup
    pub last_child_exit: i32,
    pub child_available: bool,
    pub waiting_pipe_id: u8,    // pipe id when WaitingForPipe
    pub tgid: u32,              // thread group ID (what getpid returns)
    pub clone_flags: u32,       // CLONE_* flags used to create this task
    pub clear_child_tid: usize, // address to write 0 + futex wake on exit
    pub futex_addr: usize,      // address being waited on (WaitingForFutex)
}

impl TaskSlot {
    pub const fn new() -> Self {
        Self {
            active: false,
            pid: 0, ppid: 0, pgid: 0,
            state: TaskState::Free,
            program_brk: 0,
            mmap_base: 0x10000000,
            fs_ctx: FsContext::new(),
            signal_hot: SignalHot::new(),
            signal_restorer: [0; 32],
            fds: [EMPTY_FD; 64],
            pt_root: 0,
            kstack_top: 0, saved_ksp: 0,
            saved_user_sp: 0, tls: 0, asid: 0,
            tgid: 0, clone_flags: 0, clear_child_tid: 0, futex_addr: 0,
            exit_code: 0, wake_at: 0,
            last_child_exit: 0, child_available: false,
            waiting_pipe_id: 0,
        }
    }
}

// ── Global state ──────────────────────────────────────────────────────

pub static mut TASK_TABLE: [TaskSlot; MAX_PROCS] = {
    const EMPTY: TaskSlot = TaskSlot::new();
    [EMPTY; MAX_PROCS]
};

/// Kernel stack size per task.
pub const KSTACK_SIZE: usize = 16384; // 16KB per task

/// Per-task kernel stacks.
pub static mut KSTACKS: [[u8; KSTACK_SIZE]; MAX_PROCS] = [[0; KSTACK_SIZE]; MAX_PROCS];


/// Index of the currently running task in TASK_TABLE.
pub static mut CURRENT_TASK_IDX: usize = 0;

/// Next PID to allocate (simple monotonic counter).
static mut NEXT_PID: u32 = 2; // PID 1 is init

// ── Accessors ─────────────────────────────────────────────────────────

/// Get the current task's PID.
pub fn current_pid() -> u32 {
    unsafe { TASK_TABLE[CURRENT_TASK_IDX].pid }
}

/// Get the current task's parent PID.
pub fn current_ppid() -> u32 {
    unsafe { TASK_TABLE[CURRENT_TASK_IDX].ppid }
}

/// Allocate a new PID.
pub fn alloc_pid() -> u32 {
    unsafe {
        let pid = NEXT_PID;
        NEXT_PID += 1;
        pid
    }
}

/// Find a free task slot. Returns index or None.
pub fn alloc_task_slot() -> Option<usize> {
    unsafe {
        for i in 0..MAX_PROCS {
            if !TASK_TABLE[i].active {
                return Some(i);
            }
        }
        None
    }
}

/// Initialize task slot 0 as PID 1 (init).
/// Called from boot.rs after kstate::init().
pub unsafe fn init_pid1() {
    let slot = &mut TASK_TABLE[0];
    slot.active = true;
    slot.pid = 1;
    slot.ppid = 0;
    slot.pgid = 1;
    slot.state = TaskState::Running;
    // Task 0 (init/shell) uses SYSCALL_STACK for its kernel entry stack,
    // not KSTACKS[0]. CURRENT_KSTACK_TOP must equal TASK_TABLE[0].kstack_top
    // so that swap_process_state restores the correct value after context switches.
    #[cfg(target_arch = "x86_64")]
    {
        let kstack = crate::arch::x86_64::syscall::syscall_stack_top() as usize;
        slot.kstack_top = kstack;
        crate::arch::x86_64::syscall::CURRENT_KSTACK_TOP = kstack as u64;
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        slot.kstack_top = KSTACKS[0].as_ptr() as usize + KSTACK_SIZE;
    }

    slot.asid = 1; // PID 1 gets ASID 1
    slot.tgid = 1; // PID 1's thread group is itself

    // Console FDs
    for i in 0..3 {
        slot.fds[i] = OpenFile {
            ino: 0, offset: 0, flags: 0, active: true, is_console: true,
            is_pipe: false, pipe_id: 0, pipe_write: false,
        };
    }
    CURRENT_TASK_IDX = 0;

    // Point FD_TABLE at this task's fd array — all FD accesses go directly
    // into the slot, eliminating the copy on context switch.
    rux_fs::fdtable::set_active_fds(&mut TASK_TABLE[0].fds);
}

// ── Context switch process state swap ─────────────────────────────────

/// Swap process state between two task slots.
/// Called by the scheduler's `pre_switch` callback before the actual
/// context switch. Saves globals → old slot, loads new slot → globals.
///
/// # Safety
/// Must be called with interrupts disabled (during schedule()).
pub unsafe fn swap_process_state(old_idx: usize, new_idx: usize) {
    use crate::syscall::PROCESS;
    // ── Save current globals → old slot ──────────────────────────────
    // Note: FD_TABLE is a pointer into old.fds — no FD copy needed.
    let old = &mut TASK_TABLE[old_idx];
    old.program_brk = PROCESS.program_brk;
    old.mmap_base = PROCESS.mmap_base;
    old.fs_ctx = PROCESS.fs_ctx;
    old.signal_hot = PROCESS.signal_hot;
    core::ptr::copy_nonoverlapping(
        PROCESS.signal_restorer.as_ptr(), old.signal_restorer.as_mut_ptr(), 32,
    );
    old.last_child_exit = PROCESS.last_child_exit;
    old.child_available = PROCESS.child_available;

    // Save hardware state
    #[cfg(target_arch = "x86_64")]
    {
        old.saved_user_sp = crate::arch::x86_64::syscall::SAVED_USER_RSP as usize;
        let lo: u32; let hi: u32;
        core::arch::asm!("rdmsr", in("ecx") 0xC0000100u32, out("eax") lo, out("edx") hi, options(nostack));
        old.tls = (hi as u64) << 32 | lo as u64;
    }
    #[cfg(target_arch = "aarch64")]
    {
        let sp: u64;
        core::arch::asm!("mrs {}, sp_el0", out(reg) sp, options(nostack));
        old.saved_user_sp = sp as usize;
        let tls: u64;
        core::arch::asm!("mrs {}, tpidr_el0", out(reg) tls, options(nostack));
        old.tls = tls;
    }

    // ── Load new slot → globals ──────────────────────────────────────
    let new = &TASK_TABLE[new_idx];
    PROCESS.program_brk = new.program_brk;
    PROCESS.mmap_base = new.mmap_base;
    PROCESS.fs_ctx = new.fs_ctx;
    PROCESS.signal_hot = new.signal_hot;
    core::ptr::copy_nonoverlapping(
        new.signal_restorer.as_ptr(), PROCESS.signal_restorer.as_mut_ptr(), 32,
    );
    PROCESS.last_child_exit = new.last_child_exit;
    PROCESS.child_available = new.child_available;
    // Point FD_TABLE at the new task's fd array (pointer swap, not copy).
    rux_fs::fdtable::set_active_fds(&mut TASK_TABLE[new_idx].fds);

    // Restore hardware state
    #[cfg(target_arch = "x86_64")]
    {
        crate::arch::x86_64::syscall::SAVED_USER_RSP = new.saved_user_sp as u64;
        crate::arch::x86_64::syscall::CURRENT_KSTACK_TOP = new.kstack_top as u64;
        let lo = new.tls as u32;
        let hi = (new.tls >> 32) as u32;
        core::arch::asm!("wrmsr", in("ecx") 0xC0000100u32, in("eax") lo, in("edx") hi, options(nostack));
    }
    #[cfg(target_arch = "aarch64")]
    {
        core::arch::asm!("msr sp_el0, {}", in(reg) new.saved_user_sp as u64, options(nostack));
        core::arch::asm!("msr tpidr_el0, {}", in(reg) new.tls, options(nostack));
    }

    // Switch page table with ASID/PCID to avoid full TLB flush.
    // TLB entries are tagged with the process's ASID/PCID so entries
    // from different processes coexist without interference.
    if new.pt_root != 0 && new.pt_root != old.pt_root {
        #[cfg(target_arch = "x86_64")]
        {
            // If PCID is enabled (CR4 bit 17), use no-flush CR3 write.
            // Otherwise, fall back to plain CR3 write (flushes TLB).
            let cr4: u64;
            core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nostack));
            if cr4 & (1u64 << 17) != 0 {
                let cr3 = new.pt_root | ((new.asid as u64) & 0xFFF) | (1u64 << 63);
                core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack));
            } else {
                core::arch::asm!("mov cr3, {}", in(reg) new.pt_root, options(nostack));
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            // ASID-tagged TTBR0: no TLB flush needed. User pages have nG=1
            // so they're ASID-tagged in the TLB. Kernel pages are Global (nG=0).
            let ttbr = (new.pt_root & 0x0000_FFFF_FFFF_FFFF)
                     | ((new.asid as u64) << 48);
            core::arch::asm!(
                "msr ttbr0_el1, {}",
                "isb",
                in(reg) ttbr,
                options(nostack)
            );
        }
    }

    CURRENT_TASK_IDX = new_idx;
}
