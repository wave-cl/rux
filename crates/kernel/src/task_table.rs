//! Per-process task table for multi-process support.
//!
//! Each process gets a `TaskSlot` containing all per-process state.
//! The "active" process's state is also mirrored in the globals
//! (`PROCESS`, `FD_TABLE`) for backward compatibility with syscall handlers.
//! On context switch, `swap_process_state()` swaps between slot and globals.

use rux_proc::fs::FsContext;
use rux_proc::signal::{SignalHot, SignalCold};
use rux_fs::fdtable::{OpenFile, EMPTY_FD};

/// Maximum number of concurrent processes.
pub const MAX_PROCS: usize = 8;

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
    pub in_vfork_child: bool,
    pub signal_hot: SignalHot,
    pub signal_cold: SignalCold,
    pub signal_restorer: [usize; 32],

    // ── File descriptors (mirrors FD_TABLE global) ────────────────────
    pub fds: [OpenFile; 64],

    // ── Hardware context ──────────────────────────────────────────────
    pub pt_root: u64,          // CR3 / TTBR0_EL1
    pub kstack_top: usize,     // top of this task's kernel stack
    pub saved_ksp: usize,      // saved kernel SP for context_switch
    pub saved_user_sp: usize,  // user stack pointer
    pub tls: u64,              // FS_BASE / TPIDR_EL0

    // ── Wait/exit state ──────────────────────────────────────────────
    pub exit_code: i32,
    pub wake_at: u64,           // tick count for sleep wakeup
    pub last_child_exit: i32,
    pub child_available: bool,
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
            in_vfork_child: false,
            signal_hot: SignalHot::new(),
            signal_cold: SignalCold::new(),
            signal_restorer: [0; 32],
            fds: [EMPTY_FD; 64],
            pt_root: 0,
            kstack_top: 0, saved_ksp: 0,
            saved_user_sp: 0, tls: 0,
            exit_code: 0, wake_at: 0,
            last_child_exit: 0, child_available: false,
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
    slot.kstack_top = KSTACKS[0].as_ptr() as usize + KSTACK_SIZE;
    // Console FDs
    for i in 0..3 {
        slot.fds[i] = OpenFile {
            ino: 0, offset: 0, flags: 0, active: true, is_console: true,
            is_pipe: false, pipe_id: 0, pipe_write: false,
        };
    }
    CURRENT_TASK_IDX = 0;
}
