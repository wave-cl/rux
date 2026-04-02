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

/// Per-task signal handler tables. Raw bytes to avoid linker alignment shifts.
const SIGNAL_COLD_SIZE: usize = core::mem::size_of::<rux_proc::signal::SignalCold>();
static mut SIGNAL_COLD_BYTES: [u8; SIGNAL_COLD_SIZE * MAX_PROCS] = [0; SIGNAL_COLD_SIZE * MAX_PROCS];

#[inline(always)]
pub unsafe fn signal_cold_mut(idx: usize) -> &'static mut rux_proc::signal::SignalCold {
    &mut *(SIGNAL_COLD_BYTES.as_mut_ptr().add(idx * SIGNAL_COLD_SIZE) as *mut rux_proc::signal::SignalCold)
}

/// Raw byte pointer to a task's signal_cold slot. Avoids creating a
/// &mut SignalCold reference (which triggers aarch64 codegen issues
/// in the signal delivery hot path).
#[inline(always)]
pub unsafe fn signal_cold_raw_ptr(idx: usize) -> *mut u8 {
    SIGNAL_COLD_BYTES.as_mut_ptr().add(idx * SIGNAL_COLD_SIZE)
}




/// Index of the currently running task in TASK_TABLE.
pub static mut CURRENT_TASK_IDX: usize = 0;

/// Next PID to allocate (simple monotonic counter).
static mut NEXT_PID: u32 = 2; // PID 1 is init

// ── Accessors ─────────────────────────────────────────────────────────

/// Current task index. Uses the global (correct on QEMU TCG where CPUs
/// are serialized). On real SMP hardware, this needs per-CPU storage
/// via GS-base (x86_64) or TPIDR_EL1 (aarch64).
#[inline(always)]
pub unsafe fn current_task_idx() -> usize {
    CURRENT_TASK_IDX
}

/// Set the current task index (global + percpu for future SMP).
#[inline(always)]
pub unsafe fn set_current_task_idx(idx: usize) {
    CURRENT_TASK_IDX = idx;
}

/// Get the current task's PID.
pub fn current_pid() -> u32 {
    unsafe { TASK_TABLE[current_task_idx()].pid }
}

/// Get the current task's parent PID.
pub fn current_ppid() -> u32 {
    unsafe { TASK_TABLE[current_task_idx()].ppid }
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
    use rux_arch::TaskSwitchOps;

    let slot = &mut TASK_TABLE[0];
    slot.active = true;
    slot.pid = 1;
    slot.ppid = 0;
    slot.pgid = 1;
    slot.state = TaskState::Running;

    let kstack = crate::arch::Arch::pid1_kstack_top();
    slot.kstack_top = kstack;
    crate::arch::Arch::init_pid1_hw(kstack);

    slot.asid = 1; // PID 1 gets ASID 1
    slot.tgid = 1; // PID 1's thread group is itself

    // Console FDs
    for i in 0..3 {
        slot.fds[i] = OpenFile {
            ino: 0, offset: 0, flags: 0, active: true, is_console: true,
            is_pipe: false, pipe_id: 0, pipe_write: false,
        };
    }
    set_current_task_idx(0);

    // Point FD_TABLE at this task's fd array — all FD accesses go directly
    // into the slot, eliminating the copy on context switch.
    rux_fs::fdtable::set_active_fds(&mut TASK_TABLE[0].fds);
}

// ── Context switch process state swap ─────────────────────────────────

/// Swap process state between two task slots.
/// Called by the scheduler's `pre_switch` callback before the actual
/// context switch. Saves globals → old slot, loads new slot → globals.
///
/// # SMP race warning
/// The globals `PROCESS`, `FD_TABLE`, and `CURRENT_TASK_IDX` are shared
/// across all CPUs. On QEMU TCG, CPUs are serialized (only one runs at
/// a time), so no concurrent access occurs. On real SMP hardware or KVM,
/// these globals need per-CPU copies (via GS-base on x86_64, TPIDR_EL1
/// on aarch64) to prevent one CPU's context switch from corrupting
/// another CPU's active process state.
///
/// # Safety
/// Must be called with interrupts disabled (during schedule()).
pub unsafe fn swap_process_state(old_idx: usize, new_idx: usize) {
    use rux_arch::TaskSwitchOps;
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

    // Save hardware state (user SP, TLS)
    crate::arch::Arch::save_task_hw(&mut old.saved_user_sp, &mut old.tls);

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

    // Restore hardware state (user SP, TLS, kernel stack top)
    crate::arch::Arch::restore_task_hw(new.saved_user_sp, new.tls, new.kstack_top);

    // Switch page table with ASID/PCID to avoid full TLB flush.
    if new.pt_root != 0 && new.pt_root != old.pt_root {
        crate::arch::Arch::switch_page_table(new.pt_root, new.asid);
    }

    set_current_task_idx(new_idx);
}
