//! Per-process task table for multi-process support.
//!
//! Each process gets a `TaskSlot` containing all per-process state.
//! The "active" process's state is also mirrored in the globals
//! (`PROCESS`, `FD_TABLE`) for backward compatibility with syscall handlers.
//! On context switch, `swap_process_state()` swaps between slot and globals.

use rux_proc::fs::FsContext;
use rux_proc::signal::SignalHot;
use rux_fs::fdtable::{OpenFile, EMPTY_FD, MAX_FDS};

/// Maximum number of concurrent processes.
/// 32 slots allows ~15 concurrent pipe commands before exhaustion.
pub const MAX_PROCS: usize = 64;

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
    /// Stopped by signal (SIGTSTP/SIGSTOP/SIGTTIN/SIGTTOU).
    Stopped = 8,
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

    // ── Credentials (per-task, swapped on context switch) ────────────
    pub uid: u32,
    pub euid: u32,
    pub suid: u32,
    pub gid: u32,
    pub egid: u32,
    pub sgid: u32,

    // ── Session management ───────────────────────────────────────────
    pub sid: u32,             // session ID (== pid of session leader)

    // ── File descriptors (mirrors FD_TABLE global) ────────────────────
    pub fds: [OpenFile; MAX_FDS],
    /// If != u16::MAX, this task shares its fd table with TASK_TABLE[shared_fds_with].
    /// CLONE_FILES threads point to the thread group leader's fd array.
    pub shared_fds_with: u16,

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
    pub continued: bool,        // set by SIGCONT, cleared by waitpid(WCONTINUED)
    pub waiting_pipe_id: u8,    // pipe id when WaitingForPipe
    pub tgid: u32,              // thread group ID (what getpid returns)
    pub clone_flags: u32,       // CLONE_* flags used to create this task
    pub clear_child_tid: usize, // address to write 0 + futex wake on exit
    pub futex_addr: usize,      // address being waited on (WaitingForFutex)

    // ── Interval timers (ITIMER_REAL → SIGALRM) ────────────────────
    pub itimer_real_deadline: u64,  // tick count when SIGALRM fires (0 = inactive)
    pub itimer_real_interval: u64,  // tick count for auto-reload (0 = one-shot)

    // ── Command line (for /proc/[pid]/cmdline) ─────────────────────
    pub cmdline: [u8; 128],     // null-separated argv
    pub cmdline_len: u8,

    // ── Environment (for /proc/[pid]/environ) ────────────────────
    pub environ: [u8; 512],     // null-separated KEY=VALUE pairs
    pub environ_len: u16,

    // ── Memory tracking (for /proc/[pid]/stat vsize/rss) ─────────
    pub rss_pages: u32,         // resident set size in 4K pages

    // ── Preemption ────────────────────────────────────────────────────
    pub preempt_count: u32,     // saved/restored on context switch

    // ── FPU/SIMD state ──────────────────────────────────────────────
    pub fpu_state: rux_arch::FpuState,
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
            uid: 0, euid: 0, suid: 0, gid: 0, egid: 0, sgid: 0,
            sid: 0,
            fds: [EMPTY_FD; MAX_FDS],
            shared_fds_with: u16::MAX,
            pt_root: 0,
            kstack_top: 0, saved_ksp: 0,
            saved_user_sp: 0, tls: 0, asid: 0,
            tgid: 0, clone_flags: 0, clear_child_tid: 0, futex_addr: 0,
            exit_code: 0, wake_at: 0,
            last_child_exit: 0, child_available: false, continued: false,
            waiting_pipe_id: 0,
            itimer_real_deadline: 0, itimer_real_interval: 0,
            cmdline: [0; 128], cmdline_len: 0,
            environ: [0; 512], environ_len: 0,
            rss_pages: 0,
            preempt_count: 0,
            fpu_state: rux_arch::FpuState::new(),
        }
    }
}

// ── Global state ──────────────────────────────────────────────────────

pub static mut TASK_TABLE: [TaskSlot; MAX_PROCS] = {
    const EMPTY: TaskSlot = TaskSlot::new();
    [EMPTY; MAX_PROCS]
};

/// Kernel stack size per task. 32KB allows 28KB usable with a 4KB guard page.
/// The dynamic linking exec path (load ELF + ld.so + page tables) needs >12KB.
pub const KSTACK_SIZE: usize = 32768; // 32KB per task

/// Per-task kernel stacks. KSTACK_SIZE is 16384 (4 pages), so each
/// stack is naturally page-aligned within the array when the array
/// itself is page-aligned.
#[repr(C, align(4096))]
pub struct KStackArray(pub [[u8; KSTACK_SIZE]; MAX_PROCS]);
pub static mut KSTACKS: KStackArray = KStackArray([[0; KSTACK_SIZE]; MAX_PROCS]);

/// Per-CPU IRQ stacks. IRQ handlers run on these stacks (aarch64) to avoid
/// corrupting the task kernel stack during context_switch from IRQ context.
pub const IRQ_STACK_SIZE: usize = 8192; // 8KB per CPU
#[repr(C, align(4096))]
pub struct IrqStackArray(pub [[u8; IRQ_STACK_SIZE]; crate::percpu::MAX_CPUS]);
pub static mut IRQ_STACKS: IrqStackArray = IrqStackArray([[0; IRQ_STACK_SIZE]; crate::percpu::MAX_CPUS]);

/// Per-task signal handler tables. Raw bytes to avoid linker alignment shifts.
const SIGNAL_COLD_SIZE: usize = core::mem::size_of::<rux_proc::signal::SignalCold>();
/// Aligned storage for SignalCold instances. The `#[repr(align(8))]` wrapper
/// ensures proper alignment even when BSS layout changes (e.g., adding new
/// static variables shifts addresses).
#[repr(C, align(8))]
struct AlignedSignalColdBytes([u8; SIGNAL_COLD_SIZE * MAX_PROCS]);
static mut SIGNAL_COLD_BYTES: AlignedSignalColdBytes = AlignedSignalColdBytes([0; SIGNAL_COLD_SIZE * MAX_PROCS]);

#[inline(always)]
pub unsafe fn signal_cold_mut(idx: usize) -> &'static mut rux_proc::signal::SignalCold {
    &mut *((*(&raw mut SIGNAL_COLD_BYTES)).0.as_mut_ptr().add(idx * SIGNAL_COLD_SIZE) as *mut rux_proc::signal::SignalCold)
}

/// Raw byte pointer to a task's signal_cold slot. Avoids creating a
/// &mut SignalCold reference (which triggers aarch64 codegen issues
/// in the signal delivery hot path).
#[allow(dead_code)]
#[inline(always)]
pub unsafe fn signal_cold_raw_ptr(idx: usize) -> *mut u8 {
    (*(&raw mut SIGNAL_COLD_BYTES)).0.as_mut_ptr().add(idx * SIGNAL_COLD_SIZE)
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
    crate::percpu::this_cpu().current_task_idx
}

/// Set the current task index (per-CPU for SMP safety).
#[inline(always)]
pub unsafe fn set_current_task_idx(idx: usize) {
    crate::percpu::this_cpu().current_task_idx = idx;
    // Keep global in sync for debugging / boot path
    CURRENT_TASK_IDX = idx;
    // Update per-CPU FD_TABLE CPU ID
    rux_fs::fdtable::FD_TABLE_CPU_ID = crate::percpu::this_cpu().cpu_id as usize;
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

/// Find the task slot index for a given PID. Returns None if not found.
#[inline]
pub fn find_task_by_pid(pid: u32) -> Option<usize> {
    unsafe {
        (0..MAX_PROCS).find(|&i| TASK_TABLE[i].active && TASK_TABLE[i].pid == pid)
    }
}

/// Notify a parent that a child has exited or been killed.
/// Sends SIGCHLD, sets child_available, wakes parent if blocked in waitpid.
#[inline]
pub unsafe fn notify_parent_child_exit(child_ppid: u32, exit_status: i32) {
    if let Some(pi) = find_task_by_pid(child_ppid) {
        let t = &mut TASK_TABLE[pi];
        t.last_child_exit = exit_status;
        t.child_available = true;
        t.signal_hot.pending = t.signal_hot.pending.add(crate::errno::SIGCHLD);
        if t.state == TaskState::WaitingForChild {
            t.state = TaskState::Ready;
            crate::scheduler::get().wake_task(pi);
        }
    }
}

/// Wake sleeping tasks whose deadlines have passed.
/// Called from timer tick interrupt handler.
pub unsafe fn wake_sleepers() {
    use rux_arch::TimerOps;
    let now = crate::arch::Arch::ticks();
    for i in 0..MAX_PROCS {
        let t = &mut TASK_TABLE[i];
        if !t.active { continue; }
        // Wake sleeping tasks whose deadline has passed (nanosleep + futex timeout)
        if (t.state == TaskState::Sleeping || t.state == TaskState::WaitingForFutex)
            && t.wake_at > 0 && now >= t.wake_at
        {
            t.wake_at = 0;
            t.state = TaskState::Ready;
            crate::scheduler::locked_wake_task(i);
        }
        // Check ITIMER_REAL expiry → set pending SIGALRM (signal 14)
        if t.itimer_real_deadline > 0 && now >= t.itimer_real_deadline {
            t.signal_hot.pending = t.signal_hot.pending.add(14); // SIGALRM
            if t.itimer_real_interval > 0 {
                // Repeating timer: reload deadline
                t.itimer_real_deadline = now + t.itimer_real_interval;
            } else {
                // One-shot: disarm
                t.itimer_real_deadline = 0;
            }
            // If the task is sleeping, wake it so SIGALRM can be delivered
            if t.state == TaskState::Sleeping {
                t.wake_at = 0;
                t.state = TaskState::Ready;
                crate::scheduler::get().wake_task(i);
            }
        }
    }
}

/// Initialize task slot 0 as the idle task (PID 0).
/// The idle task runs when no other tasks are runnable.
/// Called from boot.rs before init_pid1().
pub unsafe fn init_idle() {
    let slot = &mut TASK_TABLE[0];
    slot.active = true;
    slot.pid = 0;
    slot.ppid = 0;
    slot.pgid = 0;
    slot.state = TaskState::Running;
    slot.kstack_top = KSTACKS.0[0].as_ptr() as usize + KSTACK_SIZE;
    // No FDs, no page table, no user state needed for idle
}

/// Initialize task slot 1 as PID 1 (init).
/// Called from boot.rs after init_idle().
pub unsafe fn init_pid1() {
    use rux_arch::TaskSwitchOps;

    let slot = &mut TASK_TABLE[1];
    slot.active = true;
    slot.pid = 1;
    slot.ppid = 0;
    slot.pgid = 1;
    slot.state = TaskState::Running;

    let kstack = crate::arch::Arch::pid1_kstack_top();
    slot.kstack_top = kstack;
    crate::arch::Arch::init_pid1_hw(kstack);

    slot.asid = 1;
    slot.tgid = 1;
    slot.sid = 1;

    // Console FDs
    for i in 0..3 {
        slot.fds[i] = OpenFile {
            ino: 0, offset: 0, flags: 0, fd_flags: 0, active: true, is_console: true,
            is_pipe: false, pipe_id: 0, pipe_write: false,
            is_socket: false, socket_idx: 0, pipe_id_write: 0xFF,
        };
    }
    set_current_task_idx(1);

    rux_fs::fdtable::set_active_fds(&mut TASK_TABLE[1].fds);
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

    // Idle task (slot 0) has no process state — skip save/restore
    if new_idx == 0 {
        // Switching TO idle: only save old task's state
        if old_idx != 0 {
            let proc_ptr = crate::syscall::process() as *mut crate::syscall::ProcessState;
            let tt_ptr = &raw mut TASK_TABLE;
            let old = &mut (*tt_ptr)[old_idx];
            old.program_brk = (*proc_ptr).program_brk;
            old.mmap_base = (*proc_ptr).mmap_base;
            old.fs_ctx = (*proc_ptr).fs_ctx;
            old.signal_hot = (*proc_ptr).signal_hot;
            core::ptr::copy_nonoverlapping(
                (*proc_ptr).signal_restorer.as_ptr(), old.signal_restorer.as_mut_ptr(), 32,
            );
            old.last_child_exit = (*proc_ptr).last_child_exit;
            old.child_available = (*proc_ptr).child_available;
            old.uid = (*proc_ptr).uid; old.euid = (*proc_ptr).euid; old.suid = (*proc_ptr).suid;
            old.gid = (*proc_ptr).gid; old.egid = (*proc_ptr).egid; old.sgid = (*proc_ptr).sgid;
            crate::arch::Arch::save_task_hw(&mut old.saved_user_sp, &mut old.tls);
            crate::arch::Arch::save_fpu(&mut old.fpu_state as *mut _ as *mut u8);
            old.preempt_count = crate::percpu::this_cpu().preempt_count;
        }
        crate::percpu::this_cpu().preempt_count = 0; // idle has no preempt state
        set_current_task_idx(0);
        return;
    }
    if old_idx == 0 {
        // Switching FROM idle: only restore new task's state
        let proc_ptr = crate::syscall::process() as *mut crate::syscall::ProcessState;
        let tt_ptr = &raw mut TASK_TABLE;
        let new = &(*tt_ptr)[new_idx];
        (*proc_ptr).program_brk = new.program_brk;
        (*proc_ptr).mmap_base = new.mmap_base;
        (*proc_ptr).fs_ctx = new.fs_ctx;
        (*proc_ptr).signal_hot = new.signal_hot;
        core::ptr::copy_nonoverlapping(
            new.signal_restorer.as_ptr(), (*proc_ptr).signal_restorer.as_mut_ptr(), 32,
        );
        (*proc_ptr).last_child_exit = new.last_child_exit;
        (*proc_ptr).child_available = new.child_available;
        (*proc_ptr).uid = new.uid; (*proc_ptr).euid = new.euid; (*proc_ptr).suid = new.suid;
        (*proc_ptr).gid = new.gid; (*proc_ptr).egid = new.egid; (*proc_ptr).sgid = new.sgid;
        let fds_idx = if (*tt_ptr)[new_idx].shared_fds_with != u16::MAX {
            (*tt_ptr)[new_idx].shared_fds_with as usize } else { new_idx };
        rux_fs::fdtable::set_active_fds(&mut (*tt_ptr)[fds_idx].fds);
        crate::arch::Arch::restore_task_hw(new.saved_user_sp, new.tls, new.kstack_top);
        crate::arch::Arch::restore_fpu(&new.fpu_state as *const _ as *const u8);
        // preempt_count not restored — caller's preempt_disable is still active
        if new.pt_root != 0 {
            crate::arch::Arch::switch_page_table(new.pt_root, new.asid);
        }
        set_current_task_idx(new_idx);
        return;
    }

    let proc_ptr = crate::syscall::process() as *mut crate::syscall::ProcessState;
    let tt_ptr = &raw mut TASK_TABLE;

    // ── Save current globals → old slot ──────────────────────────────
    // Note: FD_TABLE is a pointer into old.fds — no FD copy needed.
    let old = &mut (*tt_ptr)[old_idx];
    old.program_brk = (*proc_ptr).program_brk;
    old.mmap_base = (*proc_ptr).mmap_base;
    old.fs_ctx = (*proc_ptr).fs_ctx;
    old.signal_hot = (*proc_ptr).signal_hot;
    core::ptr::copy_nonoverlapping(
        (*proc_ptr).signal_restorer.as_ptr(), old.signal_restorer.as_mut_ptr(), 32,
    );
    old.last_child_exit = (*proc_ptr).last_child_exit;
    old.child_available = (*proc_ptr).child_available;
    old.uid = (*proc_ptr).uid;
    old.euid = (*proc_ptr).euid;
    old.suid = (*proc_ptr).suid;
    old.gid = (*proc_ptr).gid;
    old.egid = (*proc_ptr).egid;
    old.sgid = (*proc_ptr).sgid;

    // Save hardware state (user SP, TLS)
    crate::arch::Arch::save_task_hw(&mut old.saved_user_sp, &mut old.tls);

    // Save FPU/SIMD state
    crate::arch::Arch::save_fpu(&mut old.fpu_state as *mut _ as *mut u8);

    // Save preempt_count (per-task, not per-CPU)
    old.preempt_count = crate::percpu::this_cpu().preempt_count;

    // ── Load new slot → globals ──────────────────────────────────────
    let new = &(*tt_ptr)[new_idx];
    (*proc_ptr).program_brk = new.program_brk;
    (*proc_ptr).mmap_base = new.mmap_base;
    (*proc_ptr).fs_ctx = new.fs_ctx;
    (*proc_ptr).signal_hot = new.signal_hot;
    core::ptr::copy_nonoverlapping(
        new.signal_restorer.as_ptr(), (*proc_ptr).signal_restorer.as_mut_ptr(), 32,
    );
    (*proc_ptr).last_child_exit = new.last_child_exit;
    (*proc_ptr).child_available = new.child_available;
    (*proc_ptr).uid = new.uid;
    (*proc_ptr).euid = new.euid;
    (*proc_ptr).suid = new.suid;
    (*proc_ptr).gid = new.gid;
    (*proc_ptr).egid = new.egid;
    (*proc_ptr).sgid = new.sgid;
    // Point FD_TABLE at the task's fd array — or the shared leader's array.
    let fds_idx = if (*tt_ptr)[new_idx].shared_fds_with != u16::MAX {
        (*tt_ptr)[new_idx].shared_fds_with as usize
    } else {
        new_idx
    };
    rux_fs::fdtable::set_active_fds(&mut (*tt_ptr)[fds_idx].fds);

    // Restore hardware state (user SP, TLS, kernel stack top)
    crate::arch::Arch::restore_task_hw(new.saved_user_sp, new.tls, new.kstack_top);


    // Restore FPU/SIMD state
    crate::arch::Arch::restore_fpu(&new.fpu_state as *const _ as *const u8);

    // Note: preempt_count is NOT restored here. It was saved to old task above.
    // The new task resumes with whatever preempt_count the caller set (via
    // preempt_disable before schedule). This avoids a window between restore
    // and context_switch where preempt_count=0 could allow re-entrant schedule.

    // Switch page table with ASID/PCID to avoid full TLB flush.
    if new.pt_root != 0 && new.pt_root != old.pt_root {
        crate::arch::Arch::switch_page_table(new.pt_root, new.asid);
    }

    set_current_task_idx(new_idx);
}
