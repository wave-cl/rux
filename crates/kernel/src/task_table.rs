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
    /// Uninterruptible sleep (like Linux TASK_UNINTERRUPTIBLE).
    /// Cannot be woken by signals — used during COW and page table ops.
    #[allow(dead_code)]
    Uninterruptible = 9,
    /// Blocked in poll/ppoll/epoll/select — woken by I/O events.
    WaitingForPoll = 10,
}

// ── Poll wait queue ────────────────────────────────────────────────
// Tasks sleeping in poll() register here. The timer ISR checks for
// I/O events and wakes registered tasks (like Linux wait queues).

const MAX_POLL_WAITERS: usize = 16;
static mut POLL_WAITERS: [u8; MAX_POLL_WAITERS] = [0xFF; MAX_POLL_WAITERS];
static mut POLL_WAITER_COUNT: usize = 0;

/// Register current task as waiting for poll events.
pub unsafe fn poll_wait_register(task_idx: usize) {
    if POLL_WAITER_COUNT < MAX_POLL_WAITERS {
        POLL_WAITERS[POLL_WAITER_COUNT] = task_idx as u8;
        POLL_WAITER_COUNT += 1;
    }
}

/// Wake all tasks waiting for poll events. Called from timer ISR
/// when network activity is detected.
pub unsafe fn poll_wake_all() {
    for i in 0..POLL_WAITER_COUNT {
        let idx = POLL_WAITERS[i] as usize;
        if idx < MAX_PROCS && TASK_TABLE[idx].active
            && TASK_TABLE[idx].state == TaskState::WaitingForPoll
        {
            TASK_TABLE[idx].state = TaskState::Ready;
            crate::scheduler::get().wake_task(idx);
        }
    }
    POLL_WAITER_COUNT = 0;
}

/// Check if any tasks are waiting for poll events.
pub unsafe fn has_poll_waiters() -> bool {
    POLL_WAITER_COUNT > 0
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
    pub signal_restorer: [usize; 65],

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
    /// If != u16::MAX, this task shares signal handlers with TASK_TABLE[shared_signal_cold_with].
    /// CLONE_SIGHAND threads point to the thread group leader's signal_cold.
    pub shared_signal_cold_with: u16,

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
    pub comm: [u8; 16],         // basename of argv[0] (Linux TASK_COMM_LEN=16)
    pub comm_len: u8,

    // ── Environment (for /proc/[pid]/environ) ────────────────────
    pub environ: [u8; 512],     // null-separated KEY=VALUE pairs
    pub environ_len: u16,

    // ── Memory tracking (for /proc/[pid]/stat vsize/rss) ─────────
    pub rss_pages: u32,
    pub cpu_time_ns: u64,       // accumulated CPU time (Linux CLOCK_PROCESS_CPUTIME_ID)

    // ── Preemption (Linux TIF_NEED_RESCHED) ─────────────────────────
    pub preempt_count: u32,     // saved/restored on context switch
    pub need_resched: bool,     // per-task reschedule flag

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
            signal_restorer: [0; 65],
            uid: 0, euid: 0, suid: 0, gid: 0, egid: 0, sgid: 0,
            sid: 0,
            fds: [EMPTY_FD; MAX_FDS],
            shared_fds_with: u16::MAX,
            shared_signal_cold_with: u16::MAX,
            pt_root: 0,
            kstack_top: 0, saved_ksp: 0,
            saved_user_sp: 0, tls: 0, asid: 0,
            tgid: 0, clone_flags: 0, clear_child_tid: 0, futex_addr: 0,
            exit_code: 0, wake_at: 0,
            last_child_exit: 0, child_available: false, continued: false,
            waiting_pipe_id: 0,
            itimer_real_deadline: 0, itimer_real_interval: 0,
            cmdline: [0; 128], cmdline_len: 0,
            comm: [0; 16], comm_len: 0,
            environ: [0; 512], environ_len: 0,
            rss_pages: 0, cpu_time_ns: 0,
            preempt_count: 0, need_resched: false,
            fpu_state: rux_arch::FpuState::new(),
        }
    }
}

// ── Global state ──────────────────────────────────────────────────────

pub static mut TASK_TABLE: [TaskSlot; MAX_PROCS] = {
    const EMPTY: TaskSlot = TaskSlot::new();
    [EMPTY; MAX_PROCS]
};

// ── Per-process VMA lists (Linux mm_struct.mmap) ─────────────────────
pub static mut VMA_LISTS: [rux_mm::vma::VmaList; MAX_PROCS] = {
    const EMPTY: rux_mm::vma::VmaList = rux_mm::vma::VmaList::new();
    [EMPTY; MAX_PROCS]
};

#[inline(always)]
pub unsafe fn vma_list(idx: usize) -> &'static mut rux_mm::vma::VmaList {
    &mut (*(&raw mut VMA_LISTS))[idx]
}

// ── PID hash table (Linux pid_hash) ──────────────────────────────────
const PID_HASH_SIZE: usize = 128;
const PID_HASH_EMPTY: u8 = 0xFF;
static mut PID_HASH: [u8; PID_HASH_SIZE] = [PID_HASH_EMPTY; PID_HASH_SIZE];

#[inline(always)]
fn pid_hash_idx(pid: u32) -> usize { pid as usize & (PID_HASH_SIZE - 1) }

pub unsafe fn pid_hash_insert(pid: u32, slot: usize) {
    let mut i = pid_hash_idx(pid);
    loop {
        if PID_HASH[i] == PID_HASH_EMPTY { PID_HASH[i] = slot as u8; return; }
        i = (i + 1) & (PID_HASH_SIZE - 1);
    }
}

pub unsafe fn pid_hash_remove(pid: u32) {
    let mut i = pid_hash_idx(pid);
    loop {
        if PID_HASH[i] == PID_HASH_EMPTY { return; }
        if TASK_TABLE[PID_HASH[i] as usize].pid == pid {
            PID_HASH[i] = PID_HASH_EMPTY;
            let mut j = (i + 1) & (PID_HASH_SIZE - 1);
            while PID_HASH[j] != PID_HASH_EMPTY {
                let slot = PID_HASH[j];
                PID_HASH[j] = PID_HASH_EMPTY;
                let mut k = pid_hash_idx(TASK_TABLE[slot as usize].pid);
                loop {
                    if PID_HASH[k] == PID_HASH_EMPTY { PID_HASH[k] = slot; break; }
                    k = (k + 1) & (PID_HASH_SIZE - 1);
                }
                j = (j + 1) & (PID_HASH_SIZE - 1);
            }
            return;
        }
        i = (i + 1) & (PID_HASH_SIZE - 1);
    }
}

unsafe fn pid_hash_lookup(pid: u32) -> Option<usize> {
    let mut i = pid_hash_idx(pid);
    loop {
        if PID_HASH[i] == PID_HASH_EMPTY { return None; }
        let slot = PID_HASH[i] as usize;
        if TASK_TABLE[slot].pid == pid && TASK_TABLE[slot].active { return Some(slot); }
        i = (i + 1) & (PID_HASH_SIZE - 1);
    }
}

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

/// Get signal_cold following the shared_signal_cold_with pointer (like shared_fds_with for fds).
#[inline(always)]
pub unsafe fn signal_cold_for(idx: usize) -> &'static mut rux_proc::signal::SignalCold {
    let owner = if TASK_TABLE[idx].shared_signal_cold_with != u16::MAX {
        TASK_TABLE[idx].shared_signal_cold_with as usize
    } else {
        idx
    };
    signal_cold_mut(owner)
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

// ── Per-task TIF_NEED_RESCHED ────────────────────────────────────────

#[inline(always)]
pub unsafe fn set_current_need_resched() {
    TASK_TABLE[current_task_idx()].need_resched = true;
}

#[inline(always)]
pub unsafe fn clear_current_need_resched() {
    TASK_TABLE[current_task_idx()].need_resched = false;
}

/// Check if current task needs rescheduling (per-task flag OR sched bitmask).
#[inline(always)]
pub unsafe fn current_needs_resched() -> bool {
    TASK_TABLE[current_task_idx()].need_resched
        || crate::scheduler::get().need_resched & (1u64 << crate::percpu::cpu_id() as u32) != 0
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

/// Find the task slot index for a given PID via hash table (Linux pid_hash).
#[inline]
pub fn find_task_by_pid(pid: u32) -> Option<usize> {
    unsafe { pid_hash_lookup(pid) }
}

/// Send a signal to a task and wake it if it's sleeping/blocked.
/// Consolidates the repeated pattern of setting pending + waking across
/// kill(), wake_sleepers() SIGALRM, notify_parent_child_exit() SIGCHLD, etc.
#[inline]
pub unsafe fn send_signal_to(task_idx: usize, signum: u8) {
    let info = rux_proc::signal::SigInfo {
        signo: signum, code: rux_proc::signal::SigCode::Kernel,
        _pad0: [0; 2], pid: rux_proc::id::Pid(0), uid: rux_proc::id::Uid(0),
        _pad1: [0; 4], addr: 0, status: 0, _pad2: [0; 4],
    };
    send_signal_to_with_info(task_idx, signum, info);
}

/// Per-task cached siginfo for pending standard signals (1-31).
/// Indexed by [task_idx][signum]. Last-writer-wins (matches Linux coalescing).
/// Accessed at send time (any context) and delivery time (syscall return).
/// Note: placed inside a wrapper struct to control alignment without
/// increasing BSS alignment requirements.
#[repr(C)]
struct StdSigInfoTable([[rux_proc::signal::SigInfo; 32]; MAX_PROCS]);
static mut STD_SIGINFO: StdSigInfoTable =
    StdSigInfoTable([[rux_proc::signal::SigInfo::EMPTY; 32]; MAX_PROCS]);

/// Get the std_info cache for a task (for signal delivery).
#[inline]
pub unsafe fn std_siginfo_for(task_idx: usize) -> &'static [rux_proc::signal::SigInfo; 32] {
    &*core::ptr::addr_of!(STD_SIGINFO.0[task_idx])
}

/// Send a signal with explicit SigInfo (for SI_TIMER, SI_USER, etc.).
#[inline]
pub unsafe fn send_signal_to_with_info(task_idx: usize, signum: u8, info: rux_proc::signal::SigInfo) {
    if signum >= 32 {
        // RT signal: enqueue into rt_queue with full SigInfo
        let cold = signal_cold_for(task_idx);
        let _ = cold.send_rt(&mut TASK_TABLE[task_idx].signal_hot, signum, info);
    } else {
        // Standard signal: set pending bit + cache siginfo
        TASK_TABLE[task_idx].signal_hot.pending =
            TASK_TABLE[task_idx].signal_hot.pending.add(signum);
        (*core::ptr::addr_of_mut!(STD_SIGINFO.0[task_idx]))[signum as usize] = info;
    }
    match TASK_TABLE[task_idx].state {
        TaskState::Sleeping | TaskState::WaitingForPoll
        | TaskState::WaitingForChild | TaskState::Stopped => {
            TASK_TABLE[task_idx].state = TaskState::Ready;
            crate::scheduler::get().wake_task(task_idx);
        }
        _ => {}
    }
}

/// Notify a parent that a child has exited or been killed.
/// Sends SIGCHLD, sets child_available, wakes parent if blocked in waitpid.
#[inline]
pub unsafe fn notify_parent_child_exit(child_ppid: u32, exit_status: i32) {
    if let Some(pi) = find_task_by_pid(child_ppid) {
        TASK_TABLE[pi].last_child_exit = exit_status;
        TASK_TABLE[pi].child_available = true;
        send_signal_to(pi, crate::errno::SIGCHLD);
    }
}

/// Wake sleeping tasks whose deadlines have passed.
/// Called from timer tick interrupt handler.
pub unsafe fn wake_sleepers() {
    use rux_arch::TimerOps;
    use crate::deadline_queue::{DEADLINE_QUEUE, KIND_WAKE, KIND_ITIMER};
    let now = crate::arch::Arch::ticks();
    while DEADLINE_QUEUE.peek_deadline() <= now {
        let entry = DEADLINE_QUEUE.pop();
        let i = entry.task_idx as usize;
        if i >= MAX_PROCS { continue; }
        let t = &mut TASK_TABLE[i];
        if entry.kind == KIND_WAKE {
            // Lazy removal: skip if task already woken or deadline cleared
            if !t.active || t.wake_at == 0 { continue; }
            if t.state != TaskState::Sleeping && t.state != TaskState::WaitingForFutex
                && t.state != TaskState::WaitingForPoll { continue; }
            t.wake_at = 0;
            t.state = TaskState::Ready;
            crate::scheduler::locked_wake_task(i);
        } else if entry.kind == KIND_ITIMER {
            if !t.active || t.itimer_real_deadline == 0 { continue; }
            if t.itimer_real_interval > 0 {
                t.itimer_real_deadline = now + t.itimer_real_interval;
                DEADLINE_QUEUE.insert(t.itimer_real_deadline, entry.task_idx, KIND_ITIMER);
            } else {
                t.itimer_real_deadline = 0;
            }
            send_signal_to(i, 14);
        } else if entry.kind == crate::deadline_queue::KIND_POSIX_TIMER {
            if !t.active { continue; }
            crate::posix_timer::handle_posix_timer_expiry(entry.task_idx, now);
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
    pid_hash_insert(0, 0);
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
    pid_hash_insert(1, 1);

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
                        is_pty: false, pty_id: 0, pty_master: false,
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
