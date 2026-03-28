use rux_sched::entity::SchedEntity;
use rux_klib::VirtAddr;

use crate::id::{Pid, Tgid, Pgid, Sid};
use crate::creds::Credentials;
use crate::fs::FsContext;
use crate::times::ProcessTimes;
use crate::fd::FdTable;
use crate::rlimit::ResourceLimits;
use crate::signal::{SignalHot, SignalCold};

/// Task flags (PF_* in Linux). OR'd into `task_flags`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TaskFlags {
    /// Process is being torn down.
    Exiting     = 1 << 2,
    /// Task was forked but hasn't exec'd yet.
    ForkNoExec  = 1 << 6,
    /// Killed by a signal.
    Signaled    = 1 << 10,
    /// Kernel thread (no userspace address space).
    Kthread     = 1 << 21,
}

/// The central process/thread descriptor.
///
/// Analogous to Linux's `task_struct`. Embeds `SchedEntity` at offset 0
/// for zero-indirection scheduler access — `*const Task as *const SchedEntity`
/// is a valid zero-cost cast.
///
/// # Layout
///
/// 1024 bytes (power of two for shift-based array indexing).
/// Fields ordered by **access frequency**, not category:
///
/// - **Cache lines 0-3** (bytes 0-255): SchedEntity — every tick, every pick_next.
/// - **Cache line 4** (bytes 256-303): Signal hot (pending+blocked), kstack,
///   context, pid/tgid/flags. Context switch + signal check = 5 cache lines total.
/// - **Cache lines 5-6** (bytes 304-399): Process identity, family tree, pointers
///   to cold subsystem data (fd_table, mm, sig_cold, rlimits).
/// - **Cache lines 7-9** (bytes 400-591): Credentials (permission checks on syscall).
/// - **Cache lines 9-10** (bytes 592-655): FS context + process times.
/// - **Cache lines 10-15** (bytes 656-1023): Padding.
///
/// Cold subsystem data is behind pointers (like FdTable):
/// - `sig_cold: *mut SignalCold` — signal handlers, RT queue, alt stack (3112 bytes)
/// - `rlimits: *mut ResourceLimits` — resource limits (256 bytes)
/// - `fd_table: *mut FdTable` — file descriptor table (6152 bytes)
///
/// This keeps Task at 1024 bytes: 4x more tasks in cache vs. 4096.
/// A slab allocator provides the backing memory for the pointed-to structs.
///
/// # Pin invariant
///
/// When `sched.on_rq != 0`, this task is in an intrusive RB-tree and
/// **must not be moved**. Always dequeue before moving or dropping.
#[cfg_attr(target_arch = "x86_64", repr(C, align(64)))]
#[cfg_attr(target_arch = "aarch64", repr(C, align(128)))]
pub struct Task {
    // ── Cache lines 0-3 (bytes 0-255): scheduler hot path ───────────────
    /// Scheduling entity (embedded, not a pointer). Offset 0 enables
    /// zero-cost cast between Task and SchedEntity pointers.
    pub sched: SchedEntity,

    // ── Cache line 4 (bytes 256-303): context switch + signal check ─────
    /// Signal pending + blocked masks (checked every syscall return).
    pub sig_hot: SignalHot,
    /// Kernel stack base address.
    pub kstack: VirtAddr,
    /// Saved CPU register state (opaque pointer to arch-specific context).
    pub context: *mut u8,
    /// POSIX process/thread ID.
    pub pid: Pid,
    /// Thread group ID (= leader's pid; userspace getpid returns this).
    pub tgid: Tgid,
    /// Task flags (TaskFlags OR'd).
    pub task_flags: u32,
    /// Exit code (set by exit(), read by wait()).
    pub exit_code: i32,

    // ── Cache lines 5-6 (bytes 304-399): identity + cold pointers ───────
    /// Parent's PID.
    pub ppid: Pid,
    /// Process group ID.
    pub pgid: Pgid,
    /// Session ID.
    pub sid: Sid,
    /// Clone flags used to create this task (CloneFlags OR'd).
    pub clone_flags: u32,
    /// Parent task (may differ from real_parent after reparenting to init).
    pub parent: *mut Task,
    /// Biological parent (the task that actually forked us).
    pub real_parent: *mut Task,
    /// Thread group leader.
    pub group_leader: *mut Task,
    /// Thread-local storage pointer (set by clone/set_thread_area).
    pub tls: usize,
    /// File descriptor table (6 KiB, by pointer, shared via CLONE_FILES).
    pub fd_table: *mut FdTable,
    /// Address space (opaque pointer to mm subsystem state).
    pub mm: *mut u8,
    /// Signal handlers, RT queue, alt stack (3112 bytes, by pointer).
    /// Shared between CLONE_SIGHAND threads.
    pub sig_cold: *mut SignalCold,
    /// Resource limits (256 bytes, by pointer).
    /// Shared between threads in the same thread group.
    pub rlimits: *mut ResourceLimits,
    /// Userspace pointer for CLONE_CHILD_SETTID.
    pub set_child_tid: *mut u32,
    /// Userspace pointer for CLONE_CHILD_CLEARTID.
    pub clear_child_tid: *mut u32,

    // ── Cache lines 7-9 (bytes 400-591): credentials ────────────────────
    /// Process credentials (uid/gid/capabilities). Inline because euid
    /// and cap_effective are checked on every syscall entry.
    pub creds: Credentials,

    // ── Cache lines 9-10 (bytes 592-655): FS + times ────────────────────
    /// Filesystem context (cwd, root, umask).
    pub fs: FsContext,
    /// Process time accounting.
    pub times: ProcessTimes,

    // ── Padding to 1024 ─────────────────────────────────────────────────
    pub _pad_final: [u8; 368],
}

impl Task {
    /// Create a new task with the given pid and tgid.
    /// All fields initialized to safe defaults. Pointers are null —
    /// the caller must set fd_table, mm, sig_cold, and rlimits before use.
    pub const fn new(pid: Pid, tgid: Tgid) -> Self {
        Self {
            sched: SchedEntity::new(pid.0 as u64),
            sig_hot: SignalHot::new(),
            kstack: VirtAddr::new(0),
            context: core::ptr::null_mut(),
            pid,
            tgid,
            task_flags: 0,
            exit_code: 0,
            ppid: Pid(0),
            pgid: Pgid(0),
            sid: Sid(0),
            clone_flags: 0,
            parent: core::ptr::null_mut(),
            real_parent: core::ptr::null_mut(),
            group_leader: core::ptr::null_mut(),
            tls: 0,
            fd_table: core::ptr::null_mut(),
            mm: core::ptr::null_mut(),
            sig_cold: core::ptr::null_mut(),
            rlimits: core::ptr::null_mut(),
            set_child_tid: core::ptr::null_mut(),
            clear_child_tid: core::ptr::null_mut(),
            creds: Credentials::ROOT,
            fs: FsContext::DEFAULT,
            times: ProcessTimes::ZERO,
            _pad_final: [0; 368],
        }
    }
}

// SAFETY: Task contains raw pointers (parent, real_parent, group_leader,
// fd_table, mm, context, sig_cold, rlimits, set_child_tid, clear_child_tid)
// plus those from SchedEntity (rb_left, rb_right, rb_parent_color). In the
// kernel, tasks are pinned to per-CPU runqueues and accessed under
// scheduler/task locks. Cross-CPU migration dequeues before moving.
unsafe impl Send for Task {}
unsafe impl Sync for Task {}

// ── Compile-time layout assertions ──────────────────────────────────────

const _: () = {
    assert!(core::mem::size_of::<Task>() == 1024);
    assert!(core::mem::align_of::<Task>() >= 64);

    // SchedEntity at offset 0 — zero-cost cast
    assert!(core::mem::offset_of!(Task, sched) == 0);

    // Context switch + signal check (cache line 4)
    assert!(core::mem::offset_of!(Task, sig_hot) == 256);
    assert!(core::mem::offset_of!(Task, kstack) == 272);
    assert!(core::mem::offset_of!(Task, context) == 280);
    assert!(core::mem::offset_of!(Task, pid) == 288);

    // Identity + cold pointers
    assert!(core::mem::offset_of!(Task, ppid) == 304);
    assert!(core::mem::offset_of!(Task, parent) == 320);
    assert!(core::mem::offset_of!(Task, sig_cold) == 368);
    assert!(core::mem::offset_of!(Task, rlimits) == 376);

    // Credentials
    assert!(core::mem::offset_of!(Task, creds) == 400);

    // FS + times
    assert!(core::mem::offset_of!(Task, fs) == 592);
    assert!(core::mem::offset_of!(Task, times) == 616);
};

#[cfg(test)]
mod tests {
    use super::*;
    use rux_sched::entity::SchedEntity;

    #[test]
    fn task_new_initializes_fields() {
        let task = Task::new(Pid(42), Tgid(42));
        assert_eq!(task.pid, Pid(42), "pid should be initialized");
        assert_eq!(task.tgid, Tgid(42), "tgid should be initialized");
        assert_eq!(task.ppid, Pid(0), "ppid should default to 0");
        assert_eq!(task.pgid, Pgid(0), "pgid should default to 0");
        assert_eq!(task.sid, Sid(0), "sid should default to 0");
        assert_eq!(task.task_flags, 0, "task_flags should default to 0");
        assert_eq!(task.exit_code, 0, "exit_code should default to 0");
        assert_eq!(task.clone_flags, 0, "clone_flags should default to 0");
        assert!(task.fd_table.is_null(), "fd_table should be null");
        assert!(task.mm.is_null(), "mm should be null");
        assert!(task.sig_cold.is_null(), "sig_cold should be null");
        assert!(task.rlimits.is_null(), "rlimits should be null");
        assert!(task.context.is_null(), "context should be null");
        assert!(task.parent.is_null(), "parent should be null");
        assert!(task.real_parent.is_null(), "real_parent should be null");
        assert!(task.group_leader.is_null(), "group_leader should be null");
        assert!(task.set_child_tid.is_null(), "set_child_tid should be null");
        assert!(task.clear_child_tid.is_null(), "clear_child_tid should be null");
        assert_eq!(task.tls, 0, "tls should default to 0");
        // Credentials should be ROOT by default
        assert!(task.creds.is_root(), "default creds should be root");
        // Signal hot should be empty
        assert!(!task.sig_hot.has_deliverable(), "no signals should be pending");
    }

    #[test]
    fn sched_at_offset_zero() {
        // Verify the zero-cost cast invariant: SchedEntity is at offset 0
        assert_eq!(
            core::mem::offset_of!(Task, sched), 0,
            "SchedEntity must be at offset 0 for zero-cost cast"
        );
        // Verify pointer equivalence
        let task = Task::new(Pid(1), Tgid(1));
        let task_ptr: *const Task = &task;
        let sched_ptr: *const SchedEntity = &task.sched;
        assert_eq!(
            task_ptr as usize, sched_ptr as usize,
            "Task pointer and SchedEntity pointer must be equal"
        );
    }

    #[test]
    fn task_size_is_1024() {
        assert_eq!(core::mem::size_of::<Task>(), 1024, "Task must be exactly 1024 bytes");
    }

    #[test]
    fn task_alignment_at_least_64() {
        assert!(core::mem::align_of::<Task>() >= 64, "Task must be at least 64-byte aligned");
    }
}
