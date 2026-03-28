/// Weight for nice 0 — the baseline. All vruntime deltas are scaled
/// relative to this weight. A task with weight 1024 advances vruntime
/// at 1:1 with wall-clock time.
pub const NICE_0_WEIGHT: u32 = 1024;

/// Weight for SCHED_IDLE tasks — extremely low priority within the
/// fair class. Results in ~341x slower vruntime advance than nice 0.
pub const IDLE_WEIGHT: u32 = 3;

/// Default time slice (3ms). Linux 6.6+ EEVDF default.
/// Each task gets at least this much CPU time per scheduling period,
/// scaled by its weight relative to the runqueue's total weight.
pub const BASE_SLICE_NS: u64 = 3_000_000;

/// Minimum slice floor (0.3ms). Prevents zero-length slices for
/// extremely low-weight tasks on heavily loaded runqueues.
pub const MIN_SLICE_NS: u64 = 300_000;

/// Maximum slice ceiling (24ms). Prevents a single high-weight task
/// from monopolizing the CPU for too long.
pub const MAX_SLICE_NS: u64 = 24_000_000;

/// Target scheduling period (6ms). The scheduler aims to give every
/// runnable task at least one turn within this window. When nr_running
/// exceeds sched_latency / min_granularity, the period stretches.
pub const SCHED_LATENCY_NS: u64 = 6_000_000;

/// Minimum preemption granularity (0.75ms). After a task is scheduled,
/// it won't be preempted for at least this long, even if a higher-priority
/// entity arrives. Prevents context-switch thrashing.
pub const MIN_GRANULARITY_NS: u64 = 750_000;

/// Virtual time credit for waking Normal tasks (1ms). Compensates for
/// time spent sleeping so waking tasks don't start at a vruntime
/// disadvantage. Applied only to SCHED_NORMAL, not Batch or IdlePolicy.
pub const WAKEUP_CREDIT_NS: u64 = 1_000_000;

/// Wake flag: task created via fork/clone.
pub const WF_FORK: u32 = 1 << 0;

/// Wake flag: try-to-wake-up path (task waking from sleep).
pub const WF_TTWU: u32 = 1 << 1;

/// Wake flag: synchronous wakeup (waker will immediately sleep).
pub const WF_SYNC: u32 = 1 << 2;
