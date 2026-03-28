use crate::{DeadlineParams, DeadlineState, SchedClass, SchedPolicy, TaskId, TaskState};
use crate::cpu::CpuId;

/// Unified scheduling entity — embeds parameters for ALL scheduler classes.
///
/// Like Linux's task_struct which embeds sched_entity + sched_rt_entity +
/// sched_dl_entity + sched_ext_entity simultaneously. Only the fields
/// relevant to the active class are semantically meaningful.
///
/// # Pin invariant
/// When `on_rq != 0`, this entity is in an intrusive RB-tree and **must
/// not be moved**. The tree nodes (parent, children) hold raw pointers to
/// this address. Moving the entity while on-tree corrupts the tree.
/// Always dequeue (`on_rq = 0`) before moving or dropping.
///
/// Layout is organized by **access frequency**, not by category:
/// - Cache line 0 (bytes 0–63 on x86_64, 0–127 on M1): fields touched every
///   tick and every pick_next — zero extra cache misses on the hot path.
/// - Cache line 1 (bytes 64–127): warm policy-specific fields.
/// - Cache lines 2–3: cold deadline params, PELT, and accounting.
///
/// `align(64)` on x86_64 / `align(128)` on aarch64 (M1 has 128-byte cache
/// lines) ensures the struct is always cache-line aligned, preventing false
/// sharing when adjacent entries are operated on by different CPUs.
#[cfg_attr(target_arch = "x86_64", repr(C, align(64)))]
#[cfg_attr(target_arch = "aarch64", repr(C, align(128)))]
pub struct SchedEntity {
    // ── Cache line 0 (bytes 0–63): EEVDF hot path ────────────────────────
    /// Virtual runtime — primary ordering key for EEVDF
    pub vruntime: u64,
    /// Virtual lag — eligibility: task is eligible when vlag ≤ 0
    pub vlag: i64,
    /// Virtual deadline = vruntime + slice/weight — pick_next comparison key
    pub vdeadline: u64,
    /// Remaining time slice in nanoseconds — decremented every tick
    pub slice: u64,
    /// Timestamp of last put-on-CPU — used to compute elapsed time per tick
    pub exec_start: u64,
    /// Task identity
    pub id: TaskId,
    /// Weight derived from nice, precomputed — used in vruntime update
    pub weight: u32,
    /// CPU this entity is currently on
    pub cpu: CpuId,
    /// Scheduler flags (e.g. TIF_NEED_RESCHED equivalent)
    pub flags: u32,
    /// Task lifecycle state
    pub state: TaskState,
    /// Active scheduler class — determines which class handles this entity
    pub class: SchedClass,
    pub _pad0: [u8; 2],
    // = 64 bytes on x86_64 ─────────────────────────────────────────────────

    // ── Cache line 1 (bytes 64–127): warm policy-specific fields ──────────
    /// Total CPU time consumed (nanoseconds)
    pub sum_exec: u64,
    /// Remaining RR timeslice — decremented per tick for RoundRobin, unused for FIFO
    pub rr_timeslice: u64,
    /// sched_ext: dispatch queue ID
    pub dsq_id: u64,
    /// sched_ext: virtual time for DSQ ordering
    pub dsq_vtime: u64,
    /// sched_ext: assigned time slice
    pub ext_slice: u64,
    /// Scheduling policy — determines behavior within the active class
    pub policy: SchedPolicy,
    /// Cached count of allowed CPUs
    pub nr_cpus_allowed: u16,
    /// Nice value (-20..19)
    pub nice: i8,
    /// RT priority 0-99 (higher = more important)
    pub rt_priority: u8,
    /// Deadline budget state (active / throttled / etc.)
    pub dl_state: DeadlineState,
    pub _pad1: [u8; 15],
    // = 128 bytes on M1 ────────────────────────────────────────────────────

    // ── Cache line 2 (bytes 128–191): deadline params + PELT ──────────────
    /// EDF + CBS deadline parameters (runtime / deadline / period)
    pub dl: DeadlineParams,
    /// Exponentially weighted load average (PELT)
    pub load_avg: u64,
    /// Runnable average (PELT)
    pub runnable_avg: u64,
    /// Utilization average (PELT)
    pub util_avg: u64,
    /// Timestamp of last PELT update
    pub load_last_update: u64,
    /// Bitmask of CPUs this entity may run on (inline for ≤64 CPUs)
    pub cpus_allowed: u64,

    // ── Cache line 3 (bytes 192–215): cold accounting ──────────────────────
    /// Previous CPU — used for migration decisions
    pub prev_cpu: CpuId,
    pub _pad3: u32,
    /// Voluntary context switches
    pub nvcsw: u64,
    /// Involuntary context switches
    pub nivcsw: u64,

    // ── Bytes 216–255: intrusive RB-tree links for fair timeline ─────────
    /// Left child in the vruntime-ordered RB-tree (null = leaf)
    pub rb_left: *mut SchedEntity,
    /// Right child in the vruntime-ordered RB-tree (null = leaf)
    pub rb_right: *mut SchedEntity,
    /// Parent pointer with color encoded in bit 0 (0=red, 1=black).
    /// Extract parent: `rb_parent_color & !1usize`
    /// Extract color:  `rb_parent_color & 1`
    pub rb_parent_color: usize,
    /// Augmented: minimum vdeadline in this subtree (including self).
    /// Enables O(log n) EEVDF eligible-EDF pick by pruning subtrees.
    pub rb_min_vdeadline: u64,
    /// Whether this entity is currently on a runqueue's timeline tree.
    pub on_rq: u8,
    pub _pad_tree: [u8; 7],
}

impl SchedEntity {
    #[inline(always)]
    pub const fn new(id: TaskId) -> Self {
        Self {
            vruntime: 0,
            vlag: 0,
            vdeadline: 0,
            slice: 0,
            exec_start: 0,
            id,
            weight: 1024,
            cpu: 0,
            flags: 0,
            state: TaskState::Ready,
            class: SchedClass::Fair,
            _pad0: [0; 2],

            sum_exec: 0,
            rr_timeslice: 0,
            dsq_id: 0,
            dsq_vtime: 0,
            ext_slice: 0,
            policy: SchedPolicy::Normal,
            nr_cpus_allowed: 64,
            nice: 0,
            rt_priority: 0,
            dl_state: DeadlineState::Inactive,
            _pad1: [0; 15],

            dl: DeadlineParams::ZERO,
            load_avg: 0,
            runnable_avg: 0,
            util_avg: 0,
            load_last_update: 0,
            cpus_allowed: u64::MAX,

            prev_cpu: 0,
            _pad3: 0,
            nvcsw: 0,
            nivcsw: 0,

            rb_left: core::ptr::null_mut(),
            rb_right: core::ptr::null_mut(),
            rb_parent_color: 0,
            rb_min_vdeadline: u64::MAX,
            on_rq: 0,
            _pad_tree: [0; 7],
        }
    }

    /// Recompute weight from nice value using Linux's sched_prio_to_weight table.
    #[inline(always)]
    pub fn reweight(&mut self) {
        self.weight = nice_to_weight(self.nice);
    }
}

/// Nice-to-weight lookup — Linux's exact `sched_prio_to_weight[40]` table.
/// Each step is ~1.25×: nice -20 = 88761 (≈88× weight of nice 0 = 1024).
const NICE_TO_WEIGHT: [u32; 40] = [
    88761, 71755, 56483, 46273, 36291,
    29154, 23254, 18705, 14949, 11916,
     9548,  7620,  6100,  4904,  3906,
     3121,  2501,  1991,  1586,  1277,
     1024,   820,   655,   526,   423,
      335,   272,   215,   172,   137,
      110,    87,    70,    56,    45,
       36,    29,    23,    18,    15,
];

#[inline(always)]
pub fn nice_to_weight(nice: i8) -> u32 {
    let idx = (nice as i32 + 20).clamp(0, 39) as usize;
    NICE_TO_WEIGHT[idx]
}

// SAFETY: SchedEntity contains *mut pointers (RB-tree links) which make
// it !Send and !Sync by default. In the kernel, entities are pinned to
// per-CPU runqueues and accessed under scheduler locks. The raw pointers
// are only dereferenced while holding the runqueue lock for the entity's
// CPU. Cross-CPU migration explicitly dequeues (removes from tree) before
// moving, so no pointer is live during the transfer.
unsafe impl Send for SchedEntity {}
unsafe impl Sync for SchedEntity {}

// ── Compile-time layout assertions ──────────────────────────────────────
// SchedEntity: 256 bytes total (data fills all 256, no implicit padding).
// 256 = power of two → array indexing is a shift, not a multiply.
const _: () = {
    assert!(core::mem::size_of::<SchedEntity>() == 256);
    assert!(core::mem::align_of::<SchedEntity>() >= 64);

    // Cache line 0: EEVDF hot path (bytes 0–63)
    assert!(core::mem::offset_of!(SchedEntity, sum_exec) == 64);

    // Cache line 1: warm policy fields (bytes 64–127)
    assert!(core::mem::offset_of!(SchedEntity, dl) == 128);

    // RB-tree links start at byte 216 (after accounting fields)
    assert!(core::mem::offset_of!(SchedEntity, rb_left) == 216);
};
