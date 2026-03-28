use crate::cpu::CpuId;

/// Scheduler class priority levels — ordered highest to lowest.
/// Mirrors Linux's linker-section-ordered sched_class chain.
/// The discriminant IS the priority (lower = higher priority).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum SchedClass {
    /// stop_sched_class — CPU stop/migration, one task per CPU max
    Stop = 0,
    /// dl_sched_class — SCHED_DEADLINE (EDF + CBS)
    Deadline = 1,
    /// rt_sched_class — SCHED_FIFO / SCHED_RR
    Rt = 2,
    /// fair_sched_class — SCHED_NORMAL/BATCH/IDLE (EEVDF)
    Fair = 3,
    /// ext_sched_class — SCHED_EXT (BPF-programmable)
    Ext = 4,
    /// idle_sched_class — per-CPU idle loop
    Idle = 5,
}

impl SchedClass {
    /// Next lower-priority class, if any.
    #[inline(always)]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::Stop => Some(Self::Deadline),
            Self::Deadline => Some(Self::Rt),
            Self::Rt => Some(Self::Fair),
            Self::Fair => Some(Self::Ext),
            Self::Ext => Some(Self::Idle),
            Self::Idle => None,
        }
    }

    /// Iterate from this class down through all lower-priority classes.
    #[inline(always)]
    pub const fn is_above(self, other: Self) -> bool {
        (self as u8) < (other as u8)
    }
}

/// Operations each scheduler class must implement.
/// Modeled after Linux's `struct sched_class`.
///
/// Generic over `T` (the task type) to enable static dispatch —
/// each class implementation is monomorphized, no vtable.
pub trait SchedClassOps<T> {
    /// Add a task to this class's runqueue on the given CPU.
    /// `wake_flags` encodes wake-up context (e.g., waking from sleep vs fork).
    fn enqueue(&mut self, cpu: CpuId, task: &mut T, wake_flags: u32);

    /// Remove a task from this class's runqueue.
    fn dequeue(&mut self, cpu: CpuId, task: &mut T, sleep_flags: u32);

    /// Select the next task to run. Returns `None` if no runnable task
    /// in this class on the given CPU.
    fn pick_next(&mut self, cpu: CpuId, prev: &mut T) -> Option<*mut T>;

    /// Check whether `new` should preempt `curr` on this CPU.
    fn check_preempt(&self, cpu: CpuId, curr: &T, new: &T) -> bool;

    /// Per-tick accounting. Called from the timer interrupt.
    /// Returns `true` if a reschedule is needed.
    fn task_tick(&mut self, cpu: CpuId, curr: &mut T) -> bool;

    /// Called when a task changes to this class's policy.
    fn switched_to(&mut self, cpu: CpuId, task: &mut T);

    /// Called when a task's priority changes within this class.
    fn prio_changed(&mut self, cpu: CpuId, task: &mut T, old_prio: i32);

    /// Select the best CPU for a waking task.
    fn select_cpu(&self, task: &T, prev_cpu: CpuId, wake_flags: u32) -> CpuId;

    /// Balance/migrate tasks across CPUs.
    fn balance(&mut self, cpu: CpuId) -> bool;

    /// Can this task be migrated off `cpu`?
    fn task_is_migratable(&self, task: &T, cpu: CpuId) -> bool;

    /// Update task state when placed on a runqueue.
    fn set_next(&mut self, cpu: CpuId, task: &mut T);

    /// Update task state when taken off CPU (not dequeue — just no longer current).
    fn put_prev(&mut self, cpu: CpuId, task: &mut T);

    /// Called on fork — initialize scheduling entity for a new task.
    fn task_fork(&mut self, task: &mut T);

    /// Called on exit — clean up scheduling entity.
    fn task_dead(&mut self, task: &mut T);
}
