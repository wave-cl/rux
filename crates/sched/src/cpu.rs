pub type CpuId = u32;

/// Inline CPU bitmask for ≤64 CPUs. For larger systems,
/// implementations should extend with a backing array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct CpuMask(pub u64);

impl CpuMask {
    pub const EMPTY: Self = Self(0);
    pub const ALL: Self = Self(u64::MAX);

    #[inline(always)]
    pub const fn single(cpu: CpuId) -> Self {
        Self(1u64 << cpu)
    }

    #[inline(always)]
    pub const fn contains(self, cpu: CpuId) -> bool {
        (self.0 >> cpu) & 1 != 0
    }

    #[inline(always)]
    pub const fn set(self, cpu: CpuId) -> Self {
        Self(self.0 | (1u64 << cpu))
    }

    #[inline(always)]
    pub const fn clear(self, cpu: CpuId) -> Self {
        Self(self.0 & !(1u64 << cpu))
    }

    /// Maps to POPCNT on x86_64 with BMI enabled.
    #[inline(always)]
    pub const fn count(self) -> u32 {
        self.0.count_ones()
    }

    #[inline(always)]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    #[inline(always)]
    pub const fn and(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    #[inline(always)]
    pub const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns the lowest set CPU. Maps to TZCNT on x86_64 with BMI.
    #[inline(always)]
    pub const fn first(self) -> Option<CpuId> {
        if self.0 == 0 {
            None
        } else {
            Some(self.0.trailing_zeros())
        }
    }
}

/// Per-CPU runqueue operations.
///
/// Each CPU owns a `RunQueue` that holds class-specific sub-queues.
/// The core scheduler calls `pick_next` which walks the class chain
/// from highest to lowest priority.
///
/// Generic over the task type for monomorphization.
pub trait RunQueue<T> {
    /// Pick the highest-priority runnable task on this CPU.
    /// Iterates scheduler classes from Stop → Idle.
    fn pick_next(&mut self, prev: &mut T) -> Option<*mut T>;

    /// Enqueue a task onto this CPU's runqueue.
    fn enqueue(&mut self, task: &mut T, wake_flags: u32);

    /// Dequeue a task from this CPU's runqueue.
    fn dequeue(&mut self, task: &mut T, sleep_flags: u32);

    /// Timer tick — update accounting, check for preemption.
    /// Returns `true` if reschedule needed.
    fn tick(&mut self, curr: &mut T) -> bool;

    /// Number of runnable tasks on this CPU.
    fn nr_running(&self) -> u32;

    /// Is this CPU idle (only idle task runnable)?
    fn is_idle(&self) -> bool;

    /// Current timestamp from this CPU's clock (nanoseconds).
    fn clock_ns(&self) -> u64;
}
