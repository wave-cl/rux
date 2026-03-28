use crate::cpu::CpuId;

/// Dispatch queue identifier for sched_ext.
/// Local per-CPU queues use the CPU ID; global and user-defined
/// queues use arbitrary u64 IDs.
pub type DsqId = u64;

/// Well-known DSQ IDs.
pub const DSQ_LOCAL: DsqId = u64::MAX;
pub const DSQ_GLOBAL: DsqId = u64::MAX - 1;

/// Flags for dispatch operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DispatchFlag {
    /// Enqueue at head of DSQ (LIFO)
    EnqHead = 1 << 0,
    /// Use vtime ordering in DSQ instead of FIFO
    EnqVtime = 1 << 1,
    /// Task has been preempted
    Preempted = 1 << 2,
}

/// BPF-programmable scheduler operations.
///
/// Modeled after Linux's `struct sched_ext_ops`. Each callback is
/// optional in Linux (NULL = default behavior); here, default impls
/// provide the same fallback.
///
/// `T` is the task type, `C` is an opaque context the ext scheduler
/// implementation can carry (its internal state).
///
/// # Safety
/// Implementations run with scheduler locks held and must not panic,
/// allocate, or block. Misbehavior must be caught by the caller and
/// trigger fallback to the fair class.
pub unsafe trait SchedExtOps<T> {
    /// Select a CPU for a waking task. Return the chosen CPU.
    /// Default: return `prev_cpu`.
    fn select_cpu(&self, _task: &T, prev_cpu: CpuId, _wake_flags: u32) -> CpuId {
        prev_cpu
    }

    /// Enqueue a task. Implementation should dispatch to a DSQ
    /// via the provided dispatch callback or buffer internally.
    fn enqueue(&mut self, task: &mut T, enq_flags: u32);

    /// Dequeue a task (e.g., going to sleep).
    fn dequeue(&mut self, task: &mut T, deq_flags: u32);

    /// Called when the core needs tasks. Implementation should move
    /// tasks from internal buffers into DSQs.
    fn dispatch(&mut self, cpu: CpuId, prev: &mut T);

    /// Per-tick callback. Return `true` to request rescheduling.
    fn tick(&mut self, _task: &mut T) -> bool {
        false
    }

    /// Called when a new task is created (fork/clone).
    fn init_task(&mut self, _task: &mut T) {}

    /// Called when a task exits.
    fn exit_task(&mut self, _task: &mut T) {}

    /// A CPU is coming online and available for scheduling.
    fn cpu_online(&mut self, _cpu: CpuId) {}

    /// A CPU is going offline.
    fn cpu_offline(&mut self, _cpu: CpuId) {}

    /// Called when a task's CPU affinity changes.
    fn set_cpumask(&mut self, _task: &mut T, _cpumask: u64) {}

    /// Called when a task changes nice/weight.
    fn set_weight(&mut self, _task: &mut T, _weight: u32) {}

    /// Time slice for a task in nanoseconds.
    /// Default: 20ms (SCX_SLICE_DFL).
    fn task_slice(&self, _task: &T) -> u64 {
        20_000_000
    }
}
