pub type TaskId = u64;

/// Task lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TaskState {
    /// On a runqueue, eligible to be picked
    Ready = 0,
    /// Currently executing on a CPU
    Running = 1,
    /// Sleeping — waiting on I/O, lock, futex, etc.
    Interruptible = 2,
    /// Sleeping — cannot be woken by signals
    #[allow(dead_code)]
    Uninterruptible = 3,
    /// Terminated, waiting for parent to reap
    Zombie = 4,
    /// Terminated and reaped
    Dead = 5,
    /// Stopped by signal (SIGSTOP/SIGTSTP)
    Stopped = 6,
}

impl TaskState {
    #[inline(always)]
    pub const fn is_runnable(self) -> bool {
        matches!(self, Self::Ready | Self::Running)
    }

    #[inline(always)]
    pub const fn is_blocked(self) -> bool {
        matches!(self, Self::Interruptible | Self::Uninterruptible)
    }
}
