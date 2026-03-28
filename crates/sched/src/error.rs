#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SchedError {
    TaskNotFound,
    InvalidPriority,
    InvalidPolicy,
    InvalidDeadlineParams,
    /// Deadline admission control rejected — not enough bandwidth
    BandwidthExceeded,
    QueueFull,
    NoRunnableTask,
    CpuOffline,
    MigrationDenied,
}
