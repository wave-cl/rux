/// Process time accounting (all values in nanoseconds).
#[repr(C)]
pub struct ProcessTimes {
    /// User-mode CPU time consumed by this process.
    pub utime: u64,
    /// Kernel-mode CPU time consumed by this process.
    pub stime: u64,
    /// User-mode CPU time consumed by waited-for children.
    pub cutime: u64,
    /// Kernel-mode CPU time consumed by waited-for children.
    pub cstime: u64,
    /// Monotonic time since boot when this process was created.
    pub start_time: u64,
}

const _: () = assert!(core::mem::size_of::<ProcessTimes>() == 40);

impl ProcessTimes {
    pub const ZERO: Self = Self {
        utime: 0, stime: 0, cutime: 0, cstime: 0, start_time: 0,
    };
}

impl Default for ProcessTimes {
    fn default() -> Self { Self::ZERO }
}
