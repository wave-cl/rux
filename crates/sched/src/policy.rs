/// Scheduling policies — maps 1:1 to Linux SCHED_* constants.
/// These are user-facing policy choices assigned to tasks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SchedPolicy {
    /// SCHED_NORMAL — default timesharing (EEVDF)
    Normal = 0,
    /// SCHED_FIFO — fixed-priority, no timeslice, runs until it yields or is preempted
    Fifo = 1,
    /// SCHED_RR — fixed-priority with per-task timeslice rotation
    RoundRobin = 2,
    /// SCHED_BATCH — like Normal but never preempts for interactivity
    Batch = 3,
    /// SCHED_IDLE — extremely low weight within fair class (not the idle *class*)
    IdlePolicy = 5,
    /// SCHED_DEADLINE — earliest deadline first with bandwidth reservation
    Deadline = 6,
    /// SCHED_EXT — BPF-programmable custom policy
    Ext = 7,
}

impl SchedPolicy {
    /// Which scheduler class handles this policy.
    #[inline(always)]
    pub const fn class(self) -> super::SchedClass {
        match self {
            Self::Fifo | Self::RoundRobin => super::SchedClass::Rt,
            Self::Normal | Self::Batch | Self::IdlePolicy => super::SchedClass::Fair,
            Self::Deadline => super::SchedClass::Deadline,
            Self::Ext => super::SchedClass::Ext,
        }
    }

    #[inline(always)]
    pub const fn is_realtime(self) -> bool {
        matches!(self, Self::Fifo | Self::RoundRobin | Self::Deadline)
    }
}
