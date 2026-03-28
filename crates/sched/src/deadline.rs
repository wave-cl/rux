/// Deadline scheduling parameters (EDF + CBS).
/// All times in nanoseconds.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct DeadlineParams {
    /// Maximum execution time per period
    pub runtime: u64,
    /// Relative deadline from activation
    pub deadline: u64,
    /// Activation period
    pub period: u64,
}

impl DeadlineParams {
    pub const ZERO: Self = Self {
        runtime: 0,
        deadline: 0,
        period: 0,
    };

    /// Bandwidth fraction as runtime/period (fixed-point 20.12).
    #[inline(always)]
    pub const fn bandwidth_fp12(&self) -> u64 {
        if self.period == 0 {
            return 0;
        }
        (self.runtime << 12) / self.period
    }

    #[inline(always)]
    pub const fn is_valid(&self) -> bool {
        self.runtime > 0
            && self.deadline > 0
            && self.period > 0
            && self.runtime <= self.deadline
            && self.deadline <= self.period
    }
}

/// Runtime state for a deadline task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeadlineState {
    /// Not currently using deadline scheduling
    Inactive = 0,
    /// Active, budget remaining
    Active = 1,
    /// Budget exhausted, waiting for replenishment
    Throttled = 2,
    /// New period, awaiting activation
    New = 3,
}
