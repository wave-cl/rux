/// Target timer frequency in Hz.
pub const TICK_HZ: u32 = 1000;

/// Timer hardware operations.
///
/// # Safety
/// `init` programs hardware timer registers.
/// `ack` acknowledges a timer interrupt (writes EOI).
pub unsafe trait TimerOps {
    /// Initialize the timer to fire at approximately `TICK_HZ` frequency.
    /// x86_64: APIC timer or PIT. aarch64: CNTP_TVAL_EL0 + CNTP_CTL_EL0.
    unsafe fn init();

    /// Read current time in nanoseconds since boot.
    /// x86_64: TSC with calibrated frequency. aarch64: CNTPCT_EL0 / CNTFRQ_EL0.
    fn now_ns() -> u64;

    /// Acknowledge the timer interrupt (send EOI / clear pending).
    unsafe fn ack();
}
