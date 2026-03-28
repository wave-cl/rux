/// ARM Generic Timer (EL1 physical timer).
///
/// Uses CNTP_TVAL_EL0 for countdown, CNTP_CTL_EL0 for control,
/// CNTPCT_EL0 for current count, CNTFRQ_EL0 for frequency.

static mut TICKS: u64 = 0;
static mut FREQ: u64 = 0;
static mut INTERVAL: u64 = 0;

/// Initialize the generic timer at approximately `hz` frequency.
pub unsafe fn init(hz: u32) {
    // Read timer frequency
    let freq: u64;
    core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq, options(nostack));
    FREQ = freq;

    // Calculate interval for desired Hz
    INTERVAL = freq / hz as u64;

    // Set the countdown timer
    core::arch::asm!("msr cntp_tval_el0, {}", in(reg) INTERVAL, options(nostack));

    // Enable the timer (bit 0 = enable, bit 1 = mask output)
    core::arch::asm!("msr cntp_ctl_el0, {}", in(reg) 1u64, options(nostack));
}

/// Handle a timer tick (called from IRQ handler).
pub fn handle_tick() {
    unsafe {
        TICKS += 1;

        // Re-arm the timer for the next interval
        core::arch::asm!("msr cntp_tval_el0, {}", in(reg) INTERVAL, options(nostack));

        // Scheduler tick
        let sched = crate::scheduler::get();
        sched.tick(1_000_000); // 1ms per tick at 1000 Hz
    }
}

/// Get the current tick count.
#[inline(always)]
pub fn ticks() -> u64 {
    unsafe { TICKS }
}

/// Read current time in nanoseconds since boot.
pub fn now_ns() -> u64 {
    unsafe {
        let count: u64;
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) count, options(nostack));
        if FREQ == 0 { return 0; }
        count * 1_000_000_000 / FREQ
    }
}
