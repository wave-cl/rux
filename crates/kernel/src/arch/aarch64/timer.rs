/// ARM Generic Timer (EL1 physical timer).

use core::sync::atomic::{AtomicU64, Ordering};

static TICKS: AtomicU64 = AtomicU64::new(0);
static FREQ: AtomicU64 = AtomicU64::new(0);
static INTERVAL: AtomicU64 = AtomicU64::new(0);

pub unsafe fn init(hz: u32) {
    let freq: u64;
    core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq, options(nostack));
    FREQ.store(freq, Ordering::Relaxed);

    let interval = freq / hz as u64;
    INTERVAL.store(interval, Ordering::Relaxed);

    core::arch::asm!("msr cntp_tval_el0, {}", in(reg) interval, options(nostack));
    core::arch::asm!("msr cntp_ctl_el0, {}", in(reg) 1u64, options(nostack));
}

pub fn handle_tick() {
    TICKS.fetch_add(1, Ordering::Relaxed);

    let interval = INTERVAL.load(Ordering::Relaxed);
    unsafe {
        core::arch::asm!("msr cntp_tval_el0, {}", in(reg) interval, options(nostack));

        // Wake sleeping tasks whose deadlines have passed
        crate::task_table::wake_sleepers();

        #[cfg(feature = "net")]
        if rux_net::is_configured() { rux_net::poll(TICKS.load(core::sync::atomic::Ordering::Relaxed)); }

        crate::scheduler::locked_tick(1_000_000);
        // ISR preemption is handled by aarch64_isr_check_preempt() in the
        // assembly IRQ handlers (irq_el0_handler, irq_el1_handler) AFTER
        // switching back from the per-CPU IRQ stack to the task stack.
        // schedule() runs on the task stack where the exception frame is
        // preserved across context_switch.
    }
}

#[inline(always)]
pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

/// Stop the periodic timer (tickless idle).
pub unsafe fn stop_timer() {
    core::arch::asm!("msr cntp_ctl_el0, xzr", options(nostack));
}

/// Restart the periodic timer (exit tickless idle).
pub unsafe fn start_timer() {
    let interval = INTERVAL.load(Ordering::Relaxed);
    core::arch::asm!("msr cntp_tval_el0, {}", in(reg) interval, options(nostack));
    core::arch::asm!("msr cntp_ctl_el0, {}", in(reg) 1u64, options(nostack));
}

#[allow(dead_code)]
pub fn now_ns() -> u64 {
    let count: u64;
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) count, options(nostack)); }
    let freq = FREQ.load(Ordering::Relaxed);
    if freq == 0 { return 0; }
    count * 1_000_000_000 / freq
}
