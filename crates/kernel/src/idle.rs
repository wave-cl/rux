/// Idle task — runs in slot 0 when no other tasks are runnable.

use core::sync::atomic::{AtomicU64, Ordering};

/// Cumulative idle ticks (incremented each time the idle loop wakes from HLT/WFI).
static IDLE_TICKS: AtomicU64 = AtomicU64::new(0);

/// Get the cumulative idle tick count (for /proc/uptime idle field).
pub fn idle_ticks() -> u64 {
    IDLE_TICKS.load(Ordering::Relaxed)
}

pub extern "C" fn idle_loop() -> ! {
    loop {
        unsafe {
            // Tickless idle (Linux NO_HZ): stop timer before halting if no
            // pending deadlines AND at least one task has been created (post-boot).
            // Don't stop during early boot when the timer is needed for init.
            if crate::deadline_queue::DEADLINE_QUEUE.peek_deadline() == u64::MAX
                && crate::scheduler::get().cfs.nr_running(0) == 0
                && IDLE_TICKS.load(Ordering::Relaxed) > 100
            {
                use rux_arch::TimerControl;
                crate::arch::Arch::stop_timer();
            }

            use rux_arch::HaltOps;
            crate::arch::Arch::halt_until_interrupt();
            IDLE_TICKS.fetch_add(1, Ordering::Relaxed);

            // Restart timer after waking (external IRQ may have woken us)
            {
                use rux_arch::TimerControl;
                crate::arch::Arch::start_timer();
            }

            if crate::task_table::current_needs_resched() {
                crate::task_table::clear_current_need_resched();
                crate::arch::preempt_disable();
                crate::scheduler::get().schedule();
                crate::arch::preempt_enable();
            }
        }
    }
}
