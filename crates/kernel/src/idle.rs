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
            use rux_arch::HaltOps;
            crate::arch::Arch::halt_until_interrupt();
            IDLE_TICKS.fetch_add(1, Ordering::Relaxed);
            // After timer IRQ wakes us, check if any task became runnable
            let sched = crate::scheduler::get();
            if sched.need_resched & (1u64 << crate::percpu::cpu_id() as u32) != 0 {
                crate::arch::preempt_disable();
                sched.schedule();
                crate::arch::preempt_enable();
            }
        }
    }
}
