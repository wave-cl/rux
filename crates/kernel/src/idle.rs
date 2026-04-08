/// Idle task — runs in slot 0 when no other tasks are runnable.
///
/// Halts the CPU until the next interrupt (timer tick at 1kHz).
/// Timer ISR calls wake_sleepers() which re-enqueues sleeping tasks
/// whose deadlines have passed, triggering a reschedule.
///
/// Must never be placed on the CFS run queue — the scheduler falls
/// back to slot 0 implicitly when pick_next() returns None.

pub extern "C" fn idle_loop() -> ! {
    loop {
        unsafe {
            use rux_arch::HaltOps;
            crate::arch::Arch::halt_until_interrupt();
            // After timer IRQ wakes us, check if any task became runnable
            let sched = crate::scheduler::get();
            if sched.need_resched {
                crate::arch::preempt_disable();
                sched.schedule();
                crate::arch::preempt_enable();
            }
        }
    }
}
