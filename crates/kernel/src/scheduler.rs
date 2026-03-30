/// Kernel scheduler — thin wrapper around rux_sched::kernel::Scheduler.
///
/// The scheduling logic lives in `rux_sched::kernel`. This module provides
/// the global static instance and the arch-specific context function setup.

pub use rux_sched::kernel::{Scheduler, KernelTask, ContextFns, MAX_TASKS};

/// Global scheduler instance.
/// Accessed from the timer ISR and from kernel_main.
static mut SCHED: Scheduler = Scheduler::new();

/// Get a mutable reference to the global scheduler.
///
/// # Safety
/// Must be called with interrupts disabled or from a single-CPU context.
pub unsafe fn get() -> &'static mut Scheduler {
    &mut *(&raw mut SCHED)
}

/// Initialize the scheduler's context switch functions for the current arch.
///
/// # Safety
/// Must be called once before any task creation or scheduling.
pub unsafe fn init_context_fns() {
    use rux_arch::ContextOps;
    get().set_context_fns(ContextFns {
        context_switch: crate::arch::Arch::context_switch,
        init_task_stack: crate::arch::Arch::init_task_stack,
    });
}
