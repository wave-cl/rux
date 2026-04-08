/// Kernel scheduler — thin wrapper around rux_sched::kernel::Scheduler.
///
/// The scheduling logic lives in `rux_sched::kernel`. This module provides
/// the global static instance and the arch-specific context function setup.

pub use rux_sched::kernel::{Scheduler, ContextFns};

/// Global scheduler instance.
/// Accessed from the timer ISR and from kernel_main.
static mut SCHED: Scheduler = Scheduler::new();

/// Scheduler spinlock for SMP safety.
/// Protects SCHED state (CFS tree, current task, clock) from concurrent
/// access by BSP timer ISR, AP timer ISR, and syscall return paths.
pub static SCHED_LOCK: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Acquire the scheduler lock (spinlock). Also disables preemption.
#[inline(always)]
pub fn sched_lock() {
    unsafe { crate::arch::preempt_disable(); }
    while SCHED_LOCK.compare_exchange_weak(
        false, true,
        core::sync::atomic::Ordering::Acquire,
        core::sync::atomic::Ordering::Relaxed,
    ).is_err() {
        core::hint::spin_loop();
    }
}

/// Release the scheduler lock. Also re-enables preemption.
#[inline(always)]
pub fn sched_unlock() {
    SCHED_LOCK.store(false, core::sync::atomic::Ordering::Release);
    unsafe { crate::arch::preempt_enable(); }
}

/// Get a mutable reference to the global scheduler.
///
/// # Safety
/// Caller must hold SCHED_LOCK or be in a single-CPU context (boot, ISR with IF=0).
#[inline(always)]
pub unsafe fn get() -> &'static mut Scheduler {
    &mut *(&raw mut SCHED)
}

/// Lock-protected tick: acquire lock, call tick, release.
#[inline(always)]
pub unsafe fn locked_tick(elapsed_ns: u64) {
    sched_lock();
    get().tick(elapsed_ns);
    sched_unlock();
}

/// Lock-protected wake_task: acquire lock, wake, release.
#[inline(always)]
pub unsafe fn locked_wake_task(idx: usize) {
    sched_lock();
    get().wake_task(idx);
    sched_unlock();
}

/// Initialize the scheduler's context switch functions for the current arch.
///
/// # Safety
/// Must be called once before any task creation or scheduling.
pub unsafe fn init_context_fns() {
    use rux_arch::{ContextOps, TimerControl};
    get().set_context_fns(ContextFns {
        context_switch: crate::arch::Arch::context_switch,
        init_task_stack: crate::arch::Arch::init_task_stack,
        stop_timer: crate::arch::Arch::stop_timer,
        start_timer: crate::arch::Arch::start_timer,
        pre_switch: Some(crate::task_table::swap_process_state),
    });
}

/// Set up the idle task (slot 0) in the scheduler with a proper stack frame,
/// and mark PID 1 (slot 1) as the initial running task.
///
/// # Safety
/// Must be called after init_context_fns() and init_idle()/init_pid1().
pub unsafe fn init_idle_sched() {
    use rux_arch::ContextOps;
    let sched = get();
    let idle_stack_top = crate::task_table::KSTACKS.0[0].as_ptr() as usize
        + crate::task_table::KSTACK_SIZE;
    sched.tasks[0].saved_sp = crate::arch::Arch::init_task_stack(
        idle_stack_top,
        crate::idle::idle_loop as usize,
        0, // nice
    );
    // Slot 0 is already marked active in Scheduler::new().
    // PID 1 runs in slot 1 — set it as current and active in the scheduler.
    sched.tasks[1].active = true;
    sched.tasks[1].entity = rux_sched::entity::SchedEntity::new(1);
    sched.tasks[1].entity.state = rux_sched::TaskState::Running;
    sched.current = 1;
}
