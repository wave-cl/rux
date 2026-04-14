/// Kernel scheduler — thin wrapper around rux_sched::kernel::Scheduler.
///
/// The scheduling logic lives in `rux_sched::kernel`. This module provides
/// the global static instance and the arch-specific context function setup.

pub use rux_sched::kernel::{Scheduler, ContextFns};

/// Global scheduler instance.
/// Accessed from the timer ISR and from kernel_main.
static mut SCHED: Scheduler = Scheduler::new();

/// Per-CPU scheduler locks (Linux rq->lock). Each CPU's lock protects
/// only that CPU's runqueue, eliminating cross-CPU contention.
use core::sync::atomic::{AtomicBool, Ordering};
static PERCPU_SCHED_LOCK: [AtomicBool; crate::percpu::MAX_CPUS] = {
    const UNLOCKED: AtomicBool = AtomicBool::new(false);
    [UNLOCKED; crate::percpu::MAX_CPUS]
};

/// Acquire the scheduler lock for a specific CPU's runqueue.
#[inline(always)]
pub fn sched_lock_cpu(cpu: usize) {
    unsafe { crate::arch::preempt_disable(); }
    while PERCPU_SCHED_LOCK[cpu].compare_exchange_weak(
        false, true, Ordering::Acquire, Ordering::Relaxed,
    ).is_err() {
        core::hint::spin_loop();
    }
}

/// Release a specific CPU's scheduler lock.
#[inline(always)]
pub fn sched_unlock_cpu(cpu: usize) {
    PERCPU_SCHED_LOCK[cpu].store(false, Ordering::Release);
    unsafe { crate::arch::preempt_enable(); }
}

/// Try to acquire a CPU's lock without spinning (for ISR context).
#[inline(always)]
fn try_lock_cpu(cpu: usize) -> bool {
    PERCPU_SCHED_LOCK[cpu].compare_exchange(
        false, true, Ordering::Acquire, Ordering::Relaxed,
    ).is_ok()
}

/// Get a mutable reference to the global scheduler.
///
/// # Safety
/// Caller must hold per-CPU lock or be in a single-CPU context (boot, ISR with IF=0).
#[inline(always)]
pub unsafe fn get() -> &'static mut Scheduler {
    &mut *(&raw mut SCHED)
}

/// Per-CPU tick: try-lock THIS CPU's runqueue only. No contention with other CPUs.
#[inline(always)]
pub unsafe fn locked_tick(elapsed_ns: u64) {
    let cpu = crate::percpu::cpu_id();
    crate::arch::preempt_disable();
    if try_lock_cpu(cpu) {
        {
            let idx = crate::task_table::current_task_idx();
            if idx < crate::task_table::MAX_PROCS {
                crate::task_table::TASK_TABLE[idx].cpu_time_ns += elapsed_ns;
                crate::posix_timer::check_cpu_timers(idx);
            }
        }
        let sched = get();
        sched.tick(elapsed_ns);
        if sched.need_resched & (1u64 << cpu as u32) != 0 {
            crate::task_table::set_current_need_resched();
        }
        sched_unlock_cpu(cpu);
    } else {
        crate::arch::preempt_enable();
    }
}

/// Wake a task: acquires the TARGET CPU's lock, enqueues, releases.
/// Sends a reschedule IPI if the task's CPU differs from the caller's.
#[inline(always)]
pub unsafe fn locked_wake_task(idx: usize) {
    let target_cpu = get().tasks[idx].entity.cpu as usize;
    sched_lock_cpu(target_cpu);
    get().wake_task(idx);
    sched_unlock_cpu(target_cpu);
    send_resched_ipi_if_remote(target_cpu as u32);
}

/// Send a reschedule IPI to a remote CPU if the target differs from ours.
#[inline(always)]
pub unsafe fn send_resched_ipi_if_remote(target_cpu: u32) {
    let my_cpu = crate::percpu::cpu_id() as u32;
    if target_cpu != my_cpu && crate::percpu::cpu(target_cpu as usize).online {
        #[cfg(target_arch = "x86_64")]
        crate::arch::x86_64::apic::send_reschedule(target_cpu as usize);
        #[cfg(target_arch = "aarch64")]
        crate::arch::aarch64::gic::send_reschedule(target_cpu as usize);
    }
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
        get_cpu: Some(|| crate::percpu::cpu_id() as u32),
    });
    // Per-CPU FD_TABLE callback
    rux_fs::fdtable::GET_CPU_FN = Some(|| crate::percpu::cpu_id());
    // Socket refcount callbacks for dup/close in fdtable
    rux_fs::fdtable::SOCKET_DUP_REF = Some(crate::syscall::socket::dup_socket_ref);
    rux_fs::fdtable::SOCKET_CLOSE_REF = Some(crate::syscall::socket::close_socket_ref);
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
        crate::idle::idle_loop as *const () as usize,
        0, // nice
    );
    // Slot 0 is already marked active in Scheduler::new().
    // PID 1 runs in slot 1 — set it as current and active in the scheduler.
    sched.tasks[1].active = true;
    sched.tasks[1].entity = rux_sched::entity::SchedEntity::new(1);
    sched.tasks[1].entity.state = rux_sched::TaskState::Running;
    sched.current_per_cpu[0] = 1; // BSP starts with PID 1
}
