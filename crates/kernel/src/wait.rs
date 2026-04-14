/// Unified sleep/block helper — replaces the 15+ duplicated sleep-wake
/// sequences across poll, select, epoll, nanosleep, futex, etc.

use crate::task_table::{TaskState, TASK_TABLE};

/// Why a blocked task was woken.
pub enum WakeReason {
    /// Deadline expired or I/O event (normal wake).
    Completed,
    /// An unblocked signal is pending — caller should return EINTR.
    Signal,
}

/// Block the current task until woken by I/O, timeout, or signal.
///
/// Sets the task state, registers a wake deadline, dequeues from the
/// scheduler run queue, and yields. On return, checks whether the
/// task was woken by a signal (caller should return EINTR) or normally.
///
/// For `WaitingForPoll` state, automatically registers on the poll wait queue.
///
/// # Safety
/// Must be called from syscall context with valid task_idx.
#[inline]
pub unsafe fn block_until(state: TaskState, deadline: u64) -> WakeReason {
    let task_idx = crate::task_table::current_task_idx();
    TASK_TABLE[task_idx].state = state;
    TASK_TABLE[task_idx].wake_at = deadline;
    if deadline > 0 {
        crate::deadline_queue::dq_insert(
            deadline, task_idx as u16, crate::deadline_queue::KIND_WAKE,
        );
    }

    if state == TaskState::WaitingForPoll {
        crate::task_table::poll_wait_register(task_idx);
    }

    let sched = crate::scheduler::get();
    sched.tasks[task_idx].entity.state = rux_sched::TaskState::Interruptible;
    sched.dequeue_current();
    sched.need_resched |= 1u64 << crate::percpu::cpu_id() as u32;
    crate::task_table::set_current_need_resched();
    sched.schedule();

    // Check if woken by a signal
    let hot = &TASK_TABLE[task_idx].signal_hot;
    let deliverable = hot.pending.0 & !hot.blocked.0;
    if deliverable != 0 {
        WakeReason::Signal
    } else {
        WakeReason::Completed
    }
}
