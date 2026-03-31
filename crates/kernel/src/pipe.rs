/// Kernel pipe interface — delegates to rux_ipc + rux_fs::fdtable.

pub use rux_ipc::pipe::{read, write, close, dup_ref, reset};

/// Pipe function pointers — maps directly to rux_ipc::pipe functions.
pub static PIPE: &rux_fs::fdtable::PipeFns = &rux_ipc::PIPE_FNS;

/// Create a new pipe. Returns (pipe_id, read_fd, write_fd) or error.
pub fn create() -> Result<(u8, isize, isize), isize> {
    unsafe {
        rux_fs::fdtable::create_pipe(PIPE, crate::syscall::PROCESS.in_vfork_child)
    }
}

/// Wake all tasks blocked on a specific pipe (either reading or writing).
/// Called after a successful pipe write (to wake blocked readers) or
/// after a successful pipe read (to wake blocked writers).
pub unsafe fn wake_pipe_waiters(pipe_id: u8) {
    use crate::task_table::*;
    use rux_sched::SchedClassOps;
    let sched = crate::scheduler::get();
    for i in 0..MAX_PROCS {
        if TASK_TABLE[i].active
            && TASK_TABLE[i].state == TaskState::WaitingForPipe
            && TASK_TABLE[i].waiting_pipe_id == pipe_id
        {
            TASK_TABLE[i].state = TaskState::Ready;
            sched.wake_task(i);
        }
    }
}
