/// Kernel pipe interface — delegates to rux_ipc + rux_fs::fdtable.

#[allow(unused_imports)]
pub use rux_ipc::pipe::{read, write, close, dup_ref, reset};

/// Pipe function pointers — maps directly to rux_ipc::pipe functions.
pub static PIPE: &rux_fs::fdtable::PipeFns = &rux_ipc::PIPE_FNS;

/// Check if a pipe has data available (or EOF — writers closed).
pub fn has_data(pipe_id: u8) -> bool {
    rux_ipc::pipe::has_data(pipe_id)
}

/// Check if all writers have closed the pipe.
pub fn writers_closed(pipe_id: u8) -> bool {
    rux_ipc::pipe::writers_closed(pipe_id)
}

/// Create a new pipe. Returns (pipe_id, read_fd, write_fd) or error.
pub fn create() -> Result<(u8, isize, isize), isize> {
    rux_fs::fdtable::create_pipe(PIPE)
}

/// Wake tasks blocked on a specific pipe using the per-pipe waitlist.
///
/// Instead of scanning all MAX_PROCS tasks, reads the waitlist from the
/// pipe buffer (O(waiters) instead of O(MAX_PROCS)). Called after successful
/// pipe read (wakes writers), write (wakes readers), or close (EOF/EPIPE).
pub unsafe fn wake_pipe_waiters(pipe_id: u8) {
    use crate::task_table::*;

    let (count, waiters) = rux_ipc::pipe::get_waiters(pipe_id);
    if count == 0 { return; }

    for wi in 0..count as usize {
        let i = waiters[wi] as usize;
        if i < MAX_PROCS && TASK_TABLE[i].active
            && TASK_TABLE[i].state == TaskState::WaitingForPipe
        {
            TASK_TABLE[i].state = TaskState::Ready;
            crate::scheduler::locked_wake_task(i);
        }
    }
    rux_ipc::pipe::clear_all_waiters(pipe_id);
}
