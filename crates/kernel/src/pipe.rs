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
