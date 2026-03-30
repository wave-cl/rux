/// Kernel pipe interface.
///
/// Delegates to `rux_ipc::pipe` for ring buffer management.
/// This module adds fd allocation on top.

pub use rux_ipc::pipe::{read, write, close, dup_ref, reset};

/// Create a new pipe. Returns (pipe_id, read_fd, write_fd) or error.
pub fn create() -> Result<(u8, i64, i64), i64> {
    let pipe_id = rux_ipc::pipe::alloc()?;

    let read_fd = crate::fdtable::alloc_pipe_fd(pipe_id, false)?;
    let write_fd = match crate::fdtable::alloc_pipe_fd(pipe_id, true) {
        Ok(fd) => fd,
        Err(e) => {
            crate::fdtable::sys_close(read_fd as usize);
            rux_ipc::pipe::close(pipe_id, false);
            rux_ipc::pipe::close(pipe_id, true);
            return Err(e);
        }
    };

    Ok((pipe_id, read_fd, write_fd))
}
