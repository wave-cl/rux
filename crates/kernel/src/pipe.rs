/// Kernel pipe interface.
///
/// Delegates to `rux_ipc::pipe` for ring buffer management.
/// This module adds fd allocation on top and implements PipeOps
/// for the fdtable.

pub use rux_ipc::pipe::{read, write, close, dup_ref, reset};

/// Singleton PipeOps implementation for the kernel fdtable wrapper.
pub static PIPE_OPS: KernelPipeOps = KernelPipeOps;

/// PipeOps implementation that delegates to rux_ipc::pipe.
pub struct KernelPipeOps;

impl rux_vfs::fdtable::PipeOps for KernelPipeOps {
    fn pipe_read(&self, pipe_id: u8, buf: *mut u8, len: usize) -> isize {
        rux_ipc::pipe::read(pipe_id, buf, len)
    }
    fn pipe_write(&self, pipe_id: u8, buf: *const u8, len: usize) -> isize {
        rux_ipc::pipe::write(pipe_id, buf, len)
    }
    fn pipe_close(&self, pipe_id: u8, is_write_end: bool) {
        rux_ipc::pipe::close(pipe_id, is_write_end);
    }
    fn pipe_dup_ref(&self, pipe_id: u8, is_write_end: bool) {
        rux_ipc::pipe::dup_ref(pipe_id, is_write_end);
    }
}

/// Create a new pipe. Returns (pipe_id, read_fd, write_fd) or error.
pub fn create() -> Result<(u8, isize, isize), isize> {
    let pipe_id = rux_ipc::pipe::alloc()?;

    let read_fd = rux_vfs::fdtable::alloc_pipe_fd(pipe_id, false)?;
    let write_fd = match rux_vfs::fdtable::alloc_pipe_fd(pipe_id, true) {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { rux_vfs::fdtable::sys_close(read_fd as usize, crate::syscall::IN_VFORK_CHILD, Some(&PIPE_OPS)) };
            rux_ipc::pipe::close(pipe_id, false);
            rux_ipc::pipe::close(pipe_id, true);
            return Err(e);
        }
    };

    Ok((pipe_id, read_fd, write_fd))
}
