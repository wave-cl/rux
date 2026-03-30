/// Kernel pipe interface.
///
/// Implements rux_vfs::fdtable traits (PipeOps, PipeAllocator) by
/// delegating to rux_ipc::pipe ring buffers.

pub use rux_ipc::pipe::{read, write, close, dup_ref, reset};

/// Singleton PipeOps implementation.
pub static PIPE_OPS: KernelPipeOps = KernelPipeOps;

/// Singleton PipeAllocator implementation.
pub static PIPE_ALLOC: KernelPipeAlloc = KernelPipeAlloc;

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

pub struct KernelPipeAlloc;

impl rux_vfs::fdtable::PipeAllocator for KernelPipeAlloc {
    fn alloc(&self) -> Result<u8, isize> {
        rux_ipc::pipe::alloc()
    }
    fn close(&self, pipe_id: u8, is_write_end: bool) {
        rux_ipc::pipe::close(pipe_id, is_write_end);
    }
}

/// Create a new pipe. Returns (pipe_id, read_fd, write_fd) or error.
pub fn create() -> Result<(u8, isize, isize), isize> {
    unsafe {
        rux_vfs::fdtable::create_pipe(
            &PIPE_ALLOC,
            &PIPE_OPS,
            crate::syscall::IN_VFORK_CHILD,
        )
    }
}
