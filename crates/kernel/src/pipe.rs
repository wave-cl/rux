/// Kernel pipe interface.
///
/// Uses rux_ipc::IpcPipe which directly implements PipeOps and
/// PipeAllocator by mapping to pipe ring buffer functions.

pub use rux_ipc::pipe::{read, write, close, dup_ref, reset};

/// Singleton used by fdtable callers throughout the kernel.
pub static PIPE: rux_ipc::IpcPipe = rux_ipc::IpcPipe;

/// Create a new pipe. Returns (pipe_id, read_fd, write_fd) or error.
pub fn create() -> Result<(u8, isize, isize), isize> {
    unsafe {
        rux_vfs::fdtable::create_pipe(
            &PIPE,
            &PIPE,
            crate::syscall::IN_VFORK_CHILD,
        )
    }
}
