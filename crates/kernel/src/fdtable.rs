/// File descriptor table — thin wrapper around rux_vfs::fdtable.
///
/// Re-exports the core fdtable from rux-vfs and provides convenience
/// wrappers that supply kernel-specific context (VFS, pipes, vfork flag).

pub use rux_vfs::fdtable::{
    OpenFile, FD_TABLE, EMPTY_FD, MAX_FDS, FIRST_FILE_FD,
    FD_STDIN, FD_STDOUT, FD_STDERR,
    get_fd_inode, alloc_pipe_fd, reset, is_serial_fd,
};

use crate::pipe::PIPE_OPS;

/// Open a file by path. Supplies kernel VFS automatically.
pub fn sys_open(path: &[u8]) -> i64 {
    unsafe { rux_vfs::fdtable::sys_open(path, crate::kstate::fs()) }
}

/// Open a file by inode with flags.
pub fn sys_open_ino(ino: rux_vfs::InodeId, flags: u32) -> i64 {
    unsafe { rux_vfs::fdtable::sys_open_ino(ino, flags, crate::kstate::fs()) }
}

/// Duplicate a file descriptor.
pub fn sys_dup(oldfd: usize) -> i64 {
    rux_vfs::fdtable::sys_dup(oldfd)
}

/// Duplicate a file descriptor to the lowest fd >= minfd.
pub fn sys_dupfd(oldfd: usize, minfd: usize) -> i64 {
    rux_vfs::fdtable::sys_dupfd(oldfd, minfd)
}

/// Duplicate fd to a specific newfd.
pub fn sys_dup2(oldfd: usize, newfd: usize) -> i64 {
    unsafe {
        rux_vfs::fdtable::sys_dup2(
            oldfd, newfd,
            crate::syscall::IN_VFORK_CHILD,
            Some(&PIPE_OPS),
        )
    }
}

/// Close a file descriptor.
pub fn sys_close(fd: usize) -> i64 {
    unsafe {
        rux_vfs::fdtable::sys_close(
            fd,
            crate::syscall::IN_VFORK_CHILD,
            Some(&PIPE_OPS),
        )
    }
}

/// Read from a file descriptor.
pub fn sys_read_fd(fd: usize, buf: *mut u8, len: usize) -> i64 {
    unsafe {
        rux_vfs::fdtable::sys_read_fd(
            fd, buf, len,
            crate::kstate::fs(),
            &PIPE_OPS,
        )
    }
}

/// Write to a file descriptor.
pub fn sys_write_fd(fd: usize, buf: *const u8, len: usize) -> i64 {
    unsafe {
        rux_vfs::fdtable::sys_write_fd(
            fd, buf, len,
            crate::kstate::fs(),
            &PIPE_OPS,
        )
    }
}

/// Seek on a file descriptor.
pub fn sys_lseek(fd: usize, offset: i64, whence: u32) -> i64 {
    unsafe {
        rux_vfs::fdtable::sys_lseek(fd, offset, whence, crate::kstate::fs())
    }
}
