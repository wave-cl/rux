/// Minimal per-process file descriptor table.
///
/// Architecture-independent. Since rux runs one user process at a time
/// (vfork semantics), a single global table suffices.
///
/// Kernel-specific dependencies (VFS, pipes, vfork flag) are injected
/// via parameters and the `PipeOps` trait.

use crate::{FileSystem, InodeStat};

pub const MAX_FDS: usize = 64;
pub const FD_STDIN: usize = 0;
pub const FD_STDOUT: usize = 1;
pub const FD_STDERR: usize = 2;
pub const FIRST_FILE_FD: usize = 3;

/// Pipe operations as function pointers — no traits, no wrappers.
/// Pass rux_ipc::pipe functions directly.
pub struct PipeFns {
    pub read: fn(u8, *mut u8, usize) -> isize,
    pub write: fn(u8, *const u8, usize) -> isize,
    pub close: fn(u8, bool),
    pub dup_ref: fn(u8, bool),
    pub alloc: fn() -> Result<u8, isize>,
}

#[derive(Clone, Copy)]
pub struct OpenFile {
    pub ino: u64,
    pub offset: usize,
    pub flags: u32,
    pub active: bool,
    pub is_console: bool,  // true = fd routes to console (stdin/stdout/stderr default)
    pub is_pipe: bool,
    pub pipe_id: u8,
    pub pipe_write: bool,
}

pub const EMPTY_FD: OpenFile = OpenFile {
    ino: 0, offset: 0, flags: 0, active: false, is_console: false,
    is_pipe: false, pipe_id: 0, pipe_write: false,
};

pub static mut FD_TABLE: [OpenFile; MAX_FDS] = [EMPTY_FD; MAX_FDS];

/// Get the inode for a file descriptor (for getdents to read directory).
pub fn get_fd_inode(fd: usize) -> Option<u64> {
    unsafe {
        if fd < MAX_FDS && FD_TABLE[fd].active {
            Some(FD_TABLE[fd].ino)
        } else {
            None
        }
    }
}

/// Open a file by path (absolute only — legacy). Returns fd.
pub fn sys_open<F: FileSystem>(path: &[u8], fs: &mut F) -> isize {
    let ino = match crate::path::resolve_path(fs, path) {
        Ok(ino) => ino,
        Err(_) => return -2,
    };
    sys_open_ino(ino, 0, fs)
}

/// Open a file by inode with flags. Returns fd on success, negative errno on failure.
pub fn sys_open_ino<F: FileSystem>(ino: crate::InodeId, flags: u32, fs: &mut F) -> isize {
    unsafe {
        for fd in FIRST_FILE_FD..MAX_FDS {
            if !FD_TABLE[fd].active {
                let mut offset = 0usize;
                // O_APPEND: start at end of file
                if flags & 0x400 != 0 {
                    let mut stat = core::mem::zeroed::<InodeStat>();
                    if fs.stat(ino, &mut stat).is_ok() {
                        offset = stat.size as usize;
                    }
                }
                // O_TRUNC: truncate file to 0
                if flags & 0x200 != 0 {
                    let _ = fs.truncate(ino, 0);
                }
                FD_TABLE[fd] = OpenFile {
                    ino: ino as u64, offset, flags, active: true, is_console: false,
                    is_pipe: false, pipe_id: 0, pipe_write: false,
                };
                return fd as isize;
            }
        }
        -24 // -EMFILE
    }
}

/// Duplicate a file descriptor to the lowest available fd (>= 3).
pub fn sys_dup(oldfd: usize) -> isize {
    if oldfd >= MAX_FDS { return -9; }
    unsafe {
        if oldfd > 2 && !FD_TABLE[oldfd].active { return -9; }
        for newfd in FIRST_FILE_FD..MAX_FDS {
            if !FD_TABLE[newfd].active {
                return sys_dup2_inner(oldfd, newfd, false, None);
            }
        }
        -24 // -EMFILE
    }
}

/// Duplicate a file descriptor to the lowest available fd >= minfd.
/// Used by fcntl(F_DUPFD).
pub fn sys_dupfd(oldfd: usize, minfd: usize) -> isize {
    if oldfd >= MAX_FDS { return -9; }
    unsafe {
        if oldfd > 2 && !FD_TABLE[oldfd].active { return -9; }
        let start = minfd.max(FIRST_FILE_FD);
        for newfd in start..MAX_FDS {
            if !FD_TABLE[newfd].active {
                return sys_dup2_inner(oldfd, newfd, false, None);
            }
        }
        -24 // -EMFILE
    }
}

/// Duplicate a file descriptor. Real dup2 implementation.
pub fn sys_dup2(oldfd: usize, newfd: usize, in_vfork: bool, pipes: Option<&PipeFns>) -> isize {
    sys_dup2_inner(oldfd, newfd, in_vfork, pipes)
}

fn sys_dup2_inner(oldfd: usize, newfd: usize, in_vfork: bool, pipes: Option<&PipeFns>) -> isize {
    if oldfd >= MAX_FDS || newfd >= MAX_FDS { return -9; }
    unsafe {
        if oldfd > 2 && !FD_TABLE[oldfd].active { return -9; }
        // Close newfd if it's currently open (including pipe cleanup)
        if FD_TABLE[newfd].active {
            if FD_TABLE[newfd].is_pipe && !in_vfork {
                if let Some(p) = pipes {
                    (p.close)(FD_TABLE[newfd].pipe_id, FD_TABLE[newfd].pipe_write);
                }
            }
            FD_TABLE[newfd].active = false;
        }
        if oldfd <= 2 && (!FD_TABLE[oldfd].active || FD_TABLE[oldfd].is_console) {
            // Duping a console fd (stdin/stdout/stderr not redirected)
            FD_TABLE[newfd] = OpenFile {
                ino: 0, offset: 0, flags: 0, active: true, is_console: true,
                is_pipe: false, pipe_id: 0, pipe_write: false,
            };
        } else {
            FD_TABLE[newfd] = FD_TABLE[oldfd];
            // Increment pipe ref count for the dup'd fd (skip in vfork child)
            if FD_TABLE[newfd].is_pipe && !in_vfork {
                if let Some(p) = pipes {
                    (p.dup_ref)(FD_TABLE[newfd].pipe_id, FD_TABLE[newfd].pipe_write);
                }
            }
        }
    }
    newfd as isize
}

/// Close a file descriptor. Returns 0 on success.
pub fn sys_close(fd: usize, in_vfork: bool, pipes: Option<&PipeFns>) -> isize {
    if fd < FIRST_FILE_FD || fd >= MAX_FDS {
        return -9; // -EBADF
    }
    unsafe {
        if !FD_TABLE[fd].active {
            return -9;
        }
        if FD_TABLE[fd].is_pipe && !in_vfork {
            if let Some(p) = pipes {
                (p.close)(FD_TABLE[fd].pipe_id, FD_TABLE[fd].pipe_write);
            }
        }
        FD_TABLE[fd].active = false;
    }
    0
}

/// Allocate an fd for a pipe end. Returns fd number.
pub fn alloc_pipe_fd(pipe_id: u8, is_write: bool) -> Result<isize, isize> {
    unsafe {
        for fd in FIRST_FILE_FD..MAX_FDS {
            if !FD_TABLE[fd].active {
                FD_TABLE[fd] = OpenFile {
                    ino: 0, offset: 0, flags: 0, active: true, is_console: false,
                    is_pipe: true, pipe_id, pipe_write: is_write,
                };
                return Ok(fd as isize);
            }
        }
        Err(-24) // -EMFILE
    }
}

/// Read from a file descriptor. Returns bytes read, 0 on EOF, negative on error.
pub fn sys_read_fd<F: FileSystem>(fd: usize, buf: *mut u8, len: usize, fs: &mut F, pipes: &PipeFns) -> isize {
    if fd >= MAX_FDS {
        return -9;
    }
    unsafe {
        if !FD_TABLE[fd].active {
            return -9;
        }
        if FD_TABLE[fd].is_pipe {
            return (pipes.read)(FD_TABLE[fd].pipe_id, buf, len);
        }
        let f = &mut FD_TABLE[fd];

        // Get file size
        let mut stat = core::mem::zeroed::<InodeStat>();
        if fs.stat(f.ino, &mut stat).is_err() {
            return -5; // -EIO
        }
        let size = stat.size as usize;
        if f.offset >= size {
            return 0; // EOF
        }

        let to_read = len.min(size - f.offset);
        let user_buf = core::slice::from_raw_parts_mut(buf, to_read);
        match fs.read(f.ino, f.offset as u64, user_buf) {
            Ok(n) => {
                f.offset += n;
                n as isize
            }
            Err(_) => -5,
        }
    }
}

/// Write to a file descriptor. Returns bytes written, negative on error.
pub fn sys_write_fd<F: FileSystem>(fd: usize, buf: *const u8, len: usize, fs: &mut F, pipes: &PipeFns) -> isize {
    if fd >= MAX_FDS {
        return -9;
    }
    unsafe {
        if !FD_TABLE[fd].active {
            return -9;
        }
        if FD_TABLE[fd].is_pipe {
            return (pipes.write)(FD_TABLE[fd].pipe_id, buf, len);
        }
        let f = &mut FD_TABLE[fd];

        let user_buf = core::slice::from_raw_parts(buf, len);
        match fs.write(f.ino, f.offset as u64, user_buf) {
            Ok(n) => {
                f.offset += n;
                n as isize
            }
            Err(_) => -5,
        }
    }
}

/// Seek on a file descriptor. Returns new offset, negative on error.
pub fn sys_lseek<F: FileSystem>(fd: usize, offset: i64, whence: u32, fs: &F) -> isize {
    if fd < FIRST_FILE_FD || fd >= MAX_FDS {
        return -9; // -EBADF
    }
    unsafe {
        if !FD_TABLE[fd].active {
            return -9;
        }
        let f = &mut FD_TABLE[fd];
        let new_off: i64 = match whence {
            0 => offset, // SEEK_SET
            1 => f.offset as i64 + offset, // SEEK_CUR
            2 => {
                // SEEK_END: need file size
                let mut stat = core::mem::zeroed::<InodeStat>();
                if fs.stat(f.ino, &mut stat).is_err() {
                    return -5;
                }
                stat.size as i64 + offset
            }
            _ => return -22, // -EINVAL
        };
        if new_off < 0 {
            return -22; // -EINVAL
        }
        f.offset = new_off as usize;
        new_off as isize
    }
}

/// Reset the fd table (called on exec to give child a clean slate).
pub fn reset() {
    unsafe {
        for fd in FIRST_FILE_FD..MAX_FDS {
            FD_TABLE[fd].active = false;
        }
    }
}

// ── Pipe creation ───────────────────────────────────────────────────

/// Create a new pipe: allocate ring buffer + two fds.
/// Returns (pipe_id, read_fd, write_fd) or error.
pub fn create_pipe(
    pipes: &PipeFns,
    in_vfork: bool,
) -> Result<(u8, isize, isize), isize> {
    let pipe_id = (pipes.alloc)()?;

    let read_fd = alloc_pipe_fd(pipe_id, false)?;
    let write_fd = match alloc_pipe_fd(pipe_id, true) {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { sys_close(read_fd as usize, in_vfork, Some(pipes)) };
            (pipes.close)(pipe_id, false);
            (pipes.close)(pipe_id, true);
            return Err(e);
        }
    };

    Ok((pipe_id, read_fd, write_fd))
}

/// Check if an fd is a console fd (stdin/stdout/stderr).
pub fn is_console_fd(fd: usize) -> bool {
    unsafe {
        if fd >= MAX_FDS { return false; }
        !FD_TABLE[fd].active || FD_TABLE[fd].is_console
    }
}
