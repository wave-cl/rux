/// Minimal per-process file descriptor table.
///
/// Architecture-independent. Since rux runs one user process at a time
/// (vfork semantics), a single global table suffices.
///
/// Kernel-specific dependencies (VFS, pipes, vfork flag) are injected
/// via parameters and the `PipeOps` trait.

use crate::{FileSystem, InodeStat};

pub const MAX_FDS: usize = 256;
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

/// FD_CLOEXEC — close this fd on exec.
pub const FD_CLOEXEC: u8 = 1;

#[derive(Clone, Copy)]
pub struct OpenFile {
    pub ino: u64,
    pub offset: usize,
    pub flags: u32,       // O_* file status flags (O_APPEND, O_NONBLOCK, etc.)
    pub fd_flags: u8,     // FD flags (FD_CLOEXEC) — separate from file status flags
    pub active: bool,
    pub is_console: bool,
    pub is_pipe: bool,
    pub pipe_id: u8,
    pub pipe_write: bool,
    pub is_socket: bool,
    pub socket_idx: u8,
}

pub const EMPTY_FD: OpenFile = OpenFile {
    ino: 0, offset: 0, flags: 0, fd_flags: 0, active: false, is_console: false,
    is_pipe: false, pipe_id: 0, pipe_write: false,
    is_socket: false, socket_idx: 0,
};

/// Boot-time storage used before init_pid1 points FD_TABLE at a task slot.
static mut FD_TABLE_STORAGE: [OpenFile; MAX_FDS] = [EMPTY_FD; MAX_FDS];

/// Pointer to the current task's FD array. On context switch, this is
/// reassigned to the new task's `fds` field — no copy needed.
/// Before init_pid1, points to FD_TABLE_STORAGE.
pub static mut FD_TABLE: *mut [OpenFile; MAX_FDS] = core::ptr::null_mut();

/// Point FD_TABLE at a task's FD array. Called on context switch and init.
///
/// # Safety
/// `fds` must be a valid pointer to a `[OpenFile; MAX_FDS]` that outlives
/// all accesses through FD_TABLE (i.e., a TaskSlot.fds field).
#[inline(always)]
pub unsafe fn set_active_fds(fds: *mut [OpenFile; MAX_FDS]) {
    FD_TABLE = fds;
}

/// Point FD_TABLE at boot-time storage (used before task table exists).
pub unsafe fn init_boot_fds() {
    FD_TABLE = &raw mut FD_TABLE_STORAGE as *mut [OpenFile; MAX_FDS];
}

/// Get the inode for a file descriptor (for getdents to read directory).
pub fn get_fd_inode(fd: usize) -> Option<u64> {
    unsafe {
        if fd < MAX_FDS && (*FD_TABLE)[fd].active {
            Some((*FD_TABLE)[fd].ino)
        } else {
            None
        }
    }
}

/// Get a reference to an open file descriptor, or None if invalid/inactive.
#[inline(always)]
pub unsafe fn get_fd(fd: usize) -> Option<&'static OpenFile> {
    if fd < MAX_FDS && (*FD_TABLE)[fd].active { Some(&(*FD_TABLE)[fd]) } else { None }
}

/// Get a mutable reference to an open file descriptor, or None if invalid/inactive.
#[inline(always)]
pub unsafe fn get_fd_mut(fd: usize) -> Option<&'static mut OpenFile> {
    if fd < MAX_FDS && (*FD_TABLE)[fd].active { Some(&mut (*FD_TABLE)[fd]) } else { None }
}

/// Open a file by inode with flags. Returns fd on success, negative errno on failure.
pub fn sys_open_ino<F: FileSystem>(ino: crate::InodeId, flags: u32, fs: &mut F) -> isize {
    unsafe {
        for fd in FIRST_FILE_FD..MAX_FDS {
            if !(*FD_TABLE)[fd].active {
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
                let fd_flags = if flags & 0o2000000 != 0 { FD_CLOEXEC } else { 0 }; // O_CLOEXEC
                (*FD_TABLE)[fd] = OpenFile {
                    ino: ino as u64, offset, flags, fd_flags, active: true, is_console: false,
                    is_pipe: false, pipe_id: 0, pipe_write: false,
                    is_socket: false, socket_idx: 0,
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
        if oldfd > 2 && !(*FD_TABLE)[oldfd].active { return -9; }
        for newfd in FIRST_FILE_FD..MAX_FDS {
            if !(*FD_TABLE)[newfd].active {
                return sys_dup2_inner(oldfd, newfd, None);
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
        if oldfd > 2 && !(*FD_TABLE)[oldfd].active { return -9; }
        let start = minfd.max(FIRST_FILE_FD);
        for newfd in start..MAX_FDS {
            if !(*FD_TABLE)[newfd].active {
                return sys_dup2_inner(oldfd, newfd, None);
            }
        }
        -24 // -EMFILE
    }
}

/// Duplicate a file descriptor. Real dup2 implementation.
pub fn sys_dup2(oldfd: usize, newfd: usize, pipes: Option<&PipeFns>) -> isize {
    sys_dup2_inner(oldfd, newfd, pipes)
}

fn sys_dup2_inner(oldfd: usize, newfd: usize, pipes: Option<&PipeFns>) -> isize {
    if oldfd >= MAX_FDS || newfd >= MAX_FDS { return -9; }
    unsafe {
        if oldfd > 2 && !(*FD_TABLE)[oldfd].active { return -9; }
        // POSIX: if oldfd == newfd, return newfd without closing/reopening
        if oldfd == newfd { return newfd as isize; }
        // Close newfd if it's currently open (including pipe cleanup)
        if (*FD_TABLE)[newfd].active {
            if (*FD_TABLE)[newfd].is_pipe {
                if let Some(p) = pipes {
                    (p.close)((*FD_TABLE)[newfd].pipe_id, (*FD_TABLE)[newfd].pipe_write);
                }
            }
            (*FD_TABLE)[newfd].active = false;
        }
        if oldfd <= 2 && (!(*FD_TABLE)[oldfd].active || (*FD_TABLE)[oldfd].is_console) {
            // Duping a console fd (stdin/stdout/stderr not redirected)
            (*FD_TABLE)[newfd] = OpenFile {
                ino: 0, offset: 0, flags: 0, fd_flags: 0, active: true, is_console: true,
                is_pipe: false, pipe_id: 0, pipe_write: false,
                is_socket: false, socket_idx: 0,
            };
        } else {
            (*FD_TABLE)[newfd] = (*FD_TABLE)[oldfd];
            // POSIX: dup2 clears FD_CLOEXEC on the new fd
            (*FD_TABLE)[newfd].fd_flags = 0;
            // Increment pipe ref count for the dup'd fd (skip in vfork child)
            if (*FD_TABLE)[newfd].is_pipe {
                if let Some(p) = pipes {
                    (p.dup_ref)((*FD_TABLE)[newfd].pipe_id, (*FD_TABLE)[newfd].pipe_write);
                }
            }
        }
    }
    newfd as isize
}

/// Close a file descriptor. Returns 0 on success.
pub fn sys_close(fd: usize, pipes: Option<&PipeFns>) -> isize {
    unsafe {
        let f = match get_fd(fd) {
            Some(f) => f,
            None => {
                // Console fds 0-2: closing an already-closed console fd is harmless.
                // Programs like git call close(1) then fclose(stdout) which closes again.
                if fd <= 2 { return 0; }
                return -9;
            }
        };
        if f.is_pipe {
            if let Some(p) = pipes {
                (p.close)(f.pipe_id, f.pipe_write);
            }
        }
        (*FD_TABLE)[fd].active = false;
    }
    0
}

/// Allocate an fd for a pipe end. Returns fd number.
pub fn alloc_pipe_fd(pipe_id: u8, is_write: bool) -> Result<isize, isize> {
    unsafe {
        for fd in FIRST_FILE_FD..MAX_FDS {
            if !(*FD_TABLE)[fd].active {
                (*FD_TABLE)[fd] = OpenFile {
                    ino: 0, offset: 0, flags: 0, fd_flags: 0, active: true, is_console: false,
                    is_pipe: true, pipe_id, pipe_write: is_write,
                    is_socket: false, socket_idx: 0,
                };
                return Ok(fd as isize);
            }
        }
        Err(-24) // -EMFILE
    }
}

/// Read from a file descriptor. Returns bytes read, 0 on EOF, negative on error.
pub fn sys_read_fd<F: FileSystem>(fd: usize, buf: *mut u8, len: usize, fs: &mut F, pipes: &PipeFns) -> isize {
    unsafe {
        let f = match get_fd_mut(fd) {
            Some(f) => f,
            None => return -9,
        };
        if f.is_pipe {
            return (pipes.read)(f.pipe_id, buf, len);
        }
        if buf.is_null() || len == 0 || len > 0x7FFF_FFFF || (buf as usize).wrapping_add(len) < (buf as usize) {
            return if len == 0 { 0 } else { -14 }; // -EFAULT
        }

        // Get file size
        let mut stat = core::mem::zeroed::<InodeStat>();
        if fs.stat(f.ino, &mut stat).is_err() {
            return -5; // -EIO
        }
        let is_char_dev = stat.mode & 0xF000 == 0x2000; // S_IFCHR
        let size = stat.size as usize;
        if !is_char_dev && f.offset >= size {
            return 0; // EOF (skip for character devices — they generate data)
        }

        let to_read = if is_char_dev { len } else { len.min(size - f.offset) };
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
    unsafe {
        let f = match get_fd_mut(fd) {
            Some(f) => f,
            None => return -9,
        };
        if f.is_pipe {
            return (pipes.write)(f.pipe_id, buf, len);
        }
        // Validate user buffer pointer
        if buf.is_null() || len == 0 || len > 0x7FFF_FFFF || (buf as usize).wrapping_add(len) < (buf as usize) {
            return if len == 0 { 0 } else { -14 }; // -EFAULT
        }

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
    if fd < FIRST_FILE_FD { return -29; } // ESPIPE: console/pipe fds are not seekable
    unsafe {
        let f = match get_fd_mut(fd) {
            Some(f) => f,
            None => return -9,
        };
        if f.is_pipe { return -29; } // ESPIPE: pipes are not seekable
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

/// Close FD_CLOEXEC fds on exec. Non-cloexec fds are inherited.
/// Linux closes only fds with FD_CLOEXEC set; others pass to the new program.
/// Must properly close pipe ends (decrement reader/writer count) so that
/// EOF is delivered to blocked readers when all writers are gone.
/// Returns list of pipe_ids that were closed (caller should wake waiters).
pub fn reset_with_pipes(pipes: Option<&PipeFns>) -> [u8; 16] {
    let mut closed_pipes = [0xFFu8; 16];
    let mut cp_count = 0;
    unsafe {
        for fd in FIRST_FILE_FD..MAX_FDS {
            if (*FD_TABLE)[fd].active && (*FD_TABLE)[fd].fd_flags & FD_CLOEXEC != 0 {
                if (*FD_TABLE)[fd].is_pipe {
                    let pid = (*FD_TABLE)[fd].pipe_id;
                    if let Some(p) = pipes {
                        (p.close)(pid, (*FD_TABLE)[fd].pipe_write);
                    }
                    if cp_count < 16 { closed_pipes[cp_count] = pid; cp_count += 1; }
                }
                (*FD_TABLE)[fd].active = false;
            }
        }
    }
    closed_pipes
}

/// Legacy reset (no pipe cleanup). Used by kernel boot path.
pub fn reset() {
    reset_with_pipes(None);
}

// ── Pipe creation ───────────────────────────────────────────────────

/// Create a new pipe: allocate ring buffer + two fds.
/// Returns (pipe_id, read_fd, write_fd) or error.
pub fn create_pipe(
    pipes: &PipeFns,
) -> Result<(u8, isize, isize), isize> {
    let pipe_id = (pipes.alloc)()?;

    let read_fd = alloc_pipe_fd(pipe_id, false)?;
    let write_fd = match alloc_pipe_fd(pipe_id, true) {
        Ok(fd) => fd,
        Err(e) => {
            sys_close(read_fd as usize, Some(pipes));
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
        !(*FD_TABLE)[fd].active || (*FD_TABLE)[fd].is_console
    }
}
