/// Minimal per-process file descriptor table.
/// Since rux runs one user process at a time (vfork semantics),
/// a single global table suffices.

use rux_vfs::{FileSystem, InodeStat, VfsError};

const MAX_FDS: usize = 64;
const FD_STDIN: usize = 0;
const FD_STDOUT: usize = 1;
const FD_STDERR: usize = 2;
const FIRST_FILE_FD: usize = 3;

#[derive(Clone, Copy)]
pub struct OpenFile {
    pub ino: u64,
    pub offset: usize,
    pub flags: u32,
    pub active: bool,
    pub is_pipe: bool,
    pub pipe_id: u8,
    pub pipe_write: bool,
}

const EMPTY_FD: OpenFile = OpenFile {
    ino: 0, offset: 0, flags: 0, active: false,
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
pub fn sys_open(path: &[u8]) -> i64 {
    unsafe {
        let fs = crate::kstate::fs();
        let ino = match rux_vfs::path::resolve_path(fs, path) {
            Ok(ino) => ino,
            Err(_) => return -2,
        };
        sys_open_ino(ino, 0)
    }
}

/// Open a file by inode with flags. Returns fd on success, negative errno on failure.
pub fn sys_open_ino(ino: rux_vfs::InodeId, flags: u32) -> i64 {
    unsafe {
        for fd in FIRST_FILE_FD..MAX_FDS {
            if !FD_TABLE[fd].active {
                let mut offset = 0usize;
                // O_APPEND: start at end of file
                if flags & 0x400 != 0 {
                    let fs = crate::kstate::fs();
                    let mut stat = core::mem::zeroed::<InodeStat>();
                    if fs.stat(ino, &mut stat).is_ok() {
                        offset = stat.size as usize;
                    }
                }
                // O_TRUNC: truncate file to 0
                if flags & 0x200 != 0 {
                    let fs = crate::kstate::fs();
                    let _ = fs.truncate(ino, 0);
                }
                FD_TABLE[fd] = OpenFile {
                    ino: ino as u64, offset, flags, active: true,
                    is_pipe: false, pipe_id: 0, pipe_write: false,
                };
                return fd as i64;
            }
        }
        -24 // -EMFILE
    }
}

/// Duplicate a file descriptor to the lowest available fd (>= 3).
pub fn sys_dup(oldfd: usize) -> i64 {
    if oldfd >= MAX_FDS { return -9; }
    unsafe {
        // For fd 0-2, allow even if not "active" in table
        if oldfd > 2 && !FD_TABLE[oldfd].active { return -9; }
        for newfd in FIRST_FILE_FD..MAX_FDS {
            if !FD_TABLE[newfd].active {
                return sys_dup2(oldfd, newfd);
            }
        }
        -24 // -EMFILE
    }
}

/// Duplicate a file descriptor. Real dup2 implementation.
pub fn sys_dup2(oldfd: usize, newfd: usize) -> i64 {
    if oldfd >= MAX_FDS || newfd >= MAX_FDS { return -9; }
    unsafe {
        // For stdin/stdout/stderr (0-2), allow dup2 even if not "active" in table
        if oldfd > 2 && !FD_TABLE[oldfd].active { return -9; }
        // Close newfd if it's currently open
        if newfd >= FIRST_FILE_FD && FD_TABLE[newfd].active {
            FD_TABLE[newfd].active = false;
        }
        if oldfd <= 2 {
            // Duping stdin/stdout/stderr — create a "serial" fd entry
            FD_TABLE[newfd] = OpenFile {
                ino: 0, offset: 0, flags: 0, active: true,
                is_pipe: false, pipe_id: 0, pipe_write: false,
            };
            // Mark as serial fd (ino=0 + flags bit to distinguish)
            FD_TABLE[newfd].ino = oldfd as u64; // store original fd for serial routing
        } else {
            FD_TABLE[newfd] = FD_TABLE[oldfd];
        }
    }
    newfd as i64
}

/// Close a file descriptor. Returns 0 on success.
pub fn sys_close(fd: usize) -> i64 {
    if fd < FIRST_FILE_FD || fd >= MAX_FDS {
        return -9; // -EBADF
    }
    unsafe {
        if !FD_TABLE[fd].active {
            return -9;
        }
        if FD_TABLE[fd].is_pipe {
            crate::pipe::close(FD_TABLE[fd].pipe_id, FD_TABLE[fd].pipe_write);
        }
        FD_TABLE[fd].active = false;
    }
    0
}

/// Allocate an fd for a pipe end. Returns fd number.
pub fn alloc_pipe_fd(pipe_id: u8, is_write: bool) -> Result<i64, i64> {
    unsafe {
        for fd in FIRST_FILE_FD..MAX_FDS {
            if !FD_TABLE[fd].active {
                FD_TABLE[fd] = OpenFile {
                    ino: 0, offset: 0, flags: 0, active: true,
                    is_pipe: true, pipe_id, pipe_write: is_write,
                };
                return Ok(fd as i64);
            }
        }
        Err(-24) // -EMFILE
    }
}

/// Read from a file descriptor. Returns bytes read, 0 on EOF, negative on error.
pub fn sys_read_fd(fd: usize, buf: *mut u8, len: usize) -> i64 {
    if fd >= MAX_FDS {
        return -9;
    }
    unsafe {
        if !FD_TABLE[fd].active {
            return -9;
        }
        if FD_TABLE[fd].is_pipe {
            return crate::pipe::read(FD_TABLE[fd].pipe_id, buf, len);
        }
        let f = &mut FD_TABLE[fd];
        let fs = crate::kstate::fs();

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
                n as i64
            }
            Err(_) => -5,
        }
    }
}

/// Write to a file descriptor. Returns bytes written, negative on error.
pub fn sys_write_fd(fd: usize, buf: *const u8, len: usize) -> i64 {
    if fd >= MAX_FDS {
        return -9;
    }
    unsafe {
        if !FD_TABLE[fd].active {
            return -9;
        }
        if FD_TABLE[fd].is_pipe {
            return crate::pipe::write(FD_TABLE[fd].pipe_id, buf, len);
        }
        let f = &mut FD_TABLE[fd];
        let fs = crate::kstate::fs();

        let user_buf = core::slice::from_raw_parts(buf, len);
        match fs.write(f.ino, f.offset as u64, user_buf) {
            Ok(n) => {
                f.offset += n;
                n as i64
            }
            Err(_) => -5,
        }
    }
}

/// Seek on a file descriptor. Returns new offset, negative on error.
pub fn sys_lseek(fd: usize, offset: i64, whence: u32) -> i64 {
    if fd < FIRST_FILE_FD || fd >= MAX_FDS {
        return -9; // -EBADF
    }
    unsafe {
        if !FD_TABLE[fd].active {
            return -9;
        }
        let f = &mut FD_TABLE[fd];
        let new_off = match whence {
            0 => offset, // SEEK_SET
            1 => f.offset as i64 + offset, // SEEK_CUR
            2 => {
                // SEEK_END: need file size
                let fs = crate::kstate::fs();
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
        new_off
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
