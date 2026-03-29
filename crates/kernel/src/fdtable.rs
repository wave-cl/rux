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
    active: bool,
}

static mut FD_TABLE: [OpenFile; MAX_FDS] = [OpenFile { ino: 0, offset: 0, active: false }; MAX_FDS];

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

/// Open a file by path. Returns fd on success, negative errno on failure.
pub fn sys_open(path: &[u8]) -> i64 {
    unsafe {
        let fs = crate::kstate::fs();

        let ino = match rux_vfs::path::resolve_path(fs, path) {
            Ok(ino) => ino,
            Err(_) => return -2, // -ENOENT
        };

        // Find a free fd slot
        for fd in FIRST_FILE_FD..MAX_FDS {
            if !FD_TABLE[fd].active {
                FD_TABLE[fd] = OpenFile { ino: ino as u64, offset: 0, active: true };
                return fd as i64;
            }
        }
        -24 // -EMFILE (too many open files)
    }
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
        FD_TABLE[fd].active = false;
    }
    0
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
