//! File I/O syscalls (POSIX.1 Section 2).

use rux_arch::ConsoleOps;
use rux_fs::fdtable as fdt;
type Arch = crate::arch::Arch;
/// Check if fd 0-2 should use console (not redirected to file/pipe).
pub(crate) fn is_console_fd(fd: usize) -> bool {
    fdt::is_console_fd(fd)
}

/// read(fd, buf, count) — POSIX.1
pub fn read(fd: usize, buf: usize, len: usize) -> isize {
    if fd == 0 && is_console_fd(0) {
        // stdin from console
        unsafe {
            let ptr = buf as *mut u8;
            for i in 0..len {
                let b = Arch::read_byte();
                if b == 0x03 {
                    if i == 0 { return -4; } // -EINTR
                    return i as isize;
                }
                *ptr.add(i) = b;
                if b == b'\n' {
                    return (i + 1) as isize;
                }
            }
        }
        return len as isize;
    }
    unsafe { fdt::sys_read_fd(fd, buf as *mut u8, len, crate::kstate::fs(), &crate::pipe::PIPE) }
}

/// write(fd, buf, count) — POSIX.1
pub fn write(fd: usize, buf: usize, len: usize) -> isize {
    if fd <= 2 && is_console_fd(fd) {
        unsafe {
            let ptr = buf as *const u8;
            for i in 0..len { Arch::write_byte(*ptr.add(i)); }
        }
        return len as isize;
    }
    unsafe {
        let result = fdt::sys_write_fd(fd, buf as *const u8, len, crate::kstate::fs(), &crate::pipe::PIPE);
        // Update mtime on successful file write (skip pipes/console)
        if result > 0 && fd < 64 {
            let f = &fdt::FD_TABLE[fd];
            if f.active && !f.is_console && !f.is_pipe {
                use rux_fs::FileSystem;
                let now = super::current_time_secs();
                let _ = crate::kstate::fs().utimes(f.ino, now, now);
            }
        }
        result
    }
}

/// open(pathname, flags, mode) — POSIX.1
pub fn open(path_ptr: usize, flags: usize, mode: usize) -> isize {
    unsafe {
        let path = super::read_user_path(path_ptr);
        if path.is_empty() { return -2; }

        let o_creat = flags & 0x40 != 0;

        match super::resolve_with_cwd(path) {
            Ok(ino) => fdt::sys_open_ino(ino, flags as u32, crate::kstate::fs()),
            Err(_) if o_creat => {
                use rux_fs::{FileSystem, FileName};
                let (dir_ino, name) = match super::resolve_parent_and_name(path_ptr) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                let fs = crate::kstate::fs();
                let fname = match FileName::new(name) {
                    Ok(f) => f,
                    Err(_) => return -22,
                };
                match fs.create(dir_ino, fname, (mode & 0o7777) as u32 | 0o100000) {
                    Ok(ino) => {
                        let now = super::current_time_secs();
                        let _ = fs.utimes(ino, now, now);
                        fdt::sys_open_ino(ino, flags as u32, crate::kstate::fs())
                    }
                    Err(_) => -13,
                }
            }
            Err(e) => e,
        }
    }
}

/// openat(dirfd, pathname, flags, mode) — POSIX.1-2008
pub fn openat(_dirfd: usize, pathname: usize, flags: usize, mode: usize) -> isize {
    open(pathname, flags, mode)
}

/// close(fd) — POSIX.1
pub fn close(fd: usize) -> isize {
    unsafe { fdt::sys_close(fd, crate::syscall::PROCESS.in_vfork_child, Some(&crate::pipe::PIPE)) }
}

/// dup(oldfd) — POSIX.1: duplicate fd to lowest available fd.
pub fn dup(oldfd: usize) -> isize {
    fdt::sys_dup(oldfd)
}

/// dup2(oldfd, newfd) — POSIX.1
pub fn dup2(oldfd: usize, newfd: usize) -> isize {
    unsafe { fdt::sys_dup2(oldfd, newfd, crate::syscall::PROCESS.in_vfork_child, Some(&crate::pipe::PIPE)) }
}

/// lseek(fd, offset, whence) — POSIX.1
/// offset is i64: file offsets can exceed 4GB even on 32-bit.
pub fn lseek(fd: usize, offset: i64, whence: usize) -> isize {
    unsafe { fdt::sys_lseek(fd, offset, whence as u32, crate::kstate::fs()) }
}

/// fcntl(fd, cmd, arg) — POSIX.1
pub fn fcntl(fd: usize, cmd: usize, arg: usize) -> isize {
    match cmd {
        0 => fdt::sys_dupfd(fd, arg), // F_DUPFD
        1 => 0,  // F_GETFD
        2 => 0,  // F_SETFD
        3 => {
            // F_GETFL
            unsafe {
                if fd < 64 && fdt::FD_TABLE[fd].active {
                    fdt::FD_TABLE[fd].flags as isize
                } else {
                    0
                }
            }
        }
        4 => 0,  // F_SETFL
        _ => 0,
    }
}

/// writev(fd, iov, iovcnt) — POSIX.1
pub fn writev(fd: usize, iov_ptr: usize, iovcnt: usize) -> isize {
    unsafe {
        // iovec: { iov_base: *mut u8, iov_len: usize } — two usize fields
        let iov = iov_ptr as *const [usize; 2];
        let mut total: isize = 0;
        for i in 0..iovcnt {
            let base = (*iov.add(i))[0];
            let len = (*iov.add(i))[1];
            let n = write(fd, base, len);
            if n < 0 { return n; }
            total += n;
        }
        total
    }
}

/// ioctl(fd, request, arg) — POSIX.1 (terminal operations)
pub fn ioctl(_fd: usize, request: usize, arg: usize) -> isize {
    const TCGETS: usize = 0x5401;
    const TIOCGWINSZ: usize = 0x5413;
    const TIOCSPGRP: usize = 0x5410;
    const TIOCGPGRP: usize = 0x540F;

    match request {
        TIOCGWINSZ => {
            if arg != 0 { unsafe { *(arg as *mut [u16; 4]) = [24, 80, 0, 0]; } }
            0
        }
        TCGETS => {
            if arg != 0 {
                unsafe {
                    let ptr = arg as *mut u8;
                    for i in 0..60 { *ptr.add(i) = 0; }
                    *(arg as *mut u32) = 0x500;
                    *((arg + 4) as *mut u32) = 0x5;
                    *((arg + 8) as *mut u32) = 0xBF;
                    *((arg + 12) as *mut u32) = 0x8A3B;
                }
            }
            0
        }
        TIOCGPGRP => {
            if arg != 0 { unsafe { *(arg as *mut i32) = 1; } }
            0
        }
        TIOCSPGRP | 0x5402 | 0x5403 | 0x5404 => 0,
        _ => -25 // -ENOTTY
    }
}

/// sendfile(out_fd, in_fd, offset, count) — Linux (widely used by busybox cat)
pub fn sendfile(out_fd: usize, in_fd: usize, _offset_ptr: usize, count: usize) -> isize {
    unsafe {
        let mut buf = [0u8; 4096];
        let mut total: isize = 0;
        let mut remaining = count;

        while remaining > 0 {
            let chunk = remaining.min(4096);
            let n = fdt::sys_read_fd(in_fd, buf.as_mut_ptr(), chunk, crate::kstate::fs(), &crate::pipe::PIPE);
            if n <= 0 { break; }
            let written = write(out_fd, buf.as_ptr() as usize, n as usize);
            if written < 0 { return if total > 0 { total } else { written }; }
            total += written;
            remaining -= n as usize;
        }
        total
    }
}
