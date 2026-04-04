//! File I/O syscalls (POSIX.1 Section 2).

use rux_arch::ConsoleOps;
use rux_fs::fdtable as fdt;
type Arch = crate::arch::Arch;

const O_CREAT: usize = 0x40;
#[allow(dead_code)]
const O_NONBLOCK: usize = 0x800;
/// read(fd, buf, count) — POSIX.1
/// readv(fd, iov, iovcnt) — scatter read
pub fn readv(fd: usize, iov_ptr: usize, iovcnt: usize) -> isize {
    if iovcnt == 0 { return 0; }
    let cnt = iovcnt.min(16);
    if crate::uaccess::validate_user_ptr(iov_ptr, cnt * 16).is_err() { return crate::errno::EFAULT; }
    unsafe {
        let iov = iov_ptr as *const [usize; 2];
        let mut total: isize = 0;
        for i in 0..cnt {
            let base = (*iov.add(i))[0];
            let len = (*iov.add(i))[1];
            if base == 0 || len == 0 { continue; }
            let n = read(fd, base, len);
            if n < 0 { return if total > 0 { total } else { n }; }
            total += n;
            if (n as usize) < len { break; } // short read
        }
        total
    }
}

/// Blocking pipe I/O loop: retries on EAGAIN, wakes waiters on success.
unsafe fn pipe_io(fd: usize, buf: usize, len: usize, is_write: bool) -> isize {
    let pipe_id = (*fdt::FD_TABLE)[fd].pipe_id;
    loop {
        let r = if is_write {
            rux_ipc::pipe::write_ex(pipe_id, buf as *const u8, len, true)
        } else {
            rux_ipc::pipe::read_ex(pipe_id, buf as *mut u8, len, true)
        };
        if r != crate::errno::EAGAIN {
            if r > 0 { crate::pipe::wake_pipe_waiters(pipe_id); }
            return r;
        }
        let eof_val = if is_write { crate::errno::EPIPE } else { 0 };
        if !can_pipe_block() { return eof_val; }
        pipe_block(pipe_id);
        if fd >= 64 || !(*fdt::FD_TABLE)[fd].active || !(*fdt::FD_TABLE)[fd].is_pipe {
            return eof_val;
        }
    }
}

pub fn read(fd: usize, buf: usize, len: usize) -> isize {
    if super::socket::is_socket(fd) {
        return super::socket::sys_recvfrom(fd, buf, len, 0, 0, 0);
    }
    if super::memory::is_eventfd(fd) {
        if len < 8 { return crate::errno::EINVAL; }
        if crate::uaccess::validate_user_ptr(buf, 8).is_err() { return crate::errno::EFAULT; }
        return super::memory::eventfd_read(fd, buf);
    }
    if super::memory::is_timerfd(fd) {
        if len < 8 { return crate::errno::EINVAL; }
        if crate::uaccess::validate_user_ptr(buf, 8).is_err() { return crate::errno::EFAULT; }
        return super::memory::timerfd_read(fd, buf);
    }
    if fd == 0 && fdt::is_console_fd(0) {
        unsafe {
            let tty = &mut *(&raw mut crate::tty::TTY);
            let ptr = buf as *mut u8;
            return if tty.cooked {
                tty.read_canonical::<Arch>(ptr, len)
            } else {
                tty.read_raw::<Arch>(ptr, len)
            };
        }
    }
    unsafe {
        if fd < rux_fs::fdtable::MAX_FDS && (*fdt::FD_TABLE)[fd].active && (*fdt::FD_TABLE)[fd].is_pipe {
            return pipe_io(fd, buf, len, false);
        }
        fdt::sys_read_fd(fd, buf as *mut u8, len, crate::kstate::fs(), &crate::pipe::PIPE)
    }
}

/// write(fd, buf, count) — POSIX.1
pub fn write(fd: usize, buf: usize, len: usize) -> isize {
    // Socket write → sendto
    if super::socket::is_socket(fd) {
        return super::socket::sys_sendto(fd, buf, len, 0, 0, 0);
    }
    if super::memory::is_eventfd(fd) {
        if len < 8 { return crate::errno::EINVAL; }
        if crate::uaccess::validate_user_ptr(buf, 8).is_err() { return crate::errno::EFAULT; }
        return super::memory::eventfd_write(fd, buf);
    }
    if fd <= 2 && fdt::is_console_fd(fd) {
        let write_len = len.min(65536); // Cap to prevent unbounded spin
        if crate::uaccess::validate_user_ptr(buf, write_len).is_err() { return crate::errno::EFAULT; }
        unsafe {
            let ptr = buf as *const u8;
            for i in 0..write_len { Arch::write_byte(*ptr.add(i)); }
        }
        return write_len as isize;
    }
    unsafe {
        // O_APPEND: seek to end of file before writing
        if fd < rux_fs::fdtable::MAX_FDS && (*fdt::FD_TABLE)[fd].active
            && (*fdt::FD_TABLE)[fd].flags & 0x400 != 0  // O_APPEND = 0x400
            && !(*fdt::FD_TABLE)[fd].is_pipe
            && !(*fdt::FD_TABLE)[fd].is_console
        {
            use rux_fs::FileSystem;
            let ino = (*fdt::FD_TABLE)[fd].ino;
            let mut stat = core::mem::zeroed::<rux_fs::InodeStat>();
            if crate::kstate::fs().stat(ino, &mut stat).is_ok() {
                (*fdt::FD_TABLE)[fd].offset = stat.size as usize;
            }
        }
        let result = if fd < rux_fs::fdtable::MAX_FDS && (*fdt::FD_TABLE)[fd].active && (*fdt::FD_TABLE)[fd].is_pipe {
            pipe_io(fd, buf, len, true)
        } else {
            fdt::sys_write_fd(fd, buf as *const u8, len, crate::kstate::fs(), &crate::pipe::PIPE)
        };
        // SIGPIPE: writing to a pipe with no readers
        if result == crate::errno::EPIPE {
            use rux_proc::signal::*;
            let cold: &rux_proc::signal::SignalCold = crate::task_table::signal_cold_mut(crate::task_table::current_task_idx());
            let action = *cold.get_action(Signal::Pipe);
            if action.handler_type == SignalHandler::Default {
                super::posix::exit(128 + 13);
            }
            return crate::errno::EPIPE;
        }
        // Update mtime on successful file write (skip pipes/console)
        if result > 0 && fd < rux_fs::fdtable::MAX_FDS {
            let f = &(*fdt::FD_TABLE)[fd];
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
        let path = crate::uaccess::read_user_cstr(path_ptr);
        if path.is_empty() { return crate::errno::ENOENT; }

        let o_creat = flags & O_CREAT != 0;

        match super::resolve_with_cwd(path) {
            Ok(ino) => {
                // Permission check
                use rux_fs::FileSystem;
                let fs = crate::kstate::fs();
                let mut stat = core::mem::zeroed::<rux_fs::InodeStat>();
                if fs.stat(ino, &mut stat).is_ok() {
                    let o_rdonly = flags & 3 == 0;
                    let o_wronly = flags & 3 == 1;
                    let o_rdwr = flags & 3 == 2;
                    let mut req = 0u32;
                    if o_rdonly || o_rdwr { req |= crate::perm::R_OK; }
                    if o_wronly || o_rdwr { req |= crate::perm::W_OK; }
                    if !crate::perm::check_access(stat.mode, stat.uid, stat.gid, req) {
                        return crate::errno::EACCES;
                    }
                }
                // sys_open_ino handles O_TRUNC and O_APPEND
                fdt::sys_open_ino(ino, flags as u32, crate::kstate::fs())
            }
            Err(_) if o_creat => {
                use rux_fs::{FileSystem, FileName};
                let (dir_ino, name) = match super::resolve_parent_and_name(path_ptr) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                let fs = crate::kstate::fs();
                let fname = match FileName::new(name) {
                    Ok(f) => f,
                    Err(_) => return crate::errno::EINVAL,
                };
                match fs.create(dir_ino, fname, (mode & 0o7777) as u32 | 0o100000) {
                    Ok(ino) => {
                        let now = super::current_time_secs();
                        let _ = fs.utimes(ino, now, now);
                        fdt::sys_open_ino(ino, flags as u32, crate::kstate::fs())
                    }
                    Err(_) => crate::errno::EACCES,
                }
            }
            Err(e) => e,
        }
    }
}

/// openat(dirfd, pathname, flags, mode) — POSIX.1-2008
pub fn openat(dirfd: usize, pathname: usize, flags: usize, mode: usize) -> isize {
    unsafe {
        let path = crate::uaccess::read_user_cstr(pathname);
        // If path is absolute or dirfd is AT_FDCWD (-100), resolve normally
        let at_fdcwd = (-100isize) as usize;
        if path.first() == Some(&b'/') || dirfd == at_fdcwd {
            return open(pathname, flags, mode);
        }
        // Relative path + real dirfd: resolve relative to dirfd's directory inode
        if dirfd < rux_fs::fdtable::MAX_FDS {
            if let Some(dir_ino) = rux_fs::fdtable::get_fd_inode(dirfd) {
                let fs = crate::kstate::fs();
                let o_creat = flags & O_CREAT != 0;
                // Resolve path relative to dir_ino
                match rux_fs::path::resolve_path_at(fs, dir_ino, path) {
                    Ok(ino) => {
                        // sys_open_ino handles O_TRUNC and O_APPEND
                        return fdt::sys_open_ino(ino, flags as u32, crate::kstate::fs());
                    }
                    Err(_) if o_creat => {
                        // Find parent directory and create
                        use rux_fs::{FileSystem, FileName};
                        let parent_ino = if let Some(slash) = path.iter().rposition(|&b| b == b'/') {
                            let dir_part = &path[..slash];
                            match rux_fs::path::resolve_path_at(fs, dir_ino, dir_part) {
                                Ok(p) => p,
                                Err(_) => return crate::errno::ENOENT,
                            }
                        } else {
                            dir_ino
                        };
                        let name = if let Some(slash) = path.iter().rposition(|&b| b == b'/') {
                            &path[slash + 1..]
                        } else {
                            path
                        };
                        let fname = match FileName::new(name) {
                            Ok(f) => f,
                            Err(_) => return crate::errno::EINVAL,
                        };
                        match fs.create(parent_ino, fname, (mode & 0o7777) as u32 | 0o100000) {
                            Ok(ino) => {
                                let now = super::current_time_secs();
                                let _ = fs.utimes(ino, now, now);
                                return fdt::sys_open_ino(ino, flags as u32, crate::kstate::fs());
                            }
                            Err(_) => return crate::errno::EACCES,
                        }
                    }
                    Err(_) => return crate::errno::ENOENT,
                }
            }
        }
        // Fallback: treat as normal open
        open(pathname, flags, mode)
    }
}

/// close(fd) — POSIX.1
pub fn close(fd: usize) -> isize {
    // Socket close
    if super::socket::is_socket(fd) {
        return super::socket::sys_close_socket(fd);
    }
    // eventfd / timerfd close — release slot, then fall through to fd close
    super::memory::eventfd_close(fd);
    super::memory::timerfd_close(fd);
    unsafe {
        // If closing a pipe end, wake any tasks blocked on that pipe so they
        // can see the new EOF / EPIPE condition.
        let pipe_id = if fd < rux_fs::fdtable::MAX_FDS && (*fdt::FD_TABLE)[fd].active && (*fdt::FD_TABLE)[fd].is_pipe {
            Some((*fdt::FD_TABLE)[fd].pipe_id)
        } else {
            None
        };
        let r = fdt::sys_close(fd, Some(&crate::pipe::PIPE));
        if let Some(pid) = pipe_id {
            crate::pipe::wake_pipe_waiters(pid);
        }
        r
    }
}

/// dup(oldfd) — POSIX.1: duplicate fd to lowest available fd.
pub fn dup(oldfd: usize) -> isize {
    fdt::sys_dup(oldfd)
}

/// dup2(oldfd, newfd) — POSIX.1
pub fn dup2(oldfd: usize, newfd: usize) -> isize {
    fdt::sys_dup2(oldfd, newfd, Some(&crate::pipe::PIPE))
}

/// lseek(fd, offset, whence) — POSIX.1
/// offset is i64: file offsets can exceed 4GB even on 32-bit.
pub fn lseek(fd: usize, offset: i64, whence: usize) -> isize {
    unsafe { fdt::sys_lseek(fd, offset, whence as u32, crate::kstate::fs()) }
}

/// pread64(fd, buf, count, offset) — POSIX.1: read at offset without seeking.
pub fn pread64(fd: usize, buf: usize, len: usize, offset: usize) -> isize {
    unsafe {
        use rux_fs::FileSystem;
        if fd >= 64 || !(*fdt::FD_TABLE)[fd].active { return crate::errno::EBADF; }
        if (*fdt::FD_TABLE)[fd].is_pipe { return crate::errno::ESPIPE; }
        if crate::uaccess::validate_user_ptr(buf, len).is_err() { return crate::errno::EFAULT; }
        let ino = (*fdt::FD_TABLE)[fd].ino;
        let user_buf = core::slice::from_raw_parts_mut(buf as *mut u8, len);
        match crate::kstate::fs().read(ino, offset as u64, user_buf) {
            Ok(n) => n as isize,
            Err(_) => crate::errno::EIO,
        }
    }
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
                if fd < rux_fs::fdtable::MAX_FDS && (*fdt::FD_TABLE)[fd].active {
                    (*fdt::FD_TABLE)[fd].flags as isize
                } else {
                    0
                }
            }
        }
        4 => {
            // F_SETFL — store the flags (O_NONBLOCK, O_APPEND, etc.)
            unsafe {
                if fd < rux_fs::fdtable::MAX_FDS && (*fdt::FD_TABLE)[fd].active {
                    (*fdt::FD_TABLE)[fd].flags = arg as u32;
                }
            }
            0
        }
        _ => 0,
    }
}

/// pwrite64(fd, buf, count, offset) — POSIX.1: write at offset without seeking.
pub fn pwrite64(fd: usize, buf: usize, len: usize, offset: usize) -> isize {
    unsafe {
        use rux_fs::FileSystem;
        if fd >= 64 || !(*fdt::FD_TABLE)[fd].active { return crate::errno::EBADF; }
        if (*fdt::FD_TABLE)[fd].is_pipe { return crate::errno::ESPIPE; }
        if crate::uaccess::validate_user_ptr(buf, len).is_err() { return crate::errno::EFAULT; }
        let ino = (*fdt::FD_TABLE)[fd].ino;
        let user_buf = core::slice::from_raw_parts(buf as *const u8, len);
        let fs = crate::kstate::fs();
        match fs.write(ino, offset as u64, user_buf) {
            Ok(n) => n as isize,
            Err(_) => crate::errno::EIO,
        }
    }
}

/// ftruncate(fd, length) — POSIX.1: truncate file to specified length.
pub fn ftruncate(fd: usize, length: usize) -> isize {
    unsafe {
        use rux_fs::FileSystem;
        if fd >= 64 || !(*fdt::FD_TABLE)[fd].active { return crate::errno::EBADF; }
        let ino = (*fdt::FD_TABLE)[fd].ino;
        let fs = crate::kstate::fs();
        match fs.truncate(ino, length as u64) {
            Ok(()) => 0,
            Err(_) => crate::errno::EIO,
        }
    }
}

/// truncate(path, length) — POSIX.1: truncate file by path.
pub fn truncate(path_ptr: usize, length: usize) -> isize {
    unsafe {
        use rux_fs::FileSystem;
        let path = crate::uaccess::read_user_cstr(path_ptr);
        let ino = match super::resolve_with_cwd(path) {
            Ok(ino) => ino,
            Err(e) => return e,
        };
        let fs = crate::kstate::fs();
        match fs.truncate(ino, length as u64) {
            Ok(()) => 0,
            Err(_) => crate::errno::EIO,
        }
    }
}

/// copy_file_range(fd_in, off_in, fd_out, off_out, len, flags) — Linux 4.5+
/// Copies data between two file descriptors in-kernel (no user buffer needed).
pub fn copy_file_range(fd_in: usize, off_in_ptr: usize, fd_out: usize, off_out_ptr: usize, len: usize) -> isize {
    unsafe {
        use rux_fs::FileSystem;
        if fd_in >= 64 || fd_out >= 64 { return crate::errno::EBADF; }
        let ft = &*fdt::FD_TABLE;
        if !ft[fd_in].active || !ft[fd_out].active { return crate::errno::EBADF; }

        let fs = crate::kstate::fs();
        let ino_in = ft[fd_in].ino;
        let ino_out = ft[fd_out].ino;

        // Read source offset (from pointer or fd position)
        let src_off = if off_in_ptr != 0 && crate::uaccess::validate_user_ptr(off_in_ptr, 8).is_ok() {
            crate::uaccess::get_user::<u64>(off_in_ptr)
        } else {
            ft[fd_in].offset as u64
        };
        let dst_off = if off_out_ptr != 0 && crate::uaccess::validate_user_ptr(off_out_ptr, 8).is_ok() {
            crate::uaccess::get_user::<u64>(off_out_ptr)
        } else {
            ft[fd_out].offset as u64
        };

        // Copy in chunks using a kernel buffer
        let mut buf = [0u8; 4096];
        let mut copied: usize = 0;
        let mut s_off = src_off;
        let mut d_off = dst_off;

        while copied < len {
            let chunk = (len - copied).min(4096);
            let n = match fs.read(ino_in, s_off, &mut buf[..chunk]) {
                Ok(n) if n > 0 => n,
                _ => break,
            };
            match fs.write(ino_out, d_off, &buf[..n]) {
                Ok(w) => {
                    s_off += w as u64;
                    d_off += w as u64;
                    copied += w;
                }
                Err(_) => break,
            }
        }

        // Update offset pointers
        if off_in_ptr != 0 { crate::uaccess::put_user(off_in_ptr, s_off); }
        else { (*rux_fs::fdtable::FD_TABLE)[fd_in].offset = s_off as usize; }
        if off_out_ptr != 0 { crate::uaccess::put_user(off_out_ptr, d_off); }
        else { (*rux_fs::fdtable::FD_TABLE)[fd_out].offset = d_off as usize; }

        if copied == 0 && len > 0 { return crate::errno::EIO; }
        copied as isize
    }
}

/// writev(fd, iov, iovcnt) — POSIX.1
pub fn writev(fd: usize, iov_ptr: usize, iovcnt: usize) -> isize {
    let cnt = iovcnt.min(16);
    if crate::uaccess::validate_user_ptr(iov_ptr, cnt * 16).is_err() { return crate::errno::EFAULT; }
    unsafe {
        let iov = iov_ptr as *const [usize; 2];
        let mut total: isize = 0;
        for i in 0..cnt {
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
            if arg != 0 {
                if crate::uaccess::validate_user_ptr(arg, 8).is_err() { return crate::errno::EFAULT; }
                unsafe { *(arg as *mut [u16; 4]) = [24, 80, 0, 0]; }
            }
            0
        }
        TCGETS => {
            if arg != 0 {
                if crate::uaccess::validate_user_ptr(arg, 60).is_err() { return crate::errno::EFAULT; }
                unsafe {
                    let tty = &*(&raw const crate::tty::TTY);
                    let ptr = arg as *mut u8;
                    for i in 0..60 { *ptr.add(i) = 0; }
                    *(arg as *mut u32) = 0x500; // c_iflag: ICRNL | IXON
                    *((arg + 4) as *mut u32) = 0x5; // c_oflag: OPOST | ONLCR
                    *((arg + 8) as *mut u32) = 0xBF; // c_cflag
                    // c_lflag: build from actual TTY state
                    let mut lflag: u32 = 0;
                    if tty.cooked { lflag |= 0x2; }   // ICANON
                    if tty.echo   { lflag |= 0x8; }   // ECHO
                    if tty.isig   { lflag |= 0x1; }   // ISIG
                    lflag |= 0x8A30; // ECHOE | ECHOK | IEXTEN | ECHOCTL
                    *((arg + 12) as *mut u32) = lflag;
                    // c_cc control characters (offset 17 on Linux/musl)
                    let cc = (arg + 17) as *mut u8;
                    *cc.add(0) = 0x03;  // VINTR = Ctrl-C
                    *cc.add(1) = 0x1C;  // VQUIT = Ctrl-\
                    *cc.add(2) = 0x7F;  // VERASE = DEL
                    *cc.add(3) = 0x15;  // VKILL = Ctrl-U
                    *cc.add(4) = 0x04;  // VEOF = Ctrl-D
                    *cc.add(5) = 0x00;  // VTIME
                    *cc.add(6) = 0x01;  // VMIN
                    *cc.add(10) = 0x1A; // VSUSP = Ctrl-Z
                }
            }
            0
        }
        // TCSETS / TCSETSW / TCSETSF: set terminal attributes
        0x5402 | 0x5403 | 0x5404 => {
            if arg != 0 {
                if crate::uaccess::validate_user_ptr(arg, 60).is_err() { return crate::errno::EFAULT; }
                unsafe {
                    let tty = &mut *(&raw mut crate::tty::TTY);
                    let lflag = *((arg + 12) as *const u32);
                    tty.cooked = lflag & 0x2 != 0; // ICANON
                    tty.echo   = lflag & 0x8 != 0; // ECHO
                    tty.isig   = lflag & 0x1 != 0; // ISIG
                    // c_cc: VTIME at offset 5, VMIN at offset 6
                    let cc = (arg + 17) as *const u8;
                    tty.vtime = *cc.add(5);
                    tty.vmin  = *cc.add(6);
                }
            }
            0
        }
        TIOCGPGRP => {
            if arg != 0 {
                if crate::uaccess::validate_user_ptr(arg, 4).is_err() { return crate::errno::EFAULT; }
                unsafe { *(arg as *mut i32) = crate::tty::TTY.foreground_pgid as i32; }
            }
            0
        }
        TIOCSPGRP => {
            if arg != 0 {
                if crate::uaccess::validate_user_ptr(arg, 4).is_err() { return crate::errno::EFAULT; }
                unsafe { crate::tty::TTY.foreground_pgid = *(arg as *const i32) as u32; }
            }
            0
        }
        _ => -25 // -ENOTTY
    }
}

/// sendfile(out_fd, in_fd, offset, count) — Linux (widely used by busybox cat)
pub fn sendfile(out_fd: usize, in_fd: usize, _offset_ptr: usize, count: usize) -> isize {
    // Use the high-level read/write which handle special devices (console,
    // /dev/zero, /dev/urandom, pipes, sockets) — not the low-level sys_read_fd.
    let mut buf = [0u8; 4096];
    let mut total: isize = 0;
    let mut remaining = count;

    while remaining > 0 {
        let chunk = remaining.min(4096);
        let n = read(in_fd, buf.as_ptr() as usize, chunk);
        if n <= 0 { break; }
        let written = write(out_fd, buf.as_ptr() as usize, n as usize);
        if written < 0 { return if total > 0 { total } else { written }; }
        total += written;
        remaining = remaining.saturating_sub(n as usize);
    }
    total
}

/// Check if the current process can safely block on a pipe.
/// Returns false if no other runnable tasks exist that could wake us.
unsafe fn can_pipe_block() -> bool {
    use crate::task_table::*;
    (0..MAX_PROCS).any(|i| {
        i != current_task_idx() && TASK_TABLE[i].active
            && TASK_TABLE[i].state != TaskState::Zombie
    })
}

/// Block the current task until a pipe has activity.
unsafe fn pipe_block(pipe_id: u8) {
    use crate::task_table::*;
    let idx = current_task_idx();
    rux_ipc::pipe::register_waiter(pipe_id, idx as u8);
    TASK_TABLE[idx].state = TaskState::WaitingForPipe;
    TASK_TABLE[idx].waiting_pipe_id = pipe_id;
    let sched = crate::scheduler::get();
    sched.tasks[idx].entity.state = rux_sched::TaskState::Interruptible;
    sched.dequeue_current();
    sched.schedule();
}
