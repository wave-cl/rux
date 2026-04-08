//! File I/O syscalls (POSIX.1 Section 2).

use rux_arch::ConsoleOps;
use rux_fs::fdtable as fdt;
type Arch = crate::arch::Arch;

const O_CREAT: usize = 0x40;
const O_EXCL: usize = 0x80;
const O_APPEND: usize = 0x400;
#[allow(dead_code)]
const O_NONBLOCK: usize = 0x800;

// O_DIRECTORY and O_NOFOLLOW have different values on x86_64 vs aarch64
#[cfg(target_arch = "x86_64")]
const O_DIRECTORY: usize = 0x10000;
#[cfg(target_arch = "x86_64")]
const O_NOFOLLOW: usize = 0x20000;
#[cfg(target_arch = "aarch64")]
const O_DIRECTORY: usize = 0x4000;
#[cfg(target_arch = "aarch64")]
const O_NOFOLLOW: usize = 0x8000;
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
        if fd >= rux_fs::fdtable::MAX_FDS || !(*fdt::FD_TABLE)[fd].active || !(*fdt::FD_TABLE)[fd].is_pipe {
            return eof_val;
        }
    }
}

pub fn read(fd: usize, buf: usize, len: usize) -> isize {
    // O_WRONLY: reading from write-only fd is EBADF (skip special fds)
    unsafe {
        if let Some(f) = fdt::get_fd(fd) {
            if f.flags & 3 == 1 && !f.is_console && !f.is_pipe && !f.is_socket {
                return crate::errno::EBADF;
            }
        }
    }
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
    if super::memory::is_signalfd(fd) {
        if len < 128 { return crate::errno::EINVAL; }
        return super::memory::signalfd_read(fd, buf);
    }
    if fdt::is_console_fd(fd) {
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
    // O_RDONLY: writing to read-only fd is EBADF (skip special fds)
    unsafe {
        if let Some(f) = fdt::get_fd(fd) {
            if f.flags & 3 == 0 && !f.is_console && !f.is_pipe && !f.is_socket {
                return crate::errno::EBADF;
            }
        }
    }
    // Socket write → sendto
    if super::socket::is_socket(fd) {
        return super::socket::sys_sendto(fd, buf, len, 0, 0, 0);
    }
    if super::memory::is_eventfd(fd) {
        if len < 8 { return crate::errno::EINVAL; }
        if crate::uaccess::validate_user_ptr(buf, 8).is_err() { return crate::errno::EFAULT; }
        return super::memory::eventfd_write(fd, buf);
    }
    if fdt::is_console_fd(fd) {
        let write_len = len.min(65536);
        if crate::uaccess::validate_user_ptr(buf, write_len).is_err() { return crate::errno::EFAULT; }
        unsafe {
            let slice = core::slice::from_raw_parts(buf as *const u8, write_len);
            Arch::write_bytes(slice);
        }
        return write_len as isize;
    }
    unsafe {
        // O_APPEND: seek to end of file before writing
        if fd < rux_fs::fdtable::MAX_FDS && (*fdt::FD_TABLE)[fd].active
            && (*fdt::FD_TABLE)[fd].flags & O_APPEND as u32 != 0
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
        // SIGPIPE: set pending signal (post_syscall delivers it)
        if result == crate::errno::EPIPE {
            super::PROCESS.signal_hot.pending = super::PROCESS.signal_hot.pending.add(13); // SIGPIPE=13
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

/// Create a new file and open it. Shared by open() and openat() O_CREAT paths.
/// Checks W+X on parent directory via VFS layer.
unsafe fn create_and_open(dir_ino: rux_fs::InodeId, fname: rux_fs::FileName<'_>, flags: usize, mode: usize) -> isize {
    use rux_fs::FileSystem;
    let cred = super::current_cred();
    let fs = crate::kstate::fs();
    let umask = super::PROCESS.fs_ctx.umask as u32;
    match fs.checked_create(dir_ino, fname, (mode as u32 & 0o7777 & !umask) | 0o100000, &cred) {
        Ok(ino) => {
            let now = super::current_time_secs();
            let _ = fs.utimes(ino, now, now);
            fdt::sys_open_ino(ino, flags as u32, crate::kstate::fs())
        }
        Err(_) => crate::errno::EACCES,
    }
}

/// open(pathname, flags, mode) — POSIX.1
pub fn open(path_ptr: usize, flags: usize, mode: usize) -> isize {
    unsafe {
        let path = crate::uaccess::read_user_cstr(path_ptr);
        if path.is_empty() { return crate::errno::ENOENT; }

        let o_creat = flags & O_CREAT != 0;

        // O_NOFOLLOW: resolve without following the final symlink
        let resolve_result = if flags & O_NOFOLLOW != 0 {
            let cred = super::current_cred();
            rux_fs::path::resolve_nofollow_checked(
                crate::kstate::fs(), super::PROCESS.fs_ctx.cwd, path, &cred,
            )
        } else {
            super::resolve_with_cwd(path)
        };

        match resolve_result {
            Ok(ino) => {
                // O_EXCL: fail if file exists when creating exclusively
                if o_creat && flags & O_EXCL != 0 {
                    return crate::errno::EEXIST;
                }
                // O_NOFOLLOW: fail if final component is a symlink
                if flags & O_NOFOLLOW != 0 {
                    use rux_fs::FileSystem;
                    let mut st = core::mem::zeroed::<rux_fs::InodeStat>();
                    if crate::kstate::fs().stat(ino, &mut st).is_ok() {
                        if st.mode & rux_fs::S_IFMT == rux_fs::S_IFLNK {
                            return crate::errno::ELOOP;
                        }
                    }
                }
                // O_DIRECTORY: fail if not a directory
                if flags & O_DIRECTORY != 0 {
                    use rux_fs::FileSystem;
                    let mut st = core::mem::zeroed::<rux_fs::InodeStat>();
                    if crate::kstate::fs().stat(ino, &mut st).is_ok() {
                        if st.mode & rux_fs::S_IFMT != rux_fs::S_IFDIR {
                            return crate::errno::ENOTDIR;
                        }
                    }
                }
                // Permission check via VFS layer
                let cred = super::current_cred();
                let o_rdonly = flags & 3 == 0;
                let o_wronly = flags & 3 == 1;
                let o_rdwr = flags & 3 == 2;
                let mut req = 0u32;
                if o_rdonly || o_rdwr { req |= rux_fs::R_OK; }
                if o_wronly || o_rdwr { req |= rux_fs::W_OK; }
                if let Err(_) = crate::kstate::fs().check_access(ino, req, &cred) {
                    return crate::errno::EACCES;
                }
                let fd = fdt::sys_open_ino(ino, flags as u32, crate::kstate::fs());
                // Mark /dev/tty and /dev/console as console fds
                if fd >= 0 {
                    let is_dev_console = path == b"/dev/tty" || path == b"/dev/console"
                        || path == b"/dev/ttyS0" || path == b"/dev/tty0";
                    if is_dev_console {
                        (*fdt::FD_TABLE)[fd as usize].is_console = true;
                        (*fdt::FD_TABLE)[fd as usize].ino = 0; // not a real file inode
                    }
                }
                fd
            }
            Err(_) if o_creat => {
                let (dir_ino, fname) = match super::resolve_parent_fname(path_ptr) {
                    Ok(v) => v, Err(e) => return e,
                };
                create_and_open(dir_ino, fname, flags, mode)
            }
            Err(e) => e,
        }
    }
}

/// openat(dirfd, pathname, flags, mode) — POSIX.1-2008
pub fn openat(dirfd: usize, pathname: usize, flags: usize, mode: usize) -> isize {
    unsafe {
        let path = crate::uaccess::read_user_cstr(pathname);
        let at_fdcwd = (-100isize) as usize;
        if path.first() == Some(&b'/') || dirfd == at_fdcwd {
            return open(pathname, flags, mode);
        }
        if dirfd < rux_fs::fdtable::MAX_FDS {
            if let Some(base_ino) = rux_fs::fdtable::get_fd_inode(dirfd) {
                let fs = crate::kstate::fs();
                let o_creat = flags & O_CREAT != 0;
                match rux_fs::path::resolve_path_at(fs, base_ino, path) {
                    Ok(ino) => return fdt::sys_open_ino(ino, flags as u32, crate::kstate::fs()),
                    Err(_) if o_creat => {
                        let (dir_ino, fname) = match super::resolve_parent_fname_at(dirfd, pathname) {
                            Ok(v) => v, Err(e) => return e,
                        };
                        return create_and_open(dir_ino, fname, flags, mode);
                    }
                    Err(_) => return crate::errno::ENOENT,
                }
            }
        }
        open(pathname, flags, mode)
    }
}

/// close(fd) — POSIX.1
pub fn close(fd: usize) -> isize {
    // Socket close
    if super::socket::is_socket(fd) {
        return super::socket::sys_close_socket(fd);
    }
    // eventfd / timerfd / signalfd close — release slot, then fall through to fd close
    super::memory::eventfd_close(fd);
    super::memory::timerfd_close(fd);
    super::memory::signalfd_close(fd);
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
        let f = match fdt::get_fd(fd) { Some(f) => f, None => return crate::errno::EBADF };
        if f.is_pipe { return crate::errno::ESPIPE; }
        if crate::uaccess::validate_user_ptr(buf, len).is_err() { return crate::errno::EFAULT; }
        let ino = f.ino;
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
        1 => {
            // F_GETFD — return fd flags (FD_CLOEXEC)
            unsafe { fdt::get_fd(fd).map_or(0, |f| f.fd_flags as isize) }
        }
        2 => {
            // F_SETFD — set fd flags (FD_CLOEXEC)
            unsafe { if let Some(f) = fdt::get_fd_mut(fd) { f.fd_flags = arg as u8; } }
            0
        }
        3 => {
            // F_GETFL
            unsafe { fdt::get_fd(fd).map_or(0, |f| f.flags as isize) }
        }
        4 => {
            // F_SETFL — store the flags (O_NONBLOCK, O_APPEND, etc.)
            unsafe { if let Some(f) = fdt::get_fd_mut(fd) { f.flags = arg as u32; } }
            0
        }
        1030 => {
            // F_DUPFD_CLOEXEC — like F_DUPFD but set FD_CLOEXEC on new fd
            let newfd = fdt::sys_dupfd(fd, arg);
            if newfd >= 0 {
                unsafe { if let Some(f) = fdt::get_fd_mut(newfd as usize) { f.fd_flags = fdt::FD_CLOEXEC; } }
            }
            newfd
        }
        _ => 0,
    }
}

/// pwrite64(fd, buf, count, offset) — POSIX.1: write at offset without seeking.
pub fn pwrite64(fd: usize, buf: usize, len: usize, offset: usize) -> isize {
    unsafe {
        use rux_fs::FileSystem;
        let f = match fdt::get_fd(fd) { Some(f) => f, None => return crate::errno::EBADF };
        if f.is_pipe { return crate::errno::ESPIPE; }
        if crate::uaccess::validate_user_ptr(buf, len).is_err() { return crate::errno::EFAULT; }
        let ino = f.ino;
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
        let f = match fdt::get_fd(fd) { Some(f) => f, None => return crate::errno::EBADF };
        let cred = super::current_cred();
        match crate::kstate::fs().checked_truncate(f.ino, length as u64, &cred) {
            Ok(()) => 0,
            Err(_) => crate::errno::EACCES,
        }
    }
}

/// truncate(path, length) — POSIX.1: truncate file by path.
pub fn truncate(path_ptr: usize, length: usize) -> isize {
    unsafe {
        let path = crate::uaccess::read_user_cstr(path_ptr);
        let ino = match super::resolve_with_cwd(path) {
            Ok(ino) => ino,
            Err(e) => return e,
        };
        let cred = super::current_cred();
        match crate::kstate::fs().checked_truncate(ino, length as u64, &cred) {
            Ok(()) => 0,
            Err(_) => crate::errno::EACCES,
        }
    }
}

/// copy_file_range(fd_in, off_in, fd_out, off_out, len, flags) — Linux 4.5+
/// Copies data between two file descriptors in-kernel (no user buffer needed).
pub fn copy_file_range(fd_in: usize, off_in_ptr: usize, fd_out: usize, off_out_ptr: usize, len: usize) -> isize {
    unsafe {
        use rux_fs::FileSystem;
        if fdt::get_fd(fd_in).is_none() || fdt::get_fd(fd_out).is_none() { return crate::errno::EBADF; }
        let ft = &*fdt::FD_TABLE;

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
            if base == 0 || len == 0 { continue; }
            let n = write(fd, base, len);
            if n < 0 { return if total > 0 { total } else { n }; }
            total += n;
            if (n as usize) < len { break; } // short write — stop
        }
        total
    }
}

/// ioctl(fd, request, arg) — POSIX.1 (terminal operations)
pub fn ioctl(fd: usize, request: usize, arg: usize) -> isize {
    let _fd = fd; // backward compat for FIONBIO/FIONREAD sections
    const TCGETS: usize = 0x5401;
    const TIOCGWINSZ: usize = 0x5413;
    const TIOCSPGRP: usize = 0x5410;
    const TIOCGPGRP: usize = 0x540F;
    const TIOCSCTTY: usize = 0x540E;
    const TIOCNOTTY: usize = 0x5422;

    let is_tty = fdt::is_console_fd(fd);

    match request {
        TIOCGWINSZ => {
            if !is_tty { return crate::errno::ENOTTY; }
            if arg != 0 {
                if crate::uaccess::validate_user_ptr(arg, 8).is_err() { return crate::errno::EFAULT; }
                unsafe { *(arg as *mut [u16; 4]) = [24, 80, 0, 0]; }
            }
            0
        }
        TCGETS => {
            if !is_tty { return crate::errno::ENOTTY; }
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
        TIOCSCTTY => {
            // Acquire controlling terminal: set session as owner
            unsafe {
                let idx = crate::task_table::current_task_idx();
                let sid = crate::task_table::TASK_TABLE[idx].sid;
                crate::tty::TTY.session_id = sid;
                crate::tty::TTY.foreground_pgid = crate::task_table::TASK_TABLE[idx].pgid;
            }
            0
        }
        TIOCNOTTY => {
            // Give up controlling terminal
            unsafe { crate::tty::TTY.session_id = 0; }
            0
        }
        0x5421 => {
            // FIONBIO: set non-blocking mode on fd
            if arg != 0 && crate::uaccess::validate_user_ptr(arg, 4).is_ok() {
                let val = unsafe { *(arg as *const i32) };
                unsafe {
                    if let Some(f) = fdt::get_fd_mut(_fd) {
                        if val != 0 {
                            f.flags |= 0o4000; // O_NONBLOCK
                        } else {
                            f.flags &= !0o4000;
                        }
                    }
                }
            }
            0
        }
        0x541B => {
            // FIONREAD: return number of bytes available to read
            if arg != 0 && crate::uaccess::validate_user_ptr(arg, 4).is_ok() {
                unsafe {
                    if _fd < rux_fs::fdtable::MAX_FDS && (*fdt::FD_TABLE)[_fd].is_pipe {
                        let pid = (*fdt::FD_TABLE)[_fd].pipe_id;
                        *(arg as *mut i32) = rux_ipc::pipe::available(pid) as i32;
                    } else {
                        *(arg as *mut i32) = 0; // unknown/console: 0 bytes
                    }
                }
            }
            0
        }
        _ => -25 // -ENOTTY
    }
}

/// sendfile(out_fd, in_fd, offset_ptr, count) — Linux (widely used by busybox cat)
pub fn sendfile(out_fd: usize, in_fd: usize, offset_ptr: usize, count: usize) -> isize {
    // If offset_ptr is non-NULL, use it as the read position (and update it).
    // Otherwise, use the fd's current offset (via normal read).
    unsafe {
        if offset_ptr != 0 {
            if crate::uaccess::validate_user_ptr(offset_ptr, 8).is_err() { return crate::errno::EFAULT; }
            let off: u64 = crate::uaccess::get_user(offset_ptr);
            if let Some(f) = fdt::get_fd_mut(in_fd) { f.offset = off as usize; }
        }
    }
    let buf = [0u8; 4096]; // mutated via raw pointer in read()
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
    // Update offset_ptr with new position
    unsafe {
        if offset_ptr != 0 {
            if let Some(f) = fdt::get_fd(in_fd) {
                crate::uaccess::put_user(offset_ptr, f.offset as u64);
            }
        }
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
