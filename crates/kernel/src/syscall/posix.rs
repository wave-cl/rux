/// POSIX.1-2008 standardized syscall implementations.
///
/// These syscalls are defined by the POSIX standard and are portable
/// across Unix-like operating systems. They form the core system
/// interface that any POSIX-compliant OS must provide.

use rux_arch::SerialOps;
use rux_arch::TimerOps;
type Arch = crate::arch::Arch;

// ── File I/O (POSIX.1 Section 2) ────────────────────────────────────

/// Check if fd 0-2 should use serial (not redirected to file/pipe).
fn is_serial_fd(fd: u64) -> bool {
    crate::fdtable::is_serial_fd(fd)
}

/// read(fd, buf, count) — POSIX.1
pub fn read(fd: u64, buf: u64, len: u64) -> i64 {
    if fd == 0 && is_serial_fd(0) {
        // stdin from serial
        unsafe {
            let ptr = buf as *mut u8;
            for i in 0..len as usize {
                let b = Arch::read_byte();
                if b == 0x03 {
                    // Ctrl+C: return -EINTR if we haven't read anything,
                    // or return what we have so far
                    if i == 0 {
                        return -4; // -EINTR
                    }
                    return i as i64;
                }
                *ptr.add(i) = b;
                // Return after newline (line-buffered input)
                if b == b'\n' {
                    return (i + 1) as i64;
                }
            }
        }
        return len as i64;
    }
    crate::fdtable::sys_read_fd(fd as usize, buf as *mut u8, len as usize)
}

/// write(fd, buf, count) — POSIX.1
pub fn write(fd: u64, buf: u64, len: u64) -> i64 {
    if fd <= 2 && is_serial_fd(fd) {
        // stdout/stderr to serial
        unsafe {
            let ptr = buf as *const u8;
            for i in 0..len as usize { Arch::write_byte(*ptr.add(i)); }
        }
        return len as i64;
    }
    crate::fdtable::sys_write_fd(fd as usize, buf as *const u8, len as usize)
}

/// open(pathname, flags, mode) — POSIX.1
pub fn open(path_ptr: u64, flags: u64, mode: u64) -> i64 {
    unsafe {
        let path = super::read_user_path(path_ptr);
        if path.is_empty() { return -2; }

        let o_creat = flags & 0x40 != 0;

        match super::resolve_with_cwd(path) {
            Ok(ino) => crate::fdtable::sys_open_ino(ino, flags as u32),
            Err(_) if o_creat => {
                use rux_vfs::{FileSystem, FileName};
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
                    Ok(ino) => crate::fdtable::sys_open_ino(ino, flags as u32),
                    Err(_) => -13,
                }
            }
            Err(e) => e,
        }
    }
}

/// openat(dirfd, pathname, flags, mode) — POSIX.1-2008
pub fn openat(_dirfd: u64, pathname: u64, flags: u64, mode: u64) -> i64 {
    open(pathname, flags, mode)
}

/// close(fd) — POSIX.1
pub fn close(fd: u64) -> i64 {
    crate::fdtable::sys_close(fd as usize)
}

/// dup(oldfd) — POSIX.1: duplicate fd to lowest available fd.
pub fn dup(oldfd: u64) -> i64 {
    crate::fdtable::sys_dup(oldfd as usize)
}

/// dup2(oldfd, newfd) — POSIX.1
pub fn dup2(oldfd: u64, newfd: u64) -> i64 {
    crate::fdtable::sys_dup2(oldfd as usize, newfd as usize)
}

/// lseek(fd, offset, whence) — POSIX.1
pub fn lseek(fd: u64, offset: i64, whence: u64) -> i64 {
    crate::fdtable::sys_lseek(fd as usize, offset, whence as u32)
}

/// fcntl(fd, cmd, arg) — POSIX.1
pub fn fcntl(fd: u64, cmd: u64, arg: u64) -> i64 {
    match cmd {
        0 => {
            // F_DUPFD: dup to lowest fd >= arg
            crate::fdtable::sys_dupfd(fd as usize, arg as usize)
        }
        1 => 0,  // F_GETFD: return 0 (no FD_CLOEXEC)
        2 => 0,  // F_SETFD: ignore
        3 => {
            // F_GETFL: return stored flags
            unsafe {
                if (fd as usize) < 64 && crate::fdtable::FD_TABLE[fd as usize].active {
                    crate::fdtable::FD_TABLE[fd as usize].flags as i64
                } else {
                    0
                }
            }
        }
        4 => 0,  // F_SETFL: ignore
        _ => 0,
    }
}

/// writev(fd, iov, iovcnt) — POSIX.1
pub fn writev(fd: u64, iov_ptr: u64, iovcnt: u64) -> i64 {
    unsafe {
        let iov = iov_ptr as *const [u64; 2];
        let mut total: i64 = 0;
        for i in 0..iovcnt as usize {
            let base = (*iov.add(i))[0];
            let len = (*iov.add(i))[1];
            let n = write(fd, base, len);
            if n < 0 { return n; }
            total += n;
        }
        total
    }
}

/// sendfile(out_fd, in_fd, offset, count) — Linux (widely used by busybox cat)
pub fn sendfile(out_fd: u64, in_fd: u64, offset_ptr: u64, count: u64) -> i64 {
    // Read from in_fd, write to out_fd, up to count bytes.
    // If offset_ptr is non-null, use that offset instead of fd's current offset.
    unsafe {
        let mut buf = [0u8; 4096];
        let mut total = 0i64;
        let mut remaining = count as usize;

        while remaining > 0 {
            let chunk = remaining.min(4096);
            let n = crate::fdtable::sys_read_fd(in_fd as usize, buf.as_mut_ptr(), chunk);
            if n <= 0 { break; } // EOF or error
            let written = write(out_fd, buf.as_ptr() as u64, n as u64);
            if written < 0 { return if total > 0 { total } else { written }; }
            total += written;
            remaining -= n as usize;
        }
        total
    }
}

// ── File metadata (POSIX.1 Section 2) ───────────────────────────────

/// stat(pathname, statbuf) — POSIX.1
/// (Delegates to fstatat with AT_FDCWD)
pub fn stat(pathname: u64, buf: u64) -> i64 {
    fstatat(0xffffff9cu64, pathname, buf)
}

/// fstat(fd, statbuf) — POSIX.1
use crate::arch::StatLayout;
const STAT_MODE_OFF: usize = <crate::arch::Arch as StatLayout>::MODE_OFF;
const STAT_BLKSIZE_OFF: usize = <crate::arch::Arch as StatLayout>::BLKSIZE_OFF;

pub fn fstat(fd: u64, buf: u64) -> i64 {
    if buf == 0 { return -14; }
    if fd <= 2 && is_serial_fd(fd) {
        // Default serial (not redirected to file/pipe)
        unsafe {
            let p = buf as *mut u8;
            for i in 0..144 { *p.add(i) = 0; }
            *((buf + STAT_MODE_OFF as u64) as *mut u32) = 0o20666; // S_IFCHR | 0666
            *((buf + STAT_BLKSIZE_OFF as u64) as *mut u32) = 4096;
        }
        return 0;
    }
    if fd <= 2 {
        // fd 0-2 redirected to pipe — return FIFO stat
        unsafe {
            let f = &crate::fdtable::FD_TABLE[fd as usize];
            if f.is_pipe {
                let p = buf as *mut u8;
                for i in 0..144 { *p.add(i) = 0; }
                *((buf + STAT_MODE_OFF as u64) as *mut u32) = 0o10666; // S_IFIFO | 0666
                *((buf + STAT_BLKSIZE_OFF as u64) as *mut u32) = 4096;
                return 0;
            }
        }
    }
    // Look up real inode stat from VFS
    unsafe {
        use rux_vfs::FileSystem;
        let f = &crate::fdtable::FD_TABLE[fd as usize];
        if !f.active { return -9; }
        let fs = crate::kstate::fs();
        let mut vfs_stat = core::mem::zeroed::<rux_vfs::InodeStat>();
        if fs.stat(f.ino, &mut vfs_stat).is_err() {
            // Fallback to generic file stat
            let p = buf as *mut u8;
            for i in 0..144 { *p.add(i) = 0; }
            *((buf + STAT_MODE_OFF as u64) as *mut u32) = 0o100644;
            *((buf + STAT_BLKSIZE_OFF as u64) as *mut u32) = 4096;
            return 0;
        }
        super::fill_linux_stat(buf, &vfs_stat);
    }
    0
}

/// fstatat(dirfd, pathname, statbuf, flags) — POSIX.1-2008
pub fn fstatat(_dirfd: u64, pathname: u64, buf: u64) -> i64 {
    if buf == 0 { return -14; }
    unsafe {
        use rux_vfs::FileSystem;
        let path = super::read_user_path(pathname);
        let fs = crate::kstate::fs();
        let ino = match super::resolve_with_cwd(path) {
            Ok(ino) => ino,
            Err(e) => return e,
        };
        let mut vfs_stat = core::mem::zeroed::<rux_vfs::InodeStat>();
        if fs.stat(ino, &mut vfs_stat).is_err() { return -2; }
        super::fill_linux_stat(buf, &vfs_stat);
        0
    }
}

// ── Directory operations (POSIX.1) ──────────────────────────────────

/// chdir(path) — POSIX.1
pub fn chdir(path_ptr: u64) -> i64 {
    unsafe {
        use rux_vfs::FileSystem;
        let path = super::read_user_path(path_ptr);
        if path.is_empty() { return -2; }

        let fs = crate::kstate::fs();
        let ino = match super::resolve_with_cwd(path) {
            Ok(ino) => ino,
            Err(e) => return e,
        };

        // Verify it's a directory
        let mut stat = core::mem::zeroed::<rux_vfs::InodeStat>();
        if fs.stat(ino, &mut stat).is_err() { return -2; }
        if stat.mode & rux_vfs::S_IFMT != rux_vfs::S_IFDIR {
            return -20; // -ENOTDIR
        }

        super::CWD_INODE = ino;

        // Update CWD_PATH: build absolute path
        if path[0] == b'/' {
            // Absolute: just copy it
            let len = path.len().min(255);
            super::CWD_PATH[..len].copy_from_slice(&path[..len]);
            super::CWD_PATH[len] = 0;
            super::CWD_PATH_LEN = len;
        } else {
            // Relative: append to current CWD
            let cur_len = super::CWD_PATH_LEN;
            let need_slash = cur_len > 0 && super::CWD_PATH[cur_len - 1] != b'/';
            let mut pos = cur_len;
            if need_slash && pos < 255 { super::CWD_PATH[pos] = b'/'; pos += 1; }
            for &b in path {
                if pos >= 255 { break; }
                super::CWD_PATH[pos] = b;
                pos += 1;
            }
            super::CWD_PATH[pos] = 0;
            super::CWD_PATH_LEN = pos;
        }
        0
    }
}

/// mkdir(pathname, mode) — POSIX.1
pub fn mkdir(path_ptr: u64) -> i64 {
    unsafe {
        use rux_vfs::{FileSystem, FileName};
        let (dir_ino, name) = match super::resolve_parent_and_name(path_ptr) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let fs = crate::kstate::fs();
        let fname = match FileName::new(name) {
            Ok(f) => f,
            Err(_) => return -22,
        };
        match fs.mkdir(dir_ino, fname, 0o755) {
            Ok(_) => 0,
            Err(_) => -17,
        }
    }
}

/// unlink(pathname) — POSIX.1
pub fn unlink(path_ptr: u64) -> i64 {
    unsafe {
        use rux_vfs::{FileSystem, FileName};
        let (dir_ino, name) = match super::resolve_parent_and_name(path_ptr) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let fs = crate::kstate::fs();
        let fname = match FileName::new(name) {
            Ok(f) => f,
            Err(_) => return -22,
        };
        match fs.unlink(dir_ino, fname) {
            Ok(()) => 0,
            Err(_) => -2,
        }
    }
}

/// creat(pathname, mode) — POSIX.1 (equivalent to open with O_CREAT|O_WRONLY|O_TRUNC)
pub fn creat(path_ptr: u64) -> i64 {
    unsafe {
        use rux_vfs::{FileSystem, FileName};
        let (dir_ino, name) = match super::resolve_parent_and_name(path_ptr) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let fs = crate::kstate::fs();
        let fname = match FileName::new(name) {
            Ok(f) => f,
            Err(_) => return -22,
        };
        match fs.create(dir_ino, fname, 0o644) {
            Ok(_ino) => {
                let cstr = path_ptr as *const u8;
                let mut len = 0usize;
                while *cstr.add(len) != 0 && len < 256 { len += 1; }
                crate::fdtable::sys_open(core::slice::from_raw_parts(cstr, len))
            }
            Err(_) => -17,
        }
    }
}

// ── Process control (POSIX.1) ───────────────────────────────────────

/// _exit(status) — POSIX.1
pub fn exit(status: i32) -> ! {
    Arch::write_str("rux: user exit(");
    let mut buf = [0u8; 10];
    Arch::write_str(crate::write_u32(&mut buf, status as u32));
    Arch::write_str(")\n");

    unsafe { super::LAST_CHILD_EXIT = status; }

    unsafe {
        use rux_arch::VforkOps;
        if crate::arch::Arch::vfork_jmp_active() {
            crate::arch::Arch::vfork_longjmp_to_parent(42);
        }
    }
    use rux_arch::ExitOps;
    crate::arch::Arch::exit(crate::arch::Arch::EXIT_SUCCESS);
}

/// waitpid(pid, wstatus, options) — POSIX.1
/// (Also handles Linux wait4 with rusage=NULL)
pub fn waitpid(_pid: u64, wstatus_ptr: u64, _options: u64) -> i64 {
    unsafe {
        if !super::CHILD_AVAILABLE { return -10; } // -ECHILD
        super::CHILD_AVAILABLE = false;
        if wstatus_ptr != 0 {
            let status = (super::LAST_CHILD_EXIT as u32) << 8;
            *(wstatus_ptr as *mut u32) = status;
        }
        42
    }
}

/// getcwd(buf, size) — POSIX.1
pub fn getcwd(buf: u64, size: u64) -> i64 {
    unsafe {
        let len = super::CWD_PATH_LEN;
        if buf == 0 || size < (len + 1) as u64 { return -34; } // -ERANGE
        let ptr = buf as *mut u8;
        for i in 0..len {
            *ptr.add(i) = super::CWD_PATH[i];
        }
        *ptr.add(len) = 0;
    }
    buf as i64
}

/// uname(buf) — POSIX.1
pub fn uname(buf: u64) -> i64 {
    if buf == 0 { return -14; }
    unsafe {
        let ptr = buf as *mut u8;
        for i in 0..325 { *ptr.add(i) = 0; }
        // sysname
        for (i, &b) in b"Linux".iter().enumerate() { *ptr.add(i) = b; }
        // nodename (offset 65)
        for (i, &b) in b"rux".iter().enumerate() { *ptr.add(65 + i) = b; }
        // release (offset 130)
        for (i, &b) in b"6.1.0-rux".iter().enumerate() { *ptr.add(130 + i) = b; }
        // version (offset 195)
        for (i, &b) in b"#1 SMP".iter().enumerate() { *ptr.add(195 + i) = b; }
        // machine (offset 260)
        {
            use rux_arch::ArchInfo;
            for (i, &b) in crate::arch::Arch::MACHINE_NAME.iter().enumerate() {
                *ptr.add(260 + i) = b;
            }
        }
    }
    0
}

// ── Signals (POSIX.1) ───────────────────────────────────────────────

/// sigaction(signum, act, oldact) — POSIX.1
pub fn sigaction(_signum: u64, _act: u64, _oldact: u64) -> i64 { 0 }

/// sigprocmask(how, set, oldset, sigsetsize) — POSIX.1
pub fn sigprocmask(_how: u64, _set: u64, oldset: u64, sigsetsize: u64) -> i64 {
    if oldset != 0 && sigsetsize > 0 && sigsetsize <= 8 {
        unsafe { *(oldset as *mut u64) = 0; }
    }
    0
}

// ── Terminal control (POSIX.1 termios) ──────────────────────────────

/// ioctl(fd, request, arg) — POSIX.1 (for terminal operations)
pub fn ioctl(_fd: u64, request: u64, arg: u64) -> i64 {
    const TCGETS: u64 = 0x5401;
    const TIOCGWINSZ: u64 = 0x5413;
    const TIOCSPGRP: u64 = 0x5410;
    const TIOCGPGRP: u64 = 0x540F;

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
                    *(arg as *mut u32) = 0x500;          // c_iflag: ICRNL|IXON
                    *((arg + 4) as *mut u32) = 0x5;      // c_oflag: OPOST|ONLCR
                    *((arg + 8) as *mut u32) = 0xBF;     // c_cflag
                    *((arg + 12) as *mut u32) = 0x8A3B;  // c_lflag: ISIG|ICANON|ECHO|...
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

// ── Time (POSIX.1) ──────────────────────────────────────────────────

/// clock_gettime(clockid, timespec) — POSIX.1-2008
pub fn clock_gettime(_clockid: u64, tp: u64) -> i64 {
    if tp == 0 { return -14; }
    let ticks = Arch::ticks();
    unsafe {
        *(tp as *mut u64) = ticks / 1000;
        *((tp + 8) as *mut u64) = (ticks % 1000) * 1_000_000;
    }
    0
}

// ── Memory mapping (POSIX.1) ────────────────────────────────────────

/// mmap(addr, length, prot, flags, fd, offset) — POSIX.1
pub fn mmap(addr: u64, len: u64, _prot: u64, mmap_flags: u64, _fd: u64) -> i64 {
    unsafe {
        use rux_mm::FrameAllocator;

        if mmap_flags & 0x20 == 0 { return -12; } // MAP_ANONYMOUS only

        let aligned_len = (len + 0xFFF) & !0xFFF;
        let result = if mmap_flags & 0x10 != 0 && addr != 0 {
            addr & !0xFFF // MAP_FIXED
        } else {
            let r = super::MMAP_BASE;
            super::MMAP_BASE += aligned_len;
            r
        };

        let pg_flags = rux_mm::MappingFlags::READ
            .or(rux_mm::MappingFlags::WRITE)
            .or(rux_mm::MappingFlags::USER);
        super::map_user_pages(result, result + aligned_len, pg_flags);

        result as i64
    }
}
