/// POSIX.1-2008 standardized syscall implementations.
///
/// All arguments use native-width types (usize/isize) instead of u64
/// so this code works correctly on both 32-bit and 64-bit architectures.
/// File offsets use i64 since they can exceed 4GB even on 32-bit (lseek64).

use rux_arch::SerialOps;
use rux_arch::TimerOps;
use rux_vfs::fdtable as fdt;
type Arch = crate::arch::Arch;

// ── File I/O (POSIX.1 Section 2) ────────────────────────────────────

/// Check if fd 0-2 should use serial (not redirected to file/pipe).
fn is_serial_fd(fd: usize) -> bool {
    fdt::is_serial_fd(fd)
}

/// read(fd, buf, count) — POSIX.1
pub fn read(fd: usize, buf: usize, len: usize) -> isize {
    if fd == 0 && is_serial_fd(0) {
        // stdin from serial
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
    if fd <= 2 && is_serial_fd(fd) {
        unsafe {
            let ptr = buf as *const u8;
            for i in 0..len { Arch::write_byte(*ptr.add(i)); }
        }
        return len as isize;
    }
    unsafe { fdt::sys_write_fd(fd, buf as *const u8, len, crate::kstate::fs(), &crate::pipe::PIPE) }
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
                    Ok(ino) => fdt::sys_open_ino(ino, flags as u32, crate::kstate::fs()),
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
    unsafe { fdt::sys_close(fd, crate::syscall::IN_VFORK_CHILD, Some(&crate::pipe::PIPE)) }
}

/// dup(oldfd) — POSIX.1: duplicate fd to lowest available fd.
pub fn dup(oldfd: usize) -> isize {
    fdt::sys_dup(oldfd)
}

/// dup2(oldfd, newfd) — POSIX.1
pub fn dup2(oldfd: usize, newfd: usize) -> isize {
    unsafe { fdt::sys_dup2(oldfd, newfd, crate::syscall::IN_VFORK_CHILD, Some(&crate::pipe::PIPE)) }
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

// ── File metadata (POSIX.1 Section 2) ───────────────────────────────

/// stat(pathname, statbuf) — POSIX.1
pub fn stat(pathname: usize, buf: usize) -> isize {
    fstatat(0xffffff9c, pathname, buf)
}

/// fstat(fd, statbuf) — POSIX.1
use crate::arch::StatLayout;
const STAT_MODE_OFF: usize = <crate::arch::Arch as StatLayout>::MODE_OFF;
const STAT_BLKSIZE_OFF: usize = <crate::arch::Arch as StatLayout>::BLKSIZE_OFF;

pub fn fstat(fd: usize, buf: usize) -> isize {
    if buf == 0 { return -14; }
    if fd <= 2 && is_serial_fd(fd) {
        unsafe {
            let p = buf as *mut u8;
            for i in 0..144 { *p.add(i) = 0; }
            *((buf + STAT_MODE_OFF) as *mut u32) = 0o20666;
            *((buf + STAT_BLKSIZE_OFF) as *mut u32) = 4096;
        }
        return 0;
    }
    if fd <= 2 {
        unsafe {
            let f = &fdt::FD_TABLE[fd];
            if f.is_pipe {
                let p = buf as *mut u8;
                for i in 0..144 { *p.add(i) = 0; }
                *((buf + STAT_MODE_OFF) as *mut u32) = 0o10666;
                *((buf + STAT_BLKSIZE_OFF) as *mut u32) = 4096;
                return 0;
            }
        }
    }
    unsafe {
        use rux_vfs::FileSystem;
        let f = &fdt::FD_TABLE[fd];
        if !f.active { return -9; }
        let fs = crate::kstate::fs();
        let mut vfs_stat = core::mem::zeroed::<rux_vfs::InodeStat>();
        if fs.stat(f.ino, &mut vfs_stat).is_err() {
            let p = buf as *mut u8;
            for i in 0..144 { *p.add(i) = 0; }
            *((buf + STAT_MODE_OFF) as *mut u32) = 0o100644;
            *((buf + STAT_BLKSIZE_OFF) as *mut u32) = 4096;
            return 0;
        }
        super::fill_linux_stat(buf, &vfs_stat);
    }
    0
}

/// fstatat(dirfd, pathname, statbuf, flags) — POSIX.1-2008
pub fn fstatat(_dirfd: usize, pathname: usize, buf: usize) -> isize {
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
pub fn chdir(path_ptr: usize) -> isize {
    unsafe {
        use rux_vfs::FileSystem;
        let path = super::read_user_path(path_ptr);
        if path.is_empty() { return -2; }

        let fs = crate::kstate::fs();
        let ino = match super::resolve_with_cwd(path) {
            Ok(ino) => ino,
            Err(e) => return e,
        };

        let mut stat = core::mem::zeroed::<rux_vfs::InodeStat>();
        if fs.stat(ino, &mut stat).is_err() { return -2; }
        if stat.mode & rux_vfs::S_IFMT != rux_vfs::S_IFDIR {
            return -20; // -ENOTDIR
        }

        super::CWD_INODE = ino;

        if path[0] == b'/' {
            let len = path.len().min(255);
            super::CWD_PATH[..len].copy_from_slice(&path[..len]);
            super::CWD_PATH[len] = 0;
            super::CWD_PATH_LEN = len;
        } else {
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
pub fn mkdir(path_ptr: usize) -> isize {
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
pub fn unlink(path_ptr: usize) -> isize {
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
pub fn creat(path_ptr: usize) -> isize {
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
                fdt::sys_open(core::slice::from_raw_parts(cstr, len), crate::kstate::fs())
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
    Arch::write_str(rux_klib::fmt::u32_to_str(&mut buf, status as u32));
    Arch::write_str(")\n");

    unsafe { super::LAST_CHILD_EXIT = status; }

    unsafe {
        use rux_arch::VforkContext;
        if crate::arch::Arch::jmp_active() {
            crate::arch::Arch::longjmp(42);
        }
    }
    use rux_arch::ExitOps;
    crate::arch::Arch::exit(crate::arch::Arch::EXIT_SUCCESS);
}

/// waitpid(pid, wstatus, options) — POSIX.1
pub fn waitpid(_pid: usize, wstatus_ptr: usize, _options: usize) -> isize {
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
pub fn getcwd(buf: usize, size: usize) -> isize {
    unsafe {
        let len = super::CWD_PATH_LEN;
        if buf == 0 || size < len + 1 { return -34; } // -ERANGE
        let ptr = buf as *mut u8;
        for i in 0..len {
            *ptr.add(i) = super::CWD_PATH[i];
        }
        *ptr.add(len) = 0;
    }
    buf as isize
}

/// uname(buf) — POSIX.1
pub fn uname(buf: usize) -> isize {
    if buf == 0 { return -14; }
    unsafe {
        let ptr = buf as *mut u8;
        for i in 0..325 { *ptr.add(i) = 0; }
        // sysname
        for (i, &b) in b"rux".iter().enumerate() { *ptr.add(i) = b; }
        // nodename (offset 65) — read from /etc/hostname
        {
            use rux_vfs::FileSystem;
            let mut name = [0u8; 64];
            let mut len = 3usize;
            name[0] = b'r'; name[1] = b'u'; name[2] = b'x';
            let fs = crate::kstate::fs();
            if let Ok(ino) = rux_vfs::path::resolve_path(fs, b"/etc/hostname") {
                if let Ok(n) = fs.read(ino, 0, &mut name) {
                    len = n;
                    while len > 0 && (name[len - 1] == b'\n' || name[len - 1] == b'\r') {
                        len -= 1;
                    }
                }
            }
            for i in 0..len { *ptr.add(65 + i) = name[i]; }
        }
        // release (offset 130)
        for (i, &b) in b"0.1.0".iter().enumerate() { *ptr.add(130 + i) = b; }
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
pub fn sigaction(_signum: usize, _act: usize, _oldact: usize) -> isize { 0 }

/// sigprocmask(how, set, oldset, sigsetsize) — POSIX.1
pub fn sigprocmask(_how: usize, _set: usize, oldset: usize, sigsetsize: usize) -> isize {
    if oldset != 0 && sigsetsize > 0 && sigsetsize <= 8 {
        unsafe { *(oldset as *mut u64) = 0; }
    }
    0
}

// ── Terminal control (POSIX.1 termios) ──────────────────────────────

/// ioctl(fd, request, arg) — POSIX.1 (for terminal operations)
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

// ── Time (POSIX.1) ──────────────────────────────────────────────────

/// clock_gettime(clockid, timespec) — POSIX.1-2008
pub fn clock_gettime(_clockid: usize, tp: usize) -> isize {
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
pub fn mmap(addr: usize, len: usize, _prot: usize, mmap_flags: usize, _fd: usize) -> isize {
    unsafe {
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

        result as isize
    }
}
