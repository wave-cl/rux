/// POSIX.1-2008 standardized syscall implementations.
///
/// These syscalls are defined by the POSIX standard and are portable
/// across Unix-like operating systems. They form the core system
/// interface that any POSIX-compliant OS must provide.

use super::arch;

// ── File I/O (POSIX.1 Section 2) ────────────────────────────────────

/// read(fd, buf, count) — POSIX.1
pub fn read(fd: u64, buf: u64, len: u64) -> i64 {
    if fd == 0 {
        unsafe {
            if crate::fdtable::FD_TABLE[0].active {
                return crate::fdtable::sys_read_fd(0, buf as *mut u8, len as usize);
            }
            let ptr = buf as *mut u8;
            for i in 0..len as usize {
                *ptr.add(i) = arch::serial_read_byte();
            }
        }
        return len as i64;
    }
    crate::fdtable::sys_read_fd(fd as usize, buf as *mut u8, len as usize)
}

/// write(fd, buf, count) — POSIX.1
pub fn write(fd: u64, buf: u64, len: u64) -> i64 {
    // Check if fd 0-2 has been redirected (dup2'd to a file/pipe)
    if fd <= 2 {
        unsafe {
            if crate::fdtable::FD_TABLE[fd as usize].active {
                return crate::fdtable::sys_write_fd(fd as usize, buf as *const u8, len as usize);
            }
            let ptr = buf as *const u8;
            for i in 0..len as usize { arch::serial_write_byte(*ptr.add(i)); }
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

// ── File metadata (POSIX.1 Section 2) ───────────────────────────────

/// stat(pathname, statbuf) — POSIX.1
/// (Delegates to fstatat with AT_FDCWD)
pub fn stat(pathname: u64, buf: u64) -> i64 {
    fstatat(0xffffff9cu64, pathname, buf)
}

/// fstat(fd, statbuf) — POSIX.1
/// Offset of st_mode within struct stat (differs per arch).
#[cfg(target_arch = "x86_64")]
const STAT_MODE_OFF: usize = 24;
#[cfg(target_arch = "aarch64")]
const STAT_MODE_OFF: usize = 16;

/// Offset of st_blksize within struct stat.
#[cfg(target_arch = "x86_64")]
const STAT_BLKSIZE_OFF: usize = 56;
#[cfg(target_arch = "aarch64")]
const STAT_BLKSIZE_OFF: usize = 56;

pub fn fstat(fd: u64, buf: u64) -> i64 {
    if buf == 0 { return -14; }
    if fd <= 2 {
        unsafe {
            let p = buf as *mut u8;
            for i in 0..144 { *p.add(i) = 0; }
            *((buf + STAT_MODE_OFF as u64) as *mut u32) = 0o20666; // S_IFCHR | 0666
            *((buf + STAT_BLKSIZE_OFF as u64) as *mut u32) = 4096;
        }
        return 0;
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
    arch::serial_write_str("rux: user exit(");
    let mut buf = [0u8; 10];
    arch::serial_write_str(crate::write_u32(&mut buf, status as u32));
    arch::serial_write_str(")\n");

    unsafe { super::LAST_CHILD_EXIT = status; }

    #[cfg(target_arch = "x86_64")]
    unsafe {
        if crate::x86_64::syscall::vfork_jmp_active() {
            crate::x86_64::syscall::vfork_longjmp_to_parent(42);
        }
        crate::x86_64::exit::exit_qemu(crate::x86_64::exit::EXIT_SUCCESS);
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        if crate::aarch64::syscall::vfork_jmp_active() {
            crate::aarch64::syscall::vfork_longjmp_to_parent(42);
        }
        crate::aarch64::exit::exit_qemu(crate::aarch64::exit::EXIT_SUCCESS);
    }
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
        #[cfg(target_arch = "x86_64")]
        for (i, &b) in b"x86_64".iter().enumerate() { *ptr.add(260 + i) = b; }
        #[cfg(target_arch = "aarch64")]
        for (i, &b) in b"aarch64".iter().enumerate() { *ptr.add(260 + i) = b; }
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
    let ticks = arch::ticks();
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

        let alloc = crate::kstate::alloc();
        let cr3 = arch::page_table_root();
        let pg_flags = rux_mm::MappingFlags::READ
            .or(rux_mm::MappingFlags::WRITE)
            .or(rux_mm::MappingFlags::USER);

        #[cfg(target_arch = "x86_64")]
        {
            let mut upt = crate::x86_64::paging::PageTable4Level::from_cr3(
                rux_klib::PhysAddr::new(cr3 as usize));
            for offset in (0..aligned_len).step_by(4096) {
                let frame = alloc.alloc(rux_mm::PageSize::FourK).expect("mmap page");
                let ptr = frame.as_usize() as *mut u8;
                for j in 0..4096 { core::ptr::write_volatile(ptr.add(j), 0); }
                let va = rux_klib::VirtAddr::new((result + offset) as usize);
                let _ = upt.unmap_4k(va);
                let _ = upt.map_4k(va, frame, pg_flags, alloc);
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            let mut upt = crate::aarch64::paging::PageTable4Level::from_cr3(
                rux_klib::PhysAddr::new(cr3 as usize));
            for offset in (0..aligned_len).step_by(4096) {
                let frame = alloc.alloc(rux_mm::PageSize::FourK).expect("mmap page");
                let ptr = frame.as_usize() as *mut u8;
                for j in 0..4096 { core::ptr::write_volatile(ptr.add(j), 0); }
                let va = rux_klib::VirtAddr::new((result + offset) as usize);
                let _ = upt.unmap_4k(va);
                let _ = upt.map_4k(va, frame, pg_flags, alloc);
            }
        }

        result as i64
    }
}
