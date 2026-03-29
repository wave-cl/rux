/// Shared syscall implementations — architecture-independent.
///
/// These functions implement the logic for Linux syscalls without any
/// inline assembly or architecture-specific code. The arch-specific
/// syscall entry/exit and dispatch tables remain in each arch module.

// ── Arch-specific helpers (zero-cost, cfg-dispatched) ───────────────

pub mod arch {
    /// Write a byte to the serial console.
    #[inline(always)]
    pub fn serial_write_byte(b: u8) {
        #[cfg(target_arch = "x86_64")]
        crate::x86_64::serial::write_byte(b);
        #[cfg(target_arch = "aarch64")]
        crate::aarch64::serial::write_byte(b);
    }

    /// Read a byte from the serial console (blocking).
    #[inline(always)]
    pub fn serial_read_byte() -> u8 {
        #[cfg(target_arch = "x86_64")]
        { crate::x86_64::serial::read_byte() }
        #[cfg(target_arch = "aarch64")]
        { crate::aarch64::serial::read_byte() }
    }

    /// Write a string to serial.
    pub fn serial_write_str(s: &str) {
        #[cfg(target_arch = "x86_64")]
        crate::x86_64::serial::write_str(s);
        #[cfg(target_arch = "aarch64")]
        crate::aarch64::serial::write_str(s);
    }

    /// Write bytes to serial.
    pub fn serial_write_bytes(b: &[u8]) {
        #[cfg(target_arch = "x86_64")]
        crate::x86_64::serial::write_bytes(b);
        #[cfg(target_arch = "aarch64")]
        crate::aarch64::serial::write_bytes(b);
    }

    /// Get timer ticks.
    #[inline(always)]
    pub fn ticks() -> u64 {
        #[cfg(target_arch = "x86_64")]
        { crate::x86_64::pit::ticks() }
        #[cfg(target_arch = "aarch64")]
        { crate::aarch64::timer::ticks() }
    }

    /// Read the current page table root address.
    #[inline(always)]
    pub fn page_table_root() -> u64 {
        let val: u64;
        #[cfg(target_arch = "x86_64")]
        unsafe { core::arch::asm!("mov {}, cr3", out(reg) val, options(nostack)); }
        #[cfg(target_arch = "aarch64")]
        unsafe { core::arch::asm!("mrs {}, ttbr0_el1", out(reg) val, options(nostack)); }
        val
    }
}

// ── Shared statics ──────────────────────────────────────────────────

/// Program break for brk() syscall.
pub static mut PROGRAM_BRK: u64 = 0;

/// Track child exit status for wait4.
pub static mut LAST_CHILD_EXIT: i32 = 0;

/// Track whether there's a child to collect.
pub static mut CHILD_AVAILABLE: bool = false;

// ── File I/O syscalls ───────────────────────────────────────────────

pub fn sys_read(fd: u64, buf: u64, len: u64) -> i64 {
    if fd == 0 {
        unsafe {
            let ptr = buf as *mut u8;
            for i in 0..len as usize {
                *ptr.add(i) = arch::serial_read_byte();
            }
        }
        return len as i64;
    }
    crate::fdtable::sys_read_fd(fd as usize, buf as *mut u8, len as usize)
}

pub fn sys_write(fd: u64, buf: u64, len: u64) -> i64 {
    if fd <= 2 {
        unsafe {
            let ptr = buf as *const u8;
            for i in 0..len as usize { arch::serial_write_byte(*ptr.add(i)); }
        }
        return len as i64;
    }
    crate::fdtable::sys_write_fd(fd as usize, buf as *const u8, len as usize)
}

pub fn sys_open(path_ptr: u64) -> i64 {
    unsafe {
        let cstr = path_ptr as *const u8;
        let mut len = 0usize;
        while *cstr.add(len) != 0 && len < 256 { len += 1; }
        let path = core::slice::from_raw_parts(cstr, len);
        crate::fdtable::sys_open(path)
    }
}

pub fn sys_openat(_dirfd: u64, pathname: u64) -> i64 {
    sys_open(pathname)
}

pub fn sys_writev(fd: u64, iov_ptr: u64, iovcnt: u64) -> i64 {
    unsafe {
        let iov = iov_ptr as *const [u64; 2];
        let mut total: i64 = 0;
        for i in 0..iovcnt as usize {
            let base = (*iov.add(i))[0];
            let len = (*iov.add(i))[1];
            let n = sys_write(fd, base, len);
            if n < 0 { return n; }
            total += n;
        }
        total
    }
}

pub fn sys_dup2(oldfd: u64, newfd: u64) -> i64 {
    if oldfd <= 2 && newfd <= 2 { return newfd as i64; }
    newfd as i64
}

// ── Path resolution helper ──────────────────────────────────────────

/// Resolve a path to (parent_inode, basename).
pub unsafe fn resolve_parent_and_name(path_ptr: u64) -> Result<(rux_vfs::InodeId, &'static [u8]), i64> {
    use rux_vfs::FileSystem;
    let cstr = path_ptr as *const u8;
    let mut len = 0usize;
    while *cstr.add(len) != 0 && len < 256 { len += 1; }
    let path = core::slice::from_raw_parts(cstr, len);

    let mut last_slash = 0;
    for j in 0..len {
        if path[j] == b'/' { last_slash = j; }
    }

    let fs = crate::kstate::fs();
    if last_slash == 0 {
        let name = &path[1..];
        Ok((fs.root_inode(), name))
    } else {
        let parent_path = &path[..last_slash];
        let name = &path[last_slash + 1..];
        match rux_vfs::path::resolve_path(fs, parent_path) {
            Ok(parent_ino) => Ok((parent_ino, name)),
            Err(_) => Err(-2),
        }
    }
}

// ── Filesystem mutation syscalls ────────────────────────────────────

pub fn sys_creat(path_ptr: u64) -> i64 {
    unsafe {
        use rux_vfs::{FileSystem, FileName};
        let (dir_ino, name) = match resolve_parent_and_name(path_ptr) {
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

pub fn sys_mkdir(path_ptr: u64) -> i64 {
    unsafe {
        use rux_vfs::{FileSystem, FileName};
        let (dir_ino, name) = match resolve_parent_and_name(path_ptr) {
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

pub fn sys_unlink(path_ptr: u64) -> i64 {
    unsafe {
        use rux_vfs::{FileSystem, FileName};
        let (dir_ino, name) = match resolve_parent_and_name(path_ptr) {
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

// ── Stat syscalls ───────────────────────────────────────────────────

/// Fill a Linux struct stat (144 bytes) from VFS InodeStat.
pub unsafe fn fill_linux_stat(buf: u64, vfs_stat: &rux_vfs::InodeStat) {
    let p = buf as *mut u8;
    for i in 0..144 { *p.add(i) = 0; }
    *(buf as *mut u64) = 0;                            // st_dev
    *((buf + 8) as *mut u64) = vfs_stat.ino;           // st_ino
    *((buf + 16) as *mut u64) = vfs_stat.nlink as u64; // st_nlink
    *((buf + 24) as *mut u32) = vfs_stat.mode;         // st_mode
    *((buf + 28) as *mut u32) = vfs_stat.uid;          // st_uid
    *((buf + 32) as *mut u32) = vfs_stat.gid;          // st_gid
    *((buf + 48) as *mut i64) = vfs_stat.size as i64;  // st_size
    *((buf + 56) as *mut i64) = 4096;                  // st_blksize
    *((buf + 64) as *mut i64) = vfs_stat.blocks as i64;// st_blocks
}

pub fn sys_fstat(fd: u64, buf: u64) -> i64 {
    if buf == 0 { return -14; }
    if fd <= 2 {
        unsafe {
            let p = buf as *mut u8;
            for i in 0..144 { *p.add(i) = 0; }
            *((buf + 24) as *mut u32) = 0o20666; // S_IFCHR | 0666
            *((buf + 56) as *mut i64) = 4096;
        }
        return 0;
    }
    unsafe {
        let p = buf as *mut u8;
        for i in 0..144 { *p.add(i) = 0; }
        *((buf + 24) as *mut u32) = 0o100644;
        *((buf + 56) as *mut i64) = 4096;
    }
    0
}

pub fn sys_fstatat(_dirfd: u64, pathname: u64, buf: u64) -> i64 {
    if buf == 0 { return -14; }
    unsafe {
        use rux_vfs::FileSystem;
        let cstr = pathname as *const u8;
        let mut len = 0usize;
        while *cstr.add(len) != 0 && len < 256 { len += 1; }
        let path = core::slice::from_raw_parts(cstr, len);
        let fs = crate::kstate::fs();
        let ino = match rux_vfs::path::resolve_path(fs, path) {
            Ok(ino) => ino,
            Err(_) => return -2,
        };
        let mut vfs_stat = core::mem::zeroed::<rux_vfs::InodeStat>();
        if fs.stat(ino, &mut vfs_stat).is_err() { return -2; }
        fill_linux_stat(buf, &vfs_stat);
        0
    }
}

// ── Directory listing ───────────────────────────────────────────────

pub fn sys_getdents64(fd: u64, buf_ptr: u64, bufsize: u64) -> i64 {
    unsafe {
        use rux_vfs::{FileSystem, DirEntry, InodeType};
        let fs = crate::kstate::fs();
        let out = buf_ptr as *mut u8;
        let limit = bufsize as usize;
        let mut pos = 0usize;

        let dir_ino = if fd >= 3 {
            match crate::fdtable::get_fd_inode(fd as usize) {
                Some(ino) => ino,
                None => return -9,
            }
        } else {
            0
        };

        static mut DIR_OFFSET: [usize; 16] = [0; 16];
        let off_idx = (fd as usize).min(15);
        let mut offset = DIR_OFFSET[off_idx];
        let start_pos = pos;

        loop {
            let mut entry = core::mem::zeroed::<DirEntry>();
            match fs.readdir(dir_ino, offset, &mut entry) {
                Ok(true) => {
                    let nlen = entry.name_len as usize;
                    let reclen = ((19 + nlen + 1) + 7) & !7;
                    if pos + reclen > limit { break; }
                    *((out.add(pos)) as *mut u64) = entry.ino;
                    *((out.add(pos + 8)) as *mut u64) = (offset + 1) as u64;
                    *((out.add(pos + 16)) as *mut u16) = reclen as u16;
                    let dtype: u8 = match entry.kind {
                        InodeType::File => 8,
                        InodeType::Directory => 4,
                        InodeType::Symlink => 10,
                        _ => 0,
                    };
                    *out.add(pos + 18) = dtype;
                    for i in 0..nlen { *out.add(pos + 19 + i) = entry.name[i]; }
                    *out.add(pos + 19 + nlen) = 0;
                    pos += reclen;
                    offset += 1;
                }
                _ => break,
            }
        }
        DIR_OFFSET[off_idx] = offset;
        if pos == start_pos { return 0; }
        pos as i64
    }
}

// ── Process syscalls ────────────────────────────────────────────────

pub fn sys_wait4(_pid: u64, wstatus_ptr: u64, options: u64, _rusage: u64) -> i64 {
    unsafe {
        if !CHILD_AVAILABLE { return -10; } // -ECHILD
        CHILD_AVAILABLE = false;
        if wstatus_ptr != 0 {
            let status = (LAST_CHILD_EXIT as u32) << 8;
            *(wstatus_ptr as *mut u32) = status;
        }
        42
    }
}

pub fn sys_exit(status: i32) -> ! {
    arch::serial_write_str("rux: user exit(");
    let mut buf = [0u8; 10];
    arch::serial_write_str(crate::write_u32(&mut buf, status as u32));
    arch::serial_write_str(")\n");

    unsafe { LAST_CHILD_EXIT = status; }

    // Arch-specific: check vfork and either longjmp or exit kernel
    #[cfg(target_arch = "x86_64")]
    unsafe {
        if super::x86_64::syscall::vfork_jmp_active() {
            super::x86_64::syscall::vfork_longjmp_to_parent(42);
        }
        crate::x86_64::exit::exit_qemu(crate::x86_64::exit::EXIT_SUCCESS);
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        if super::aarch64::syscall::vfork_jmp_active() {
            super::aarch64::syscall::vfork_longjmp_to_parent(42);
        }
        crate::aarch64::exit::exit_qemu(crate::aarch64::exit::EXIT_SUCCESS);
    }
}

// ── Info syscalls ───────────────────────────────────────────────────

pub fn sys_uname(buf: u64) -> i64 {
    if buf == 0 { return -14; }
    unsafe {
        let ptr = buf as *mut u8;
        for i in 0..325 { *ptr.add(i) = 0; }
        let s = b"Linux";
        for (i, &b) in s.iter().enumerate() { *ptr.add(i) = b; }
        let s = b"rux";
        for (i, &b) in s.iter().enumerate() { *ptr.add(65 + i) = b; }
        let s = b"6.1.0-rux";
        for (i, &b) in s.iter().enumerate() { *ptr.add(130 + i) = b; }
        let s = b"#1 SMP";
        for (i, &b) in s.iter().enumerate() { *ptr.add(195 + i) = b; }
        #[cfg(target_arch = "x86_64")]
        { let s = b"x86_64"; for (i, &b) in s.iter().enumerate() { *ptr.add(260 + i) = b; } }
        #[cfg(target_arch = "aarch64")]
        { let s = b"aarch64"; for (i, &b) in s.iter().enumerate() { *ptr.add(260 + i) = b; } }
    }
    0
}

pub fn sys_getcwd(buf: u64, size: u64) -> i64 {
    if buf == 0 || size < 2 { return -34; }
    unsafe {
        let ptr = buf as *mut u8;
        *ptr = b'/';
        *ptr.add(1) = 0;
    }
    buf as i64
}

pub fn sys_clock_gettime(_clockid: u64, tp: u64) -> i64 {
    if tp == 0 { return -14; }
    let ticks = arch::ticks();
    unsafe {
        *(tp as *mut u64) = ticks / 1000;
        *((tp + 8) as *mut u64) = (ticks % 1000) * 1_000_000;
    }
    0
}

// ── Signal stubs ────────────────────────────────────────────────────

pub fn sys_rt_sigaction(_signum: u64, _act: u64, _oldact: u64) -> i64 { 0 }

pub fn sys_rt_sigprocmask(_how: u64, _set: u64, oldset: u64, sigsetsize: u64) -> i64 {
    if oldset != 0 && sigsetsize > 0 && sigsetsize <= 8 {
        unsafe { *(oldset as *mut u64) = 0; }
    }
    0
}

// ── Terminal ioctl ──────────────────────────────────────────────────

pub fn sys_ioctl(_fd: u64, request: u64, arg: u64) -> i64 {
    const TCGETS: u64 = 0x5401;
    const TIOCGWINSZ: u64 = 0x5413;
    const TIOCSPGRP: u64 = 0x5410;
    const TIOCGPGRP: u64 = 0x540F;

    match request {
        TIOCGWINSZ => {
            if arg != 0 {
                unsafe { *(arg as *mut [u16; 4]) = [24, 80, 0, 0]; }
            }
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
        TIOCSPGRP => 0,
        0x5402 | 0x5403 | 0x5404 => 0,
        _ => -25
    }
}

// ── Memory management ───────────────────────────────────────────────

pub fn sys_brk(addr: u64) -> i64 {
    unsafe {
        if PROGRAM_BRK == 0 { PROGRAM_BRK = 0x800000; }
        if addr == 0 { return PROGRAM_BRK as i64; }
        if addr >= PROGRAM_BRK {
            use rux_mm::FrameAllocator;
            let old_page = (PROGRAM_BRK + 0xFFF) & !0xFFF;
            let new_page = (addr + 0xFFF) & !0xFFF;
            let alloc = crate::kstate::alloc();
            let cr3 = arch::page_table_root();

            #[cfg(target_arch = "x86_64")]
            {
                let mut upt = crate::x86_64::paging::PageTable4Level::from_cr3(
                    rux_klib::PhysAddr::new(cr3 as usize));
                let flags = rux_mm::MappingFlags::READ
                    .or(rux_mm::MappingFlags::WRITE)
                    .or(rux_mm::MappingFlags::USER);
                for pa in (old_page..new_page).step_by(4096) {
                    let frame = alloc.alloc(rux_mm::PageSize::FourK).expect("brk page");
                    let ptr = frame.as_usize() as *mut u8;
                    for j in 0..4096 { core::ptr::write_volatile(ptr.add(j), 0); }
                    let va = rux_klib::VirtAddr::new(pa as usize);
                    let _ = upt.unmap_4k(va);
                    let _ = upt.map_4k(va, frame, flags, alloc);
                }
            }
            #[cfg(target_arch = "aarch64")]
            {
                let mut upt = crate::aarch64::paging::PageTable4Level::from_cr3(
                    rux_klib::PhysAddr::new(cr3 as usize));
                let flags = rux_mm::MappingFlags::READ
                    .or(rux_mm::MappingFlags::WRITE)
                    .or(rux_mm::MappingFlags::USER);
                for pa in (old_page..new_page).step_by(4096) {
                    let frame = alloc.alloc(rux_mm::PageSize::FourK).expect("brk page");
                    let ptr = frame.as_usize() as *mut u8;
                    for j in 0..4096 { core::ptr::write_volatile(ptr.add(j), 0); }
                    let va = rux_klib::VirtAddr::new(pa as usize);
                    let _ = upt.unmap_4k(va);
                    let _ = upt.map_4k(va, frame, flags, alloc);
                }
            }

            PROGRAM_BRK = addr;
        }
        PROGRAM_BRK as i64
    }
}

pub fn sys_mmap(addr: u64, len: u64, _prot: u64, mmap_flags: u64, _fd: u64) -> i64 {
    unsafe {
        use rux_mm::FrameAllocator;
        static mut MMAP_BASE: u64 = 0x10000000;

        if mmap_flags & 0x20 == 0 { return -12; } // no file-backed mmap

        let aligned_len = (len + 0xFFF) & !0xFFF;
        let result = if mmap_flags & 0x10 != 0 && addr != 0 {
            addr & !0xFFF
        } else {
            let r = MMAP_BASE;
            MMAP_BASE += aligned_len;
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
