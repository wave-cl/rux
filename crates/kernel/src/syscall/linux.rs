/// Linux-specific syscall extensions.
///
/// These syscalls are Linux kernel extensions not defined by POSIX.
/// All arguments use native-width types (usize/isize).

// ── Pipes (Linux extension) ──────────────────────────────────────────

/// pipe2(pipefd, flags) — create a pipe.
pub fn pipe2(pipefd_ptr: usize, _flags: usize) -> isize {
    if pipefd_ptr == 0 { return -14; } // -EFAULT
    match crate::pipe::create() {
        Ok((_pipe_id, read_fd, write_fd)) => {
            unsafe {
                let p = pipefd_ptr as *mut i32;
                *p = read_fd as i32;
                *p.add(1) = write_fd as i32;
            }
            0
        }
        Err(e) => e,
    }
}

// ── Memory: brk (Linux historical, not POSIX) ──────────────────────

/// brk(addr) — Linux-specific heap management.
pub fn brk(addr: usize) -> isize {
    unsafe {
        if super::PROCESS.program_brk == 0 { super::PROCESS.program_brk = 0x800000; }
        if addr == 0 { return super::PROCESS.program_brk as isize; }
        if addr >= super::PROCESS.program_brk {
            let old_page = (super::PROCESS.program_brk + 0xFFF) & !0xFFF;
            let new_page = (addr + 0xFFF) & !0xFFF;
            let flags = rux_mm::MappingFlags::READ
                .or(rux_mm::MappingFlags::WRITE)
                .or(rux_mm::MappingFlags::USER);
            super::map_user_pages(old_page, new_page, flags);
            super::PROCESS.program_brk = addr;
        }
        super::PROCESS.program_brk as isize
    }
}

// ── Directory listing (Linux-specific format) ───────────────────────

/// getdents64(fd, dirp, count) — Linux-specific.
pub fn getdents64(fd: usize, buf_ptr: usize, bufsize: usize) -> isize {
    unsafe {
        let dir_ino = if fd >= 3 {
            match rux_fs::fdtable::get_fd_inode(fd) {
                Some(ino) => ino,
                None => return -9,
            }
        } else {
            0 // root
        };
        let mut offset = if fd < 64 { (*rux_fs::fdtable::FD_TABLE)[fd].offset } else { 0 };
        let result = rux_fs::getdents::pack_getdents64(
            crate::kstate::fs(), dir_ino, buf_ptr as *mut u8, bufsize, &mut offset,
        );
        if fd < 64 { (*rux_fs::fdtable::FD_TABLE)[fd].offset = offset; }
        result
    }
}

// ── Process extensions (Linux-specific) ─────────────────────────────

/// exit_group(status) — Linux-specific.
pub fn exit_group(status: i32) -> ! {
    super::posix::exit(status)
}

/// wait4(pid, wstatus, options, rusage) — Linux extension of POSIX waitpid.
pub fn wait4(pid: usize, wstatus_ptr: usize, options: usize, _rusage: usize) -> isize {
    super::posix::waitpid(pid, wstatus_ptr, options)
}

/// statfs(path, buf) — Linux filesystem stats.
/// Used by `df` to show disk space.
pub fn statfs(_path_ptr: usize, buf_ptr: usize) -> isize {
    if buf_ptr == 0 { return -14; }
    unsafe {
        use rux_mm::FrameAllocator;
        let total_frames = 16384usize;
        let free_frames = crate::kstate::alloc().available_frames(rux_mm::PageSize::FourK);

        let w = core::mem::size_of::<usize>();
        let p = buf_ptr;
        // Zero the struct (120 bytes on 64-bit)
        for i in 0..120 { *(buf_ptr as *mut u8).add(i) = 0; }

        *(p as *mut usize) = 0x858458F6; // f_type: RAMFS_MAGIC
        *((p + w) as *mut usize) = 4096;  // f_bsize: block size
        *((p + 2*w) as *mut usize) = total_frames; // f_blocks
        *((p + 3*w) as *mut usize) = free_frames;  // f_bfree
        *((p + 4*w) as *mut usize) = free_frames;  // f_bavail
        *((p + 5*w) as *mut usize) = 65536;        // f_files (max inodes)
        *((p + 6*w) as *mut usize) = 65536;        // f_ffree
        // f_fsid at 7*w (8 bytes) = 0
        *((p + 9*w) as *mut usize) = 255;          // f_namelen
        *((p + 10*w) as *mut usize) = 4096;        // f_frsize
    }
    0
}

/// set_tid_address(tidptr) — Linux-specific TLS.
pub fn set_tid_address(_tidptr: usize) -> isize {
    1 // TID = 1
}

/// sysinfo(info) — Linux-specific system information.
/// Used by `free`, `uptime`, and other utilities.
pub fn sysinfo(info_ptr: usize) -> isize {
    if info_ptr == 0 { return -14; }
    unsafe {
        use rux_arch::TimerOps;
        let ticks = crate::arch::Arch::ticks();
        let uptime = ticks / 1000; // seconds since boot

        let total_frames = {
            use rux_mm::FrameAllocator;
            16384usize // hardcoded, matches init
        };
        let free_frames = {
            use rux_mm::FrameAllocator;
            crate::kstate::alloc().available_frames(rux_mm::PageSize::FourK)
        };

        let p = info_ptr as *mut u8;
        // Zero the struct first (varies 64-112 bytes depending on arch)
        for i in 0..112 { *p.add(i) = 0; }

        let w = core::mem::size_of::<usize>();

        // uptime (long)
        *(info_ptr as *mut usize) = uptime as usize;
        // loads[3] (unsigned long × 3) — fixed-point with 16-bit fraction
        // 0 load = 0
        let loads_ptr = info_ptr + w;
        *(loads_ptr as *mut usize) = 0;
        *((loads_ptr + w) as *mut usize) = 0;
        *((loads_ptr + 2 * w) as *mut usize) = 0;
        // totalram (unsigned long)
        *((info_ptr + 4 * w) as *mut usize) = total_frames * 4096;
        // freeram (unsigned long)
        *((info_ptr + 5 * w) as *mut usize) = free_frames * 4096;
        // sharedram = 0, bufferram = 0
        // totalswap = 0, freeswap = 0
        // procs (unsigned short) — at offset 8*w on 64-bit
        *((info_ptr + 8 * w) as *mut u16) = 1; // 1 process
        // mem_unit (unsigned int) — at offset after totalhigh/freehigh
        // On 64-bit: offset = 10*w + 4 (after procs pad + totalhigh + freehigh)
        // Simpler: mem_unit = 1 (bytes already in byte units)
        *((info_ptr + 10 * w + 4) as *mut u32) = 1;
    }
    0
}
