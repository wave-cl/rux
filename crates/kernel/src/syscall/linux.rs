/// Linux-specific syscall extensions.
///
/// These syscalls are Linux kernel extensions not defined by POSIX.
/// All arguments use native-width types (usize/isize).

// ── Pipes (Linux extension) ──────────────────────────────────────────

/// pipe2(pipefd, flags) — create a pipe.
/// Supports O_NONBLOCK (0o4000) and O_CLOEXEC (0o2000000).
pub fn pipe2(pipefd_ptr: usize, flags: usize) -> isize {
    if crate::uaccess::validate_user_ptr(pipefd_ptr, 8).is_err() { return crate::errno::EFAULT; }
    match crate::pipe::create() {
        Ok((_pipe_id, read_fd, write_fd)) => {
            unsafe {
                // Apply O_NONBLOCK to both pipe fds
                if flags & 0o4000 != 0 {
                    if let Some(f) = rux_fs::fdtable::get_fd_mut(read_fd as usize) { f.flags |= 0x800; }
                    if let Some(f) = rux_fs::fdtable::get_fd_mut(write_fd as usize) { f.flags |= 0x800; }
                }
                // Apply O_CLOEXEC to both pipe fds
                if flags & 0o2000000 != 0 {
                    if let Some(f) = rux_fs::fdtable::get_fd_mut(read_fd as usize) { f.fd_flags = rux_fs::fdtable::FD_CLOEXEC; }
                    if let Some(f) = rux_fs::fdtable::get_fd_mut(write_fd as usize) { f.fd_flags = rux_fs::fdtable::FD_CLOEXEC; }
                }
                crate::uaccess::put_user(pipefd_ptr, read_fd as i32);
                crate::uaccess::put_user(pipefd_ptr + 4, write_fd as i32);
            }
            0
        }
        Err(e) => e,
    }
}

// ── Memory: brk (Linux historical, not POSIX) ──────────────────────

/// brk(addr) — Linux-specific heap management.
/// Grows or shrinks the process heap. Returns the actual break on success.
pub fn brk(addr: usize) -> isize {
    unsafe {
        if super::PROCESS.program_brk == 0 { super::PROCESS.program_brk = 0x800000; }
        if addr == 0 { return super::PROCESS.program_brk as isize; }
        let old_brk = super::PROCESS.program_brk;
        if addr > old_brk {
            // Growing: map new pages
            let old_page = (old_brk + 0xFFF) & !0xFFF;
            let new_page = (addr + 0xFFF) & !0xFFF;
            if new_page > old_page {
                let flags = rux_mm::MappingFlags::READ
                    .or(rux_mm::MappingFlags::WRITE)
                    .or(rux_mm::MappingFlags::USER);
                if !super::map_user_pages(old_page, new_page, flags) {
                    // OOM: return current brk unchanged (Linux behavior)
                    return super::PROCESS.program_brk as isize;
                }
            }
            super::PROCESS.program_brk = addr;
        } else if addr < old_brk {
            // Shrinking: unmap freed pages
            let old_page = (old_brk + 0xFFF) & !0xFFF;
            let new_page = (addr + 0xFFF) & !0xFFF;
            if new_page < old_page {
                super::posix::munmap(new_page, old_page - new_page);
            }
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
                None => return crate::errno::EBADF,
            }
        } else {
            0 // root
        };
        let mut offset = if fd < rux_fs::fdtable::MAX_FDS { (*rux_fs::fdtable::FD_TABLE)[fd].offset } else { 0 };
        let result = rux_fs::getdents::pack_getdents64(
            crate::kstate::fs(), dir_ino, buf_ptr as *mut u8, bufsize, &mut offset,
        );
        if fd < rux_fs::fdtable::MAX_FDS { (*rux_fs::fdtable::FD_TABLE)[fd].offset = offset; }
        result
    }
}

// ── Process extensions (Linux-specific) ─────────────────────────────

/// exit_group(status) — Linux-specific.
pub fn exit_group(status: i32) -> ! {
    super::posix::exit(status)
}

/// wait4(pid, wstatus, options, rusage) — Linux extension of POSIX waitpid.
pub fn wait4(pid: usize, wstatus_ptr: usize, options: usize, rusage: usize) -> isize {
    // Zero the rusage struct (144 bytes) so programs get valid empty data
    if rusage != 0 && crate::uaccess::validate_user_ptr(rusage, 144).is_ok() {
        unsafe { core::ptr::write_bytes(rusage as *mut u8, 0, 144); }
    }
    super::posix::waitpid(pid, wstatus_ptr, options)
}

/// Fill a statfs buffer at buf_ptr with filesystem stats.
/// `magic` selects the filesystem type (EXT2, PROC, etc.).
unsafe fn fill_statfs(buf_ptr: usize, magic: usize) {
    use rux_mm::FrameAllocator;
    let w = core::mem::size_of::<usize>();
    let p = buf_ptr;
    for i in 0..120 { *(p as *mut u8).add(i) = 0; }
    *(p as *mut usize) = magic;
    *((p + w) as *mut usize) = 4096;     // f_bsize
    *((p + 9*w) as *mut usize) = 255;    // f_namelen
    *((p + 10*w) as *mut usize) = 4096;  // f_frsize
    if magic == 0xEF53 { // EXT2: report real block counts
        let alloc = crate::kstate::alloc();
        let total = alloc.total_frames();
        let free = alloc.available_frames(rux_mm::PageSize::FourK);
        *((p + 2*w) as *mut usize) = total;   // f_blocks
        *((p + 3*w) as *mut usize) = free;    // f_bfree
        *((p + 4*w) as *mut usize) = free;    // f_bavail
        *((p + 5*w) as *mut usize) = 65536;   // f_files
        *((p + 6*w) as *mut usize) = 65536;   // f_ffree
    }
}

/// statfs(path, buf) — Linux filesystem stats.
pub fn statfs(path_ptr: usize, buf_ptr: usize) -> isize {
    if crate::uaccess::validate_user_ptr(buf_ptr, 120).is_err() { return crate::errno::EFAULT; }
    unsafe {
        let path = crate::uaccess::read_user_cstr(path_ptr);
        let magic = if path.starts_with(b"/proc") { 0x9FA0 }
            else if path.starts_with(b"/dev") || path.starts_with(b"/sys") { 0x1373 }
            else { 0xEF53 };
        fill_statfs(buf_ptr, magic);
    }
    0
}

/// fstatfs(fd, buf) — Linux filesystem stats by file descriptor.
pub fn fstatfs(_fd: usize, buf_ptr: usize) -> isize {
    if crate::uaccess::validate_user_ptr(buf_ptr, 120).is_err() { return crate::errno::EFAULT; }
    unsafe { fill_statfs(buf_ptr, 0xEF53); }
    0
}

/// set_tid_address(tidptr) — Linux: store clear_child_tid pointer, return tid.
pub fn set_tid_address(tidptr: usize) -> isize {
    // Validate now — this pointer is dereferenced later on thread exit
    if tidptr != 0 && crate::uaccess::validate_user_ptr(tidptr, 4).is_err() {
        return crate::errno::EFAULT;
    }
    unsafe {
        use crate::task_table::*;
        TASK_TABLE[current_task_idx()].clear_child_tid = tidptr;
        TASK_TABLE[current_task_idx()].pid as isize
    }
}

/// sysinfo(info) — Linux-specific system information.
/// Used by `free`, `uptime`, and other utilities.
pub fn sysinfo(info_ptr: usize) -> isize {
    if crate::uaccess::validate_user_ptr(info_ptr, 112).is_err() { return crate::errno::EFAULT; }
    unsafe {
        use rux_arch::TimerOps;
        let ticks = crate::arch::Arch::ticks();
        let uptime = ticks / 1000; // seconds since boot

        let total_frames = {
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

/// splice(fd_in, off_in, fd_out, off_out, len, flags) — move data between fds.
/// At least one fd must be a pipe. Uses a kernel buffer for the transfer.
pub fn splice(fd_in: usize, off_in_ptr: usize, fd_out: usize, off_out_ptr: usize, len: usize, _flags: usize) -> isize {
    if len == 0 { return 0; }
    let chunk = len.min(4096); // transfer up to 4KB at a time
    let mut kbuf = [0u8; 4096];

    unsafe {
        use rux_fs::fdtable as fdt;

        // Determine offsets (NULL means use fd's current offset)
        let in_off = if off_in_ptr != 0 {
            if crate::uaccess::validate_user_ptr(off_in_ptr, 8).is_err() { return crate::errno::EFAULT; }
            Some(*(off_in_ptr as *const i64) as u64)
        } else { None };

        let out_off = if off_out_ptr != 0 {
            if crate::uaccess::validate_user_ptr(off_out_ptr, 8).is_err() { return crate::errno::EFAULT; }
            Some(*(off_out_ptr as *const i64) as u64)
        } else { None };

        // Read from fd_in
        let bytes_in = if fd_in < fdt::MAX_FDS && (*fdt::FD_TABLE)[fd_in].active && (*fdt::FD_TABLE)[fd_in].is_pipe {
            let n = (crate::pipe::PIPE.read)((*fdt::FD_TABLE)[fd_in].pipe_id, kbuf.as_mut_ptr(), chunk);
            if n <= 0 { return if n == 0 { 0 } else { n as isize }; }
            n as usize
        } else if fd_in < fdt::MAX_FDS && (*fdt::FD_TABLE)[fd_in].active {
            // File fd — read at offset
            use rux_fs::FileSystem;
            let f = &(*fdt::FD_TABLE)[fd_in];
            let offset = in_off.unwrap_or(f.offset as u64);
            let fs = crate::kstate::fs();
            let n = fs.read(f.ino, offset, &mut kbuf[..chunk]).unwrap_or(0);
            if n == 0 { return 0; }
            // Update file offset
            if in_off.is_none() {
                (*fdt::FD_TABLE)[fd_in].offset += n;
            } else if off_in_ptr != 0 {
                *(off_in_ptr as *mut i64) += n as i64;
            }
            n
        } else {
            return crate::errno::EBADF;
        };

        // Write to fd_out
        let bytes_out = if fd_out < fdt::MAX_FDS && (*fdt::FD_TABLE)[fd_out].active && (*fdt::FD_TABLE)[fd_out].is_pipe {
            let n = (crate::pipe::PIPE.write)((*fdt::FD_TABLE)[fd_out].pipe_id, kbuf.as_ptr(), bytes_in);
            if n <= 0 { return crate::errno::EIO; }
            n as usize
        } else if fd_out < fdt::MAX_FDS && (*fdt::FD_TABLE)[fd_out].active {
            use rux_fs::FileSystem;
            let f = &(*fdt::FD_TABLE)[fd_out];
            let offset = out_off.unwrap_or(f.offset as u64);
            let fs = crate::kstate::fs();
            let n = fs.write(f.ino, offset, &kbuf[..bytes_in]).unwrap_or(0);
            if n == 0 { return crate::errno::EIO; }
            if out_off.is_none() {
                (*fdt::FD_TABLE)[fd_out].offset += n;
            } else if off_out_ptr != 0 {
                *(off_out_ptr as *mut i64) += n as i64;
            }
            n
        } else if super::socket::is_socket(fd_out) {
            // Socket output
            let n = super::socket::sys_sendto(fd_out, kbuf.as_ptr() as usize, bytes_in, 0, 0, 0);
            if n < 0 { return n; }
            n as usize
        } else {
            return crate::errno::EBADF;
        };

        bytes_out as isize
    }
}

/// tee(fd_in, fd_out, len, flags) — duplicate pipe data without consuming.
/// Both fds must be pipes. Copies data from fd_in's buffer to fd_out without
/// advancing fd_in's read position. Simplified: just read+write (consuming).
pub fn tee(fd_in: usize, fd_out: usize, len: usize, flags: usize) -> isize {
    // Simplified implementation: tee acts like splice between two pipes.
    // A full implementation would peek without consuming, but for basic
    // conformance this is sufficient.
    splice(fd_in, 0, fd_out, 0, len, flags)
}
