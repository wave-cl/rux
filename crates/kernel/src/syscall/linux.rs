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
        if super::process().program_brk == 0 { super::process().program_brk = 0x800000; }
        if addr == 0 { return super::process().program_brk as isize; }
        let old_brk = super::process().program_brk;
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
                    return super::process().program_brk as isize;
                }
                let new_pages = (new_page - old_page) / 4096;
                let idx = crate::task_table::current_task_idx();
                crate::task_table::TASK_TABLE[idx].rss_pages += new_pages as u32;
            }
            super::process().program_brk = addr;
        } else if addr < old_brk {
            // Shrinking: unmap freed pages
            let old_page = (old_brk + 0xFFF) & !0xFFF;
            let new_page = (addr + 0xFFF) & !0xFFF;
            if new_page < old_page {
                super::posix::munmap(new_page, old_page - new_page);
                let freed_pages = (old_page - new_page) / 4096;
                let idx = crate::task_table::current_task_idx();
                crate::task_table::TASK_TABLE[idx].rss_pages =
                    crate::task_table::TASK_TABLE[idx].rss_pages.saturating_sub(freed_pages as u32);
            }
            super::process().program_brk = addr;
        }
        super::process().program_brk as isize
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
        let mut offset = if fd < rux_fs::fdtable::MAX_FDS { (*rux_fs::fdtable::fd_table())[fd].offset } else { 0 };
        let result = rux_fs::getdents::pack_getdents64(
            crate::kstate::fs(), dir_ino, buf_ptr as *mut u8, bufsize, &mut offset,
        );
        if fd < rux_fs::fdtable::MAX_FDS { (*rux_fs::fdtable::fd_table())[fd].offset = offset; }
        result
    }
}

// ── Process extensions (Linux-specific) ─────────────────────────────

/// exit_group(status) — Linux-specific.
/// Kills all threads in the calling thread's thread group, then exits.
pub fn exit_group(status: i32) -> ! {
    unsafe {
        use crate::task_table::*;
        let idx = current_task_idx();
        let my_tgid = TASK_TABLE[idx].tgid;

        // Kill all other threads in our thread group
        for j in 0..MAX_PROCS {
            if j != idx && TASK_TABLE[j].active
                && TASK_TABLE[j].tgid == my_tgid
                && TASK_TABLE[j].state != TaskState::Zombie
                && TASK_TABLE[j].state != TaskState::Free
            {
                // Mark thread as dead and dequeue from scheduler
                pid_hash_remove(TASK_TABLE[j].pid);
                TASK_TABLE[j].active = false;
                TASK_TABLE[j].state = TaskState::Free;
                let sched = crate::scheduler::get();
                sched.tasks[j].entity.state = rux_sched::TaskState::Dead;
                sched.tasks[j].active = false;
            }
        }
    }
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

/// waitid(idtype, id, infop, options) — POSIX equivalent of wait4 with
/// siginfo_t output. Routes through waitpid() for the scan logic, using
/// the infop buffer itself as a scratch wstatus pointer (overwritten with
/// the formatted siginfo_t afterwards).
pub fn waitid(idtype: usize, id: usize, infop: usize, options: usize) -> isize {
    // idtype: P_ALL=0, P_PID=1, P_PGID=2, P_PIDFD=3
    let pid = match idtype {
        0 => usize::MAX,
        1 => id,
        2 => return crate::errno::ENOSYS,
        _ => return crate::errno::EINVAL,
    };
    if infop != 0 && crate::uaccess::validate_user_ptr(infop, 128).is_err() {
        return crate::errno::EFAULT;
    }
    // Mask to waitpid()-supported bits: WNOHANG=1, WUNTRACED=2, WCONTINUED=8.
    let waitpid_options = options & 0xB;

    // Use infop as scratch wstatus storage (4 bytes at offset 0). waitpid()
    // writes the encoded status (exit_code << 8) there. We then overwrite
    // the whole 128-byte siginfo_t with proper fields.
    let r = super::posix::waitpid(pid, infop, waitpid_options);
    if r <= 0 { return r; }
    let child_pid = r as u32;

    if infop != 0 {
        unsafe {
            let wstatus = *(infop as *const u32);
            let p = infop as *mut u8;
            for i in 0..128 { *p.add(i) = 0; }
            // siginfo_t for SIGCHLD:
            //   off 0  : si_signo  = SIGCHLD (17)
            //   off 4  : si_errno  = 0
            //   off 8  : si_code   = CLD_EXITED(1)/CLD_KILLED(2)/CLD_STOPPED(5)
            //   off 12 : si_pid    = child pid
            //   off 16 : si_uid    = 0
            //   off 24 : si_status = exit code or terminating signal
            *(infop as *mut i32) = 17;
            let exit_code = (wstatus >> 8) as i32;
            let term_sig = (wstatus & 0x7F) as i32;
            let cld_code = if term_sig == 0 { 1i32 } else { 2 };
            *((infop + 8) as *mut i32) = cld_code;
            *((infop + 12) as *mut u32) = child_pid;
            *((infop + 24) as *mut i32) = if term_sig == 0 { exit_code } else { term_sig };
        }
    }
    0
}

/// ptrace(request, pid, addr, data) — partial implementation.
/// PTRACE_TRACEME / SETOPTIONS succeed; PTRACE_GETREGS / SETREGS work for
/// self-introspection (target_pid == current_pid); cross-process tracing
/// is not supported and returns EPERM.
pub fn ptrace(request: usize, pid: usize, _addr: usize, data: usize) -> isize {
    match request {
        0 => 0,           // PTRACE_TRACEME
        0x4200 => 0,      // PTRACE_SETOPTIONS
        // PTRACE_GETREGS (12) / PTRACE_SETREGS (13) — self only.
        // Linux signature: ptrace(req, pid, addr, data); the user buffer
        // is `data` (4th arg), not `addr`.
        12 => unsafe {
            if pid as u32 != crate::task_table::current_pid() {
                return crate::errno::EPERM;
            }
            if data == 0 || crate::uaccess::validate_user_ptr(data, crate::arch::USER_REGS_SIZE).is_err() {
                return crate::errno::EFAULT;
            }
            crate::arch::read_user_regs(data as *mut u64);
            0
        }
        13 => unsafe {
            if pid as u32 != crate::task_table::current_pid() {
                return crate::errno::EPERM;
            }
            if data == 0 || crate::uaccess::validate_user_ptr(data, crate::arch::USER_REGS_SIZE).is_err() {
                return crate::errno::EFAULT;
            }
            crate::arch::write_user_regs(data as *const u64);
            0
        }
        // Other memory/register operations: cross-AS access not supported.
        1 | 2 | 3 | 4 | 5 | 6 | 14 | 15 | 24 => crate::errno::EPERM,
        // Process-control requests: ESRCH if pid missing, else EPERM
        7 | 8 | 9 | 16 | 17 | 0x4206 => {
            if crate::task_table::find_task_by_pid(pid as u32).is_some() {
                crate::errno::EPERM
            } else {
                crate::errno::ESRCH
            }
        }
        _ => crate::errno::EINVAL,
    }
}

/// vmsplice(fd, iov, iovcnt, flags) — write userspace iov[] into a pipe.
/// Implemented as a loop of write() calls; the existing pipe write path
/// handles fd validation, blocking, and SIGPIPE generation.
pub fn vmsplice(fd: usize, iov_ptr: usize, iovcnt: usize, _flags: usize) -> isize {
    let cnt = iovcnt.min(64);
    if cnt == 0 { return 0; }
    if crate::uaccess::validate_user_ptr(iov_ptr, cnt * 16).is_err() {
        return crate::errno::EFAULT;
    }
    unsafe {
        let iov = iov_ptr as *const [usize; 2];
        let mut total: isize = 0;
        for i in 0..cnt {
            let base = (*iov.add(i))[0];
            let len = (*iov.add(i))[1];
            if base == 0 || len == 0 { continue; }
            let n = super::file::write(fd, base, len);
            if n < 0 { return if total > 0 { total } else { n }; }
            total += n;
            if (n as usize) < len { break; }
        }
        total
    }
}

/// process_vm_readv/process_vm_writev common implementation.
/// Cross-process access requires a page-table switch we don't have, so
/// only same-process (debug self-introspection) is supported.
/// `to_local`: true → readv (remote→local), false → writev (local→remote)
unsafe fn process_vm_rw(
    pid: usize,
    local: usize, liovcnt: usize,
    remote: usize, riovcnt: usize,
    to_local: bool,
) -> isize {
    let me = crate::task_table::current_pid();
    if pid as u32 != me {
        if crate::task_table::find_task_by_pid(pid as u32).is_none() {
            return crate::errno::ESRCH;
        }
        return crate::errno::EPERM;
    }
    let lcnt = liovcnt.min(64);
    let rcnt = riovcnt.min(64);
    if crate::uaccess::validate_user_ptr(local, lcnt * 16).is_err()
        || crate::uaccess::validate_user_ptr(remote, rcnt * 16).is_err() {
        return crate::errno::EFAULT;
    }
    let liov = local as *const [usize; 2];
    let riov = remote as *const [usize; 2];
    let mut total: isize = 0;
    let mut li = 0usize; let mut ri = 0usize;
    let mut loff = 0usize; let mut roff = 0usize;
    while li < lcnt && ri < rcnt {
        let llen = (*liov.add(li))[1];
        let rlen = (*riov.add(ri))[1];
        if llen == 0 { li += 1; loff = 0; continue; }
        if rlen == 0 { ri += 1; roff = 0; continue; }
        let lbase = (*liov.add(li))[0] + loff;
        let rbase = (*riov.add(ri))[0] + roff;
        let n = (llen - loff).min(rlen - roff);
        if crate::uaccess::validate_user_ptr(lbase, n).is_err()
            || crate::uaccess::validate_user_ptr(rbase, n).is_err() {
            return if total > 0 { total } else { crate::errno::EFAULT };
        }
        if to_local {
            core::ptr::copy(rbase as *const u8, lbase as *mut u8, n);
        } else {
            core::ptr::copy(lbase as *const u8, rbase as *mut u8, n);
        }
        total += n as isize;
        loff += n; roff += n;
        if loff == llen { li += 1; loff = 0; }
        if roff == rlen { ri += 1; roff = 0; }
    }
    total
}

/// process_vm_readv(pid, local_iov, liovcnt, remote_iov, riovcnt, flags)
pub fn process_vm_readv(pid: usize, l: usize, lc: usize, r: usize, rc: usize, _flags: usize) -> isize {
    unsafe { process_vm_rw(pid, l, lc, r, rc, true) }
}

/// process_vm_writev(pid, local_iov, liovcnt, remote_iov, riovcnt, flags)
pub fn process_vm_writev(pid: usize, l: usize, lc: usize, r: usize, rc: usize, _flags: usize) -> isize {
    unsafe { process_vm_rw(pid, l, lc, r, rc, false) }
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
            use rux_mm::FrameAllocator;
            crate::kstate::alloc().total_frames()
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
        let procs = (*(&raw const crate::task_table::TASK_TABLE)).iter()
            .filter(|t| t.active && t.state != crate::task_table::TaskState::Zombie)
            .count();
        *((info_ptr + 8 * w) as *mut u16) = procs as u16;
        // mem_unit (unsigned int) — at offset after totalhigh/freehigh
        // On 64-bit: offset = 10*w + 4 (after procs pad + totalhigh + freehigh)
        // Simpler: mem_unit = 1 (bytes already in byte units)
        *((info_ptr + 10 * w + 4) as *mut u32) = 1;
    }
    0
}

/// splice(fd_in, off_in, fd_out, off_out, len, flags) — move data between fds.
/// At least one fd must be a pipe (or socket). Uses a kernel buffer for the transfer.
pub fn splice(fd_in: usize, off_in_ptr: usize, fd_out: usize, off_out_ptr: usize, len: usize, _flags: usize) -> isize {
    if len == 0 { return 0; }
    let chunk = len.min(4096);
    let mut kbuf = [0u8; 4096];

    unsafe {
        use rux_fs::fdtable as fdt;

        let in_is_pipe = fd_in < fdt::MAX_FDS && (*fdt::fd_table())[fd_in].active && (*fdt::fd_table())[fd_in].is_pipe;
        let out_is_pipe = fd_out < fdt::MAX_FDS && (*fdt::fd_table())[fd_out].active && (*fdt::fd_table())[fd_out].is_pipe;
        let out_is_socket = super::socket::is_socket(fd_out);

        // At least one fd must be a pipe (Linux requirement)
        if !in_is_pipe && !out_is_pipe && !out_is_socket {
            return crate::errno::EINVAL;
        }

        // ESPIPE: offset pointers not allowed on pipes
        if in_is_pipe && off_in_ptr != 0 { return crate::errno::ESPIPE; }
        if out_is_pipe && off_out_ptr != 0 { return crate::errno::ESPIPE; }

        // Parse offset pointers (NULL = use fd's current offset)
        let in_off = if off_in_ptr != 0 {
            if crate::uaccess::validate_user_ptr(off_in_ptr, 8).is_err() { return crate::errno::EFAULT; }
            Some(*(off_in_ptr as *const i64) as u64)
        } else { None };

        let out_off = if off_out_ptr != 0 {
            if crate::uaccess::validate_user_ptr(off_out_ptr, 8).is_err() { return crate::errno::EFAULT; }
            Some(*(off_out_ptr as *const i64) as u64)
        } else { None };

        // Read from fd_in
        let bytes_in = if in_is_pipe {
            let n = (crate::pipe::PIPE.read)((*fdt::fd_table())[fd_in].pipe_id, kbuf.as_mut_ptr(), chunk);
            if n <= 0 { return if n == 0 { 0 } else { n as isize }; }
            n as usize
        } else if fd_in < fdt::MAX_FDS && (*fdt::fd_table())[fd_in].active {
            use rux_fs::FileSystem;
            let f = &(*fdt::fd_table())[fd_in];
            let offset = in_off.unwrap_or(f.offset as u64);
            let fs = crate::kstate::fs();
            let n = fs.read(f.ino, offset, &mut kbuf[..chunk]).unwrap_or(0);
            if n == 0 { return 0; }
            if in_off.is_none() {
                (*fdt::fd_table())[fd_in].offset += n;
            } else if off_in_ptr != 0 {
                *(off_in_ptr as *mut i64) += n as i64;
            }
            n
        } else {
            return crate::errno::EBADF;
        };

        // Write to fd_out
        let bytes_out = if out_is_pipe {
            let n = (crate::pipe::PIPE.write)((*fdt::fd_table())[fd_out].pipe_id, kbuf.as_ptr(), bytes_in);
            if n <= 0 { return crate::errno::EIO; }
            n as usize
        } else if out_is_socket {
            let n = super::socket::sys_sendto(fd_out, kbuf.as_ptr() as usize, bytes_in, 0, 0, 0);
            if n < 0 { return n; }
            n as usize
        } else if fd_out < fdt::MAX_FDS && (*fdt::fd_table())[fd_out].active {
            use rux_fs::FileSystem;
            let f = &(*fdt::fd_table())[fd_out];
            let offset = out_off.unwrap_or(f.offset as u64);
            let fs = crate::kstate::fs();
            let n = fs.write(f.ino, offset, &kbuf[..bytes_in]).unwrap_or(0);
            if n == 0 { return crate::errno::EIO; }
            if out_off.is_none() {
                (*fdt::fd_table())[fd_out].offset += n;
            } else if off_out_ptr != 0 {
                *(off_out_ptr as *mut i64) += n as i64;
            }
            n
        } else {
            return crate::errno::EBADF;
        };

        bytes_out as isize
    }
}

/// tee(fd_in, fd_out, len, flags) — duplicate pipe data.
/// Both fds must be pipes. Linux tee peeks without consuming; our simplified
/// implementation consumes (same as splice). This matches observed behavior
/// for programs that use tee for logging/mirroring where the source is
/// immediately refilled.
pub fn tee(fd_in: usize, fd_out: usize, len: usize, _flags: usize) -> isize {
    unsafe {
        use rux_fs::fdtable as fdt;
        // Both fds must be pipes
        let in_pipe = fd_in < fdt::MAX_FDS && (*fdt::fd_table())[fd_in].active && (*fdt::fd_table())[fd_in].is_pipe;
        let out_pipe = fd_out < fdt::MAX_FDS && (*fdt::fd_table())[fd_out].active && (*fdt::fd_table())[fd_out].is_pipe;
        if !in_pipe || !out_pipe { return crate::errno::EINVAL; }
    }
    splice(fd_in, 0, fd_out, 0, len, 0)
}
