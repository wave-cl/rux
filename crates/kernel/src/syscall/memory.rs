//! Memory mapping, poll, and epoll syscalls.

use rux_fs::fdtable as fdt;

// ── Shared helpers for virtual fd types (eventfd, timerfd, epoll) ──

/// Allocate an fd from the fd table, applying O_NONBLOCK if set in flags.
/// Returns the fd number on success, or negative errno.
unsafe fn alloc_virtual_fd(flags: usize) -> isize {
    let fd_table = &mut *fdt::FD_TABLE;
    let fd = match (fdt::FIRST_FILE_FD..fdt::MAX_FDS).find(|&f| !fd_table[f].active) {
        Some(f) => f,
        None => return crate::errno::ENOMEM,
    };
    fd_table[fd] = fdt::EMPTY_FD;
    fd_table[fd].active = true;
    if flags & 0x800 != 0 { fd_table[fd].flags |= 0x800; } // O_NONBLOCK / EFD_NONBLOCK / TFD_NONBLOCK
    fd as isize
}

/// Blocking read that returns a u64 value. Polls `check` up to `max_iters`
/// times, writing the result to `buf` when ready. Respects O_NONBLOCK on fd.
unsafe fn blocking_read_u64<F>(fd: usize, buf: usize, max_iters: u32, mut check: F) -> isize
where F: FnMut() -> Option<u64>
{
    let nonblock = fd < fdt::MAX_FDS && ((*fdt::FD_TABLE)[fd].flags & 0x800) != 0;
    for _ in 0..max_iters {
        if let Some(val) = check() {
            *(buf as *mut u64) = val;
            return 8;
        }
        if nonblock { return crate::errno::EAGAIN; }
        use rux_arch::HaltOps;
        crate::arch::Arch::halt_until_interrupt();
    }
    crate::errno::EAGAIN
}

// ── epoll ──────────────────────────────────────────────────────────

const MAX_EPOLL: usize = 4;
const MAX_EPOLL_FDS: usize = 64;

#[derive(Clone, Copy)]
struct EpollEntry {
    fd: i32,
    events: u32,
    data: u64,
}

struct EpollInstance {
    active: bool,
    entries: [EpollEntry; MAX_EPOLL_FDS],
    count: usize,
    epoll_fd: usize, // the FD number assigned to this epoll instance
}

impl EpollInstance {
    const fn empty() -> Self {
        Self {
            active: false,
            entries: [EpollEntry { fd: -1, events: 0, data: 0 }; MAX_EPOLL_FDS],
            count: 0,
            epoll_fd: 0,
        }
    }
}

static mut EPOLL: [EpollInstance; MAX_EPOLL] = [
    EpollInstance::empty(), EpollInstance::empty(),
    EpollInstance::empty(), EpollInstance::empty(),
];

/// epoll_create1(flags) → fd
pub fn epoll_create(_flags: usize) -> isize {
    unsafe {
        let idx = match (0..MAX_EPOLL).find(|&i| !EPOLL[i].active) {
            Some(i) => i,
            None => return crate::errno::ENOMEM,
        };
        // Allocate an FD for this epoll instance
        let fd_table = &mut *fdt::FD_TABLE;
        let fd = match (fdt::FIRST_FILE_FD..fdt::MAX_FDS).find(|&f| !fd_table[f].active) {
            Some(f) => f,
            None => return crate::errno::ENOMEM,
        };
        fd_table[fd] = fdt::EMPTY_FD;
        fd_table[fd].active = true;
        // Mark as epoll FD (reuse is_pipe field with a flag)
        EPOLL[idx].active = true;
        EPOLL[idx].count = 0;
        EPOLL[idx].epoll_fd = fd;
        fd as isize
    }
}

fn find_epoll(epfd: usize) -> Option<usize> {
    unsafe { (0..MAX_EPOLL).find(|&i| EPOLL[i].active && EPOLL[i].epoll_fd == epfd) }
}

/// epoll_ctl(epfd, op, fd, event_ptr) — add/mod/del fd
pub fn epoll_ctl(epfd: usize, op: usize, fd: usize, event_ptr: usize) -> isize {
    const EPOLL_CTL_ADD: usize = 1;
    const EPOLL_CTL_DEL: usize = 2;
    const EPOLL_CTL_MOD: usize = 3;

    let idx = match find_epoll(epfd) {
        Some(i) => i,
        None => return crate::errno::EBADF,
    };

    unsafe {
        let ep = &mut EPOLL[idx];
        match op {
            EPOLL_CTL_ADD => {
                if ep.count >= MAX_EPOLL_FDS { return crate::errno::ENOMEM; }
                if crate::uaccess::validate_user_ptr(event_ptr, 12).is_err() { return crate::errno::EFAULT; }
                let events = *(event_ptr as *const u32);
                let data = *((event_ptr + 4) as *const u64);
                let slot = ep.count;
                ep.entries[slot] = EpollEntry { fd: fd as i32, events, data };
                ep.count += 1;
                0
            }
            EPOLL_CTL_DEL => {
                if let Some(pos) = ep.entries[..ep.count].iter().position(|e| e.fd == fd as i32) {
                    ep.entries[pos] = ep.entries[ep.count - 1];
                    ep.count -= 1;
                }
                0
            }
            EPOLL_CTL_MOD => {
                if crate::uaccess::validate_user_ptr(event_ptr, 12).is_err() { return crate::errno::EFAULT; }
                let events = *(event_ptr as *const u32);
                let data = *((event_ptr + 4) as *const u64);
                if let Some(pos) = ep.entries[..ep.count].iter().position(|e| e.fd == fd as i32) {
                    ep.entries[pos].events = events;
                    ep.entries[pos].data = data;
                }
                0
            }
            _ => crate::errno::EINVAL,
        }
    }
}

/// epoll_wait(epfd, events, maxevents, timeout) — wait for events
pub fn epoll_wait(epfd: usize, events_ptr: usize, maxevents: usize, timeout: usize) -> isize {
    let idx = match find_epoll(epfd) {
        Some(i) => i,
        None => return crate::errno::EBADF,
    };
    if maxevents == 0 { return crate::errno::EINVAL; }
    let out_count = maxevents.min(64);
    if crate::uaccess::validate_user_ptr(events_ptr, out_count * 12).is_err() { return crate::errno::EFAULT; }

    let timeout_ms = if timeout as isize == -1 { 30_000usize } else { (timeout as usize).min(30_000) };
    let has_sockets = unsafe {
        let ep = &EPOLL[idx];
        ep.entries[..ep.count].iter().any(|e| e.fd >= 0 && super::socket::is_socket(e.fd as usize))
    };

    for _ in 0..timeout_ms.max(1) {
        #[cfg(feature = "net")]
        if has_sockets {
            unsafe { use rux_arch::TimerOps; rux_net::poll(crate::arch::Arch::ticks()); }
        }

        let mut ready = 0usize;
        unsafe {
            let ep = &EPOLL[idx];
            for i in 0..ep.count {
                if ready >= out_count { break; }
                let e = &ep.entries[i];
                let fd = e.fd as usize;
                let mut revents: u32 = 0;
                const EPOLLIN: u32 = 1;
                const EPOLLOUT: u32 = 4;
                if e.events & EPOLLIN != 0 {
                    if super::socket::is_socket(fd) {
                        if super::socket::socket_has_data(fd) { revents |= EPOLLIN; }
                    } else if is_eventfd(fd) {
                        if eventfd_has_data(fd) { revents |= EPOLLIN; }
                    } else if is_timerfd(fd) {
                        if timerfd_has_data(fd) { revents |= EPOLLIN; }
                    } else if fd < rux_fs::fdtable::MAX_FDS && (*fdt::FD_TABLE)[fd].is_pipe {
                        // Pipe: check if data available in the pipe buffer
                        let pid = (*fdt::FD_TABLE)[fd].pipe_id;
                        if crate::pipe::has_data(pid) { revents |= EPOLLIN; }
                    } else {
                        revents |= EPOLLIN; // regular files always readable
                    }
                }
                if e.events & EPOLLOUT != 0 {
                    if super::socket::is_socket(fd) {
                        if super::socket::socket_can_write(fd) { revents |= EPOLLOUT; }
                    } else if is_eventfd(fd) {
                        revents |= EPOLLOUT; // eventfd always writable
                    } else if fd < rux_fs::fdtable::MAX_FDS && (*fdt::FD_TABLE)[fd].is_pipe && (*fdt::FD_TABLE)[fd].pipe_write {
                        revents |= EPOLLOUT; // write end of pipe always writable (simplified)
                    } else if !is_timerfd(fd) {
                        revents |= EPOLLOUT; // regular files always writable
                    }
                }
                if revents != 0 {
                    let out = events_ptr + ready * 12;
                    *(out as *mut u32) = revents;
                    *((out + 4) as *mut u64) = e.data;
                    ready += 1;
                }
            }
        }
        if ready > 0 { return ready as isize; }
        if timeout == 0 { return 0; } // non-blocking
        unsafe { use rux_arch::HaltOps; crate::arch::Arch::halt_until_interrupt(); }
    }
    0
}

// ── eventfd ────────────────────────────────────────────────────────

const MAX_EVENTFD: usize = 8;

struct EventFdSlot {
    active: bool,
    fd: usize,
    counter: u64,
    semaphore: bool, // EFD_SEMAPHORE: read returns 1, decrements by 1
}

static mut EVENTFDS: [EventFdSlot; MAX_EVENTFD] = {
    const EMPTY: EventFdSlot = EventFdSlot { active: false, fd: 0, counter: 0, semaphore: false };
    [EMPTY; MAX_EVENTFD]
};

/// eventfd2(initval, flags) → fd
pub fn eventfd2(initval: usize, flags: usize) -> isize {
    const EFD_SEMAPHORE: usize = 1;
    unsafe {
        let idx = match (0..MAX_EVENTFD).find(|&i| !EVENTFDS[i].active) {
            Some(i) => i,
            None => return crate::errno::ENOMEM,
        };
        let fd = alloc_virtual_fd(flags);
        if fd < 0 { return fd; }
        EVENTFDS[idx] = EventFdSlot {
            active: true, fd: fd as usize,
            counter: initval as u64,
            semaphore: flags & EFD_SEMAPHORE != 0,
        };
        fd
    }
}

fn find_eventfd(fd: usize) -> Option<usize> {
    unsafe { (0..MAX_EVENTFD).find(|&i| EVENTFDS[i].active && EVENTFDS[i].fd == fd) }
}

/// Check if fd is an eventfd.
pub fn is_eventfd(fd: usize) -> bool { find_eventfd(fd).is_some() }

/// Read from eventfd: returns 8-byte u64 counter value, resets to 0.
/// With EFD_SEMAPHORE: returns 1, decrements counter by 1.
pub fn eventfd_read(fd: usize, buf: usize) -> isize {
    let idx = match find_eventfd(fd) {
        Some(i) => i,
        None => return crate::errno::EBADF,
    };
    unsafe {
        blocking_read_u64(fd, buf, 30_000, || {
            if EVENTFDS[idx].counter > 0 {
                Some(if EVENTFDS[idx].semaphore {
                    EVENTFDS[idx].counter -= 1; 1u64
                } else {
                    let v = EVENTFDS[idx].counter;
                    EVENTFDS[idx].counter = 0; v
                })
            } else { None }
        })
    }
}

/// Write to eventfd: adds u64 value to counter.
pub fn eventfd_write(fd: usize, buf: usize) -> isize {
    let idx = match find_eventfd(fd) {
        Some(i) => i,
        None => return crate::errno::EBADF,
    };
    unsafe {
        let val = *(buf as *const u64);
        if val == u64::MAX { return crate::errno::EINVAL; }
        let new_val = EVENTFDS[idx].counter.saturating_add(val);
        if new_val == u64::MAX { return crate::errno::EAGAIN; } // would overflow
        EVENTFDS[idx].counter = new_val;
        8
    }
}

/// Close an eventfd slot.
pub fn eventfd_close(fd: usize) {
    if let Some(idx) = find_eventfd(fd) {
        unsafe { EVENTFDS[idx].active = false; }
    }
}

/// Check if eventfd has data (counter > 0) — for poll/epoll.
pub fn eventfd_has_data(fd: usize) -> bool {
    find_eventfd(fd).map(|i| unsafe { EVENTFDS[i].counter > 0 }).unwrap_or(false)
}

// ── timerfd ────────────────────────────────────────────────────────

const MAX_TIMERFD: usize = 4;

struct TimerFdSlot {
    active: bool,
    fd: usize,
    /// Interval in nanoseconds (0 = one-shot).
    interval_ns: u64,
    /// Next expiry in kernel ticks (milliseconds).
    next_expiry_ms: u64,
    /// Number of expirations since last read.
    expirations: u64,
}

static mut TIMERFDS: [TimerFdSlot; MAX_TIMERFD] = {
    const EMPTY: TimerFdSlot = TimerFdSlot {
        active: false, fd: 0, interval_ns: 0, next_expiry_ms: 0, expirations: 0,
    };
    [EMPTY; MAX_TIMERFD]
};

/// timerfd_create(clockid, flags) → fd
pub fn timerfd_create(_clockid: usize, flags: usize) -> isize {
    unsafe {
        let idx = match (0..MAX_TIMERFD).find(|&i| !TIMERFDS[i].active) {
            Some(i) => i,
            None => return crate::errno::ENOMEM,
        };
        let fd = alloc_virtual_fd(flags);
        if fd < 0 { return fd; }
        TIMERFDS[idx] = TimerFdSlot {
            active: true, fd: fd as usize, interval_ns: 0, next_expiry_ms: 0, expirations: 0,
        };
        fd
    }
}

fn find_timerfd(fd: usize) -> Option<usize> {
    unsafe { (0..MAX_TIMERFD).find(|&i| TIMERFDS[i].active && TIMERFDS[i].fd == fd) }
}

pub fn is_timerfd(fd: usize) -> bool { find_timerfd(fd).is_some() }

/// timerfd_settime(fd, flags, new_value_ptr, old_value_ptr) → 0
/// new_value is struct itimerspec { it_interval: timespec, it_value: timespec }
pub fn timerfd_settime(fd: usize, _flags: usize, new_ptr: usize, old_ptr: usize) -> isize {
    if crate::uaccess::validate_user_ptr(new_ptr, 32).is_err() { return crate::errno::EFAULT; }
    let idx = match find_timerfd(fd) {
        Some(i) => i,
        None => return crate::errno::EBADF,
    };
    unsafe {
        // Write old value if requested
        if old_ptr != 0 {
            if crate::uaccess::validate_user_ptr(old_ptr, 32).is_err() { return crate::errno::EFAULT; }
            // Write zeros (simplified)
            core::ptr::write_bytes(old_ptr as *mut u8, 0, 32);
        }
        // Read new itimerspec: { interval: {sec, nsec}, value: {sec, nsec} }
        let interval_sec: u64 = crate::uaccess::get_user(new_ptr);
        let interval_nsec: u64 = crate::uaccess::get_user(new_ptr + 8);
        let value_sec: u64 = crate::uaccess::get_user(new_ptr + 16);
        let value_nsec: u64 = crate::uaccess::get_user(new_ptr + 24);

        let interval_ns = interval_sec * 1_000_000_000 + interval_nsec;
        let value_ns = value_sec * 1_000_000_000 + value_nsec;

        use rux_arch::TimerOps;
        let now_ms = crate::arch::Arch::ticks();

        TIMERFDS[idx].interval_ns = interval_ns;
        TIMERFDS[idx].expirations = 0;
        if value_ns == 0 {
            // Disarm
            TIMERFDS[idx].next_expiry_ms = 0;
        } else {
            TIMERFDS[idx].next_expiry_ms = now_ms + (value_ns / 1_000_000).max(1);
        }
    }
    0
}

/// timerfd_gettime(fd, curr_value_ptr) → 0
pub fn timerfd_gettime(fd: usize, value_ptr: usize) -> isize {
    if crate::uaccess::validate_user_ptr(value_ptr, 32).is_err() { return crate::errno::EFAULT; }
    let idx = match find_timerfd(fd) {
        Some(i) => i,
        None => return crate::errno::EBADF,
    };
    unsafe {
        // Write interval
        let int_sec = TIMERFDS[idx].interval_ns / 1_000_000_000;
        let int_nsec = TIMERFDS[idx].interval_ns % 1_000_000_000;
        crate::uaccess::put_user(value_ptr, int_sec);
        crate::uaccess::put_user(value_ptr + 8, int_nsec);

        // Write remaining time
        use rux_arch::TimerOps;
        let now_ms = crate::arch::Arch::ticks();
        let remaining_ms = TIMERFDS[idx].next_expiry_ms.saturating_sub(now_ms);
        let rem_sec = remaining_ms / 1000;
        let rem_nsec = (remaining_ms % 1000) * 1_000_000;
        crate::uaccess::put_user(value_ptr + 16, rem_sec);
        crate::uaccess::put_user(value_ptr + 24, rem_nsec);
    }
    0
}

/// Read from timerfd: returns u64 count of expirations since last read.
/// Blocks until at least one expiration.
pub fn timerfd_read(fd: usize, buf: usize) -> isize {
    let idx = match find_timerfd(fd) {
        Some(i) => i,
        None => return crate::errno::EBADF,
    };
    unsafe {
        blocking_read_u64(fd, buf, 60_000, || {
            use rux_arch::TimerOps;
            let now_ms = crate::arch::Arch::ticks();
            if TIMERFDS[idx].next_expiry_ms > 0 && now_ms >= TIMERFDS[idx].next_expiry_ms {
                TIMERFDS[idx].expirations += 1;
                if TIMERFDS[idx].interval_ns > 0 {
                    TIMERFDS[idx].next_expiry_ms = now_ms + (TIMERFDS[idx].interval_ns / 1_000_000).max(1);
                } else {
                    TIMERFDS[idx].next_expiry_ms = 0;
                }
            }
            if TIMERFDS[idx].expirations > 0 {
                let val = TIMERFDS[idx].expirations;
                TIMERFDS[idx].expirations = 0;
                Some(val)
            } else { None }
        })
    }
}

pub fn timerfd_close(fd: usize) {
    if let Some(idx) = find_timerfd(fd) {
        unsafe { TIMERFDS[idx].active = false; }
    }
}

pub fn timerfd_has_data(fd: usize) -> bool {
    find_timerfd(fd).map(|idx| unsafe {
        use rux_arch::TimerOps;
        let now_ms = crate::arch::Arch::ticks();
        TIMERFDS[idx].next_expiry_ms > 0 && now_ms >= TIMERFDS[idx].next_expiry_ms
            || TIMERFDS[idx].expirations > 0
    }).unwrap_or(false)
}

// ── MAP_SHARED file write-back tracking ────────────────────────────

const MAX_SHARED_MAPS: usize = 32;

struct SharedMapping {
    active: bool,
    va: usize,      // virtual address of mapping
    len: usize,     // length in bytes
    ino: u64,       // file inode
    offset: u64,    // file offset
}

static mut SHARED_MAPS: [SharedMapping; MAX_SHARED_MAPS] = {
    const EMPTY: SharedMapping = SharedMapping { active: false, va: 0, len: 0, ino: 0, offset: 0 };
    [EMPTY; MAX_SHARED_MAPS]
};

/// Write back all MAP_SHARED pages that overlap [addr, addr+len).
unsafe fn writeback_shared(addr: usize, len: usize) {
    use rux_fs::FileSystem;
    let fs = crate::kstate::fs();
    for m in SHARED_MAPS.iter_mut() {
        if !m.active { continue; }
        // Check overlap
        let m_end = m.va + m.len;
        let r_end = addr + len;
        if m.va < r_end && addr < m_end {
            // Write back the entire mapping to the file
            let src = core::slice::from_raw_parts(m.va as *const u8, m.len);
            let _ = fs.write(m.ino, m.offset, src);
            m.active = false;
        }
    }
}

/// msync(addr, len, flags) — write back MAP_SHARED pages.
pub unsafe fn msync(addr: usize, len: usize) {
    writeback_shared(addr, (len + 0xFFF) & !0xFFF);
}

/// mmap(addr, len, prot, flags, fd, offset) — POSIX.1
///
/// aarch64: Clean D-cache and invalidate I-cache for a virtual address range.
/// Required after writing data that will be executed (mmap PROT_EXEC, ELF loading).
/// Uses per-line DC CVAU + IC IVAU for precise maintenance, then DSB+ISB.
#[cfg(target_arch = "aarch64")]
unsafe fn sync_icache(va: usize, len: usize) {
    // CTR_EL0.DminLine and IminLine give cache line sizes
    // QEMU virt: typically 64 bytes, but read dynamically for correctness
    let ctr: u64;
    core::arch::asm!("mrs {}, ctr_el0", out(reg) ctr, options(nostack));
    let dline = 4 << ((ctr >> 16) & 0xF);  // D-cache minimum line (bytes)
    let iline = 4 << (ctr & 0xF);          // I-cache minimum line (bytes)

    // Clean D-cache to point of unification
    let mut addr = va & !(dline - 1);
    while addr < va + len {
        core::arch::asm!("dc cvau, {}", in(reg) addr, options(nostack));
        addr += dline;
    }
    core::arch::asm!("dsb ish", options(nostack));

    // Invalidate I-cache to point of unification
    let mut addr = va & !(iline - 1);
    while addr < va + len {
        core::arch::asm!("ic ivau, {}", in(reg) addr, options(nostack));
        addr += iline;
    }
    core::arch::asm!("dsb ish", "isb", options(nostack));
}

/// Supports MAP_ANONYMOUS, MAP_PRIVATE file-backed, and MAP_SHARED file-backed
/// (with write-back on munmap).
pub fn mmap(addr: usize, len: usize, prot: usize, mmap_flags: usize, fd: usize, offset: usize) -> isize {
    const MAP_FIXED: usize = 0x10;
    const MAP_ANONYMOUS: usize = 0x20;
    const MAP_SHARED: usize = 0x01;
    const PROT_READ: usize = 1;
    const PROT_WRITE: usize = 2;
    const PROT_EXEC: usize = 4;

    if len == 0 { return crate::errno::EINVAL; }
    // Guard against integer overflow in alignment arithmetic
    use rux_arch::MemoryLayout;
    if len > crate::arch::Arch::USER_ADDR_LIMIT as usize { return crate::errno::ENOMEM; }

    unsafe {
        let aligned_len = (len + 0xFFF) & !0xFFF;

        let result = if mmap_flags & MAP_FIXED != 0 && addr != 0 {
            let fixed_addr = addr & !0xFFF;
            // Unmap existing pages to avoid double-mapping (ld.so uses MAP_FIXED
            // to replace segments at exact addresses).
            munmap(fixed_addr, aligned_len);
            fixed_addr
        } else {
            let r = super::PROCESS.mmap_base;
            super::PROCESS.mmap_base += aligned_len;
            r
        };

        // Build page flags from prot
        let mut pg_flags = rux_mm::MappingFlags::USER;
        if prot & PROT_READ != 0 { pg_flags = pg_flags.or(rux_mm::MappingFlags::READ); }
        if prot & PROT_WRITE != 0 { pg_flags = pg_flags.or(rux_mm::MappingFlags::WRITE); }
        if prot & PROT_EXEC != 0 { pg_flags = pg_flags.or(rux_mm::MappingFlags::EXECUTE); }
        if prot == 0 { pg_flags = pg_flags.or(rux_mm::MappingFlags::READ); }

        if mmap_flags & MAP_ANONYMOUS == 0 && fd < rux_fs::fdtable::MAX_FDS {
            // File-backed: allocate pages and read file data
            use rux_fs::FileSystem;
            let fs = crate::kstate::fs();
            let ino = (*rux_fs::fdtable::FD_TABLE)[fd].ino;
            if (*rux_fs::fdtable::FD_TABLE)[fd].active && ino != 0 {
                super::map_user_pages(result, result + aligned_len, pg_flags);
                let file_offset = offset as u64;
                let dst = core::slice::from_raw_parts_mut(result as *mut u8, len);
                let _ = fs.read(ino, file_offset, dst);

                // aarch64: flush I-cache after writing executable pages.
                // aarch64 has separate I/D caches — data written via store
                // instructions is visible in D-cache but the I-cache may
                // still hold stale entries. Without this, executing freshly
                // mmap'd .so code reads garbage instructions.
                #[cfg(target_arch = "aarch64")]
                if prot & PROT_EXEC != 0 {
                    sync_icache(result, aligned_len);
                }

                // Track MAP_SHARED mappings for write-back on munmap
                if mmap_flags & MAP_SHARED != 0 {
                    if let Some(slot) = SHARED_MAPS.iter_mut().find(|s| !s.active) {
                        *slot = SharedMapping {
                            active: true, va: result, len, ino, offset: file_offset,
                        };
                    }
                }
            }
        } else if mmap_flags & MAP_FIXED != 0 {
            // MAP_FIXED anonymous (BSS replacement by ld.so): allocate eagerly
            // because the old pages were just munmap'd and accessed immediately
            super::map_user_pages(result, result + aligned_len, pg_flags);
        }
        // Non-MAP_FIXED anonymous: lazy — demand pager maps zero pages on fault.
        // Saves hundreds of frames for malloc buffers, guard pages, etc.

        result as isize
    }
}

/// munmap(addr, length) — POSIX.1: unmap pages from address space.
/// Writes back MAP_SHARED pages before freeing.
/// COW-aware: only frees frames whose refcount reaches zero.
pub fn munmap(addr: usize, len: usize) -> isize {
    // Write back any MAP_SHARED file mappings in this range
    unsafe { writeback_shared(addr, (len + 0xFFF) & !0xFFF); }
    if addr & 0xFFF != 0 { return crate::errno::EINVAL; } // must be page-aligned
    unsafe {
        let alloc = crate::kstate::alloc();
        let mut upt = super::current_user_page_table();

        let aligned_len = (len + 0xFFF) & !0xFFF;
        let mut va = addr;
        while va < addr + aligned_len {
            if let Ok(pa) = upt.translate(rux_klib::VirtAddr::new(va)) {
                let _ = upt.unmap_4k(rux_klib::VirtAddr::new(va));
                let page_pa = rux_klib::PhysAddr::new(pa.as_usize() & !0xFFF);
                use rux_mm::FrameAllocator;
                // COW-aware: only free if refcount drops to zero
                if page_pa.as_usize() >= alloc.alloc_base().as_usize() {
                    if crate::cow::dec_ref(page_pa) {
                        alloc.dealloc(page_pa, rux_mm::PageSize::FourK);
                    }
                }
            }
            va += 4096;
        }
    }
    0
}

/// mremap(old_addr, old_size, new_size, flags) — Linux.
/// Grows or shrinks a memory mapping. MREMAP_MAYMOVE allows relocation.
pub fn mremap(old_addr: usize, old_size: usize, new_size: usize, flags: usize) -> isize {
    const MREMAP_MAYMOVE: usize = 1;
    if old_addr & 0xFFF != 0 { return crate::errno::EINVAL; }
    if new_size == 0 { return crate::errno::EINVAL; }

    let old_aligned = (old_size + 0xFFF) & !0xFFF;
    let new_aligned = (new_size + 0xFFF) & !0xFFF;

    if new_aligned <= old_aligned {
        // Shrinking: unmap excess pages
        if new_aligned < old_aligned {
            munmap(old_addr + new_aligned, old_aligned - new_aligned);
        }
        return old_addr as isize;
    }

    // Growing: try to extend in place first
    let grow_start = old_addr + old_aligned;
    let grow_end = old_addr + new_aligned;

    // Check if the extension area is free (no existing mappings)
    let can_grow_in_place = unsafe {
        let upt = super::current_user_page_table();
        (grow_start..grow_end).step_by(4096).all(|va| {
            upt.translate(rux_klib::VirtAddr::new(va)).is_err()
        })
    };

    if can_grow_in_place {
        // Extend in place — map new pages (demand-paged, no immediate alloc)
        // The demand pager will allocate on first access.
        return old_addr as isize;
    }

    // Can't grow in place — relocate if MREMAP_MAYMOVE
    if flags & MREMAP_MAYMOVE == 0 {
        return crate::errno::ENOMEM;
    }

    // Allocate new region from mmap base
    unsafe {
        let new_addr = super::PROCESS.mmap_base;
        super::PROCESS.mmap_base += new_aligned;

        // Map new pages
        let pg_flags = rux_mm::MappingFlags::READ
            .or(rux_mm::MappingFlags::WRITE)
            .or(rux_mm::MappingFlags::USER);
        super::map_user_pages(new_addr, new_addr + new_aligned, pg_flags);

        // Copy old data
        let copy_len = old_aligned.min(new_aligned);
        core::ptr::copy_nonoverlapping(
            old_addr as *const u8,
            new_addr as *mut u8,
            copy_len,
        );

        // Unmap old region
        munmap(old_addr, old_aligned);

        new_addr as isize
    }
}

// ── Futex ──────────────────────────────────────────────────────────────

/// futex(uaddr, op, val, ...) — Linux: fast userspace mutex.
/// Supports FUTEX_WAIT (block if *uaddr == val) and FUTEX_WAKE (wake N waiters).
pub fn futex(uaddr: usize, op: usize, val: usize) -> isize {
    const FUTEX_WAIT: usize = 0;
    const FUTEX_WAKE: usize = 1;

    match op & 0x7F { // mask off FUTEX_PRIVATE_FLAG
        FUTEX_WAIT => futex_wait(uaddr, val as u32),
        FUTEX_WAKE => futex_wake(uaddr, val),
        _ => 0, // unsupported ops succeed silently
    }
}

fn futex_wait(uaddr: usize, expected: u32) -> isize {
    unsafe {
        use crate::task_table::*;

        // Validate user pointer
        if uaddr < 0x1000 || uaddr >= 0x8000_0000_0000 {
            return crate::errno::EAGAIN;
        }

        // Check if the page is mapped before reading. If not, return EAGAIN
        // (the caller will retry after the page is faulted in).
        let upt = crate::syscall::current_user_page_table();
        if upt.translate(rux_klib::VirtAddr::new(uaddr & !0xFFF)).is_err() {
            return crate::errno::EAGAIN;
        }

        // Atomic check: if value changed since caller checked, return EAGAIN
        let p = uaddr as *const u8;
        let val: u32 = (*p.add(0) as u32) | ((*p.add(1) as u32) << 8)
                      | ((*p.add(2) as u32) << 16) | ((*p.add(3) as u32) << 24);
        if val != expected {
            return crate::errno::EAGAIN;
        }

        // Block until woken by FUTEX_WAKE
        let idx = current_task_idx();
        TASK_TABLE[idx].state = TaskState::WaitingForFutex;
        TASK_TABLE[idx].futex_addr = uaddr;
        let sched = crate::scheduler::get();
        sched.tasks[idx].entity.state = rux_sched::TaskState::Interruptible;
        sched.dequeue_current();
        sched.schedule();
        0
    }
}

/// Wake up to `max_wake` tasks waiting on the futex at `uaddr`.
/// Returns the number of tasks woken.
pub fn futex_wake(uaddr: usize, max_wake: usize) -> isize {
    unsafe {
        use crate::task_table::*;

        let sched = crate::scheduler::get();
        let mut woken = 0usize;
        for i in 0..MAX_PROCS {
            if woken >= max_wake { break; }
            if TASK_TABLE[i].active
                && TASK_TABLE[i].state == TaskState::WaitingForFutex
                && TASK_TABLE[i].futex_addr == uaddr
            {
                TASK_TABLE[i].state = TaskState::Ready;
                sched.wake_task(i);
                woken += 1;
            }
        }
        woken as isize
    }
}

/// pselect6(nfds, readfds, writefds, exceptfds, timeout, sigmask) — POSIX.1
/// Minimal implementation: checks socket FDs for readiness.
pub fn pselect6(nfds: usize, readfds_ptr: usize, writefds_ptr: usize, _exceptfds_ptr: usize, timeout_ptr: usize) -> isize {
    let nfds = nfds.min(64);

    // Parse timeout
    let timeout_ms = if timeout_ptr >= 0x10000 && timeout_ptr < 0x8000_0000_0000 {
        unsafe {
            let sec: u64 = crate::uaccess::get_user(timeout_ptr);
            let nsec: u64 = crate::uaccess::get_user(timeout_ptr + 8);
            let ms = sec * 1000 + nsec / 1_000_000;
            if ms > 30_000 { 30_000 } else { ms as usize }
        }
    } else { 5_000 };

    let read_set = if readfds_ptr != 0 && crate::uaccess::validate_user_ptr(readfds_ptr, 8).is_ok() {
        unsafe { *(readfds_ptr as *const u64) }
    } else { 0 };
    let write_set = if writefds_ptr != 0 && crate::uaccess::validate_user_ptr(writefds_ptr, 8).is_ok() {
        unsafe { *(writefds_ptr as *const u64) }
    } else { 0 };

    let has_sockets = (0..nfds).any(|fd| {
        ((read_set | write_set) & (1u64 << fd)) != 0
            && fd < rux_fs::fdtable::MAX_FDS
            && super::socket::is_socket(fd)
    });

    let max_iters = if has_sockets && timeout_ms > 0 { timeout_ms.min(30_000) } else { 1 };

    for _ in 0..max_iters {
        #[cfg(feature = "net")]
        if has_sockets {
            unsafe {
                use rux_arch::TimerOps;
                rux_net::poll(crate::arch::Arch::ticks());
            }
        }

        let mut ready = 0i32;
        let mut out_read: u64 = 0;
        let mut out_write: u64 = 0;

        for fd in 0..nfds {
            let bit = 1u64 << fd;
            if read_set & bit != 0 {
                if fd <= 2 || !super::socket::is_socket(fd) {
                    // Console/file FDs are always ready
                    out_read |= bit;
                    ready += 1;
                } else if super::socket::socket_has_data(fd) {
                    out_read |= bit;
                    ready += 1;
                }
            }
            if write_set & bit != 0 {
                if !super::socket::is_socket(fd) || super::socket::socket_can_write(fd) {
                    out_write |= bit;
                    ready += 1;
                }
            }
        }

        if ready > 0 {
            if readfds_ptr != 0 { unsafe { *(readfds_ptr as *mut u64) = out_read; } }
            if writefds_ptr != 0 { unsafe { *(writefds_ptr as *mut u64) = out_write; } }
            return ready as isize;
        }

        unsafe { use rux_arch::HaltOps; crate::arch::Arch::halt_until_interrupt(); }
    }

    // Timeout: clear all sets
    if readfds_ptr != 0 { unsafe { *(readfds_ptr as *mut u64) = 0; } }
    if writefds_ptr != 0 { unsafe { *(writefds_ptr as *mut u64) = 0; } }
    0
}

/// mprotect(addr, len, prot) — POSIX.1: change page protection.
pub fn mprotect(addr: usize, len: usize, prot: usize) -> isize {
    if addr & 0xFFF != 0 { return crate::errno::EINVAL; }
    use rux_arch::MemoryLayout;
    if len > crate::arch::Arch::USER_ADDR_LIMIT as usize { return crate::errno::EINVAL; }
    unsafe {
        let upt = super::current_user_page_table();
        let aligned_len = (len + 0xFFF) & !0xFFF;

        let mut flags = rux_mm::MappingFlags::USER.or(rux_mm::MappingFlags::READ);
        if prot & 2 != 0 { flags = flags.or(rux_mm::MappingFlags::WRITE); }
        if prot & 4 != 0 { flags = flags.or(rux_mm::MappingFlags::EXECUTE); }

        let pte_flags = crate::arch::PageTable::pte_flags(flags);

        let mut va = addr;
        while va < addr + aligned_len {
            let virt = rux_klib::VirtAddr::new(va);
            if let Ok(pa) = upt.translate(virt) {
                let pa_page = rux_klib::PhysAddr::new(pa.as_usize() & !0xFFF);
                upt.remap(virt, pa_page, pte_flags);
            }
            va += 4096;
        }
    }
    0
}

/// poll(fds, nfds, timeout) — POSIX.1: check fd readiness.
/// Returns number of fds with events, or 0 on timeout.
/// ppoll wrapper: reads timeout from timespec pointer
pub fn ppoll(fds_ptr: usize, nfds: usize, timeout_ptr: usize, _sigmask: usize) -> isize {
    if fds_ptr != 0 && nfds > 0 {
        if crate::uaccess::validate_user_ptr(fds_ptr, nfds.min(64) * 8).is_err() { return crate::errno::EFAULT; }
    }
    let timeout_ms = if timeout_ptr >= 0x10000 && timeout_ptr < 0x8000_0000_0000 {
        unsafe {
            let sec: u64 = crate::uaccess::get_user(timeout_ptr);
            let nsec: u64 = crate::uaccess::get_user(timeout_ptr + 8);
            let ms = sec * 1000 + nsec / 1_000_000;
            if ms > 30_000 { 30_000 } else { ms as usize }
        }
    } else { 5_000 }; // no timeout / invalid → 5s default (responsive enough for DNS)
    poll(fds_ptr, nfds, timeout_ms)
}

pub fn poll(fds_ptr: usize, nfds: usize, timeout_ms: usize) -> isize {
    if fds_ptr == 0 || nfds == 0 { return 0; }

    // Check if we have blocking-capable fds (sockets, eventfd, timerfd)
    let needs_blocking = unsafe {
        (0..nfds.min(64)).any(|i| {
            let entry = (fds_ptr + i * 8) as *const u8;
            let fd = *(entry as *const i32) as usize;
            fd < rux_fs::fdtable::MAX_FDS && (super::socket::is_socket(fd) || is_eventfd(fd) || is_timerfd(fd))
        })
    };

    let max_iters = if needs_blocking && timeout_ms > 0 {
        timeout_ms.min(30_000)
    } else { 1 };

    for _attempt in 0..max_iters {
        // Poll smoltcp (drains all available frames in one call)
        #[cfg(feature = "net")]
        if needs_blocking {
            unsafe {
                use rux_arch::TimerOps;
                rux_net::poll(crate::arch::Arch::ticks());
            }
        }

        unsafe {
            let mut ready = 0i32;
            for i in 0..nfds.min(64) {
            let entry = (fds_ptr + i * 8) as *mut u8;
            let fd = *(entry as *const i32) as usize;
            let events = *((entry as usize + 4) as *const i16);
            let revents_ptr = (entry as usize + 6) as *mut i16;

            if fd >= 64 { *revents_ptr = 0; continue; }

            let f = &(*fdt::FD_TABLE)[fd];
            let mut revents: i16 = 0;
            if f.active && f.is_socket {
                // Socket: check actual readiness
                if events & 4 != 0 {
                    // POLLOUT: ready if connected (not still in SYN_SENT)
                    if super::socket::socket_can_write(fd) {
                        revents |= 4;
                    }
                }
                if events & 1 != 0 {
                    // POLLIN: check if data is available
                    if super::socket::socket_has_data(fd) {
                        revents |= 1;
                    }
                }
            } else if f.active && is_eventfd(fd) {
                // eventfd: readable if counter > 0, always writable
                if events & 1 != 0 && eventfd_has_data(fd) { revents |= 1; }
                if events & 4 != 0 { revents |= 4; }
            } else if f.active && is_timerfd(fd) {
                // timerfd: readable if expired
                if events & 1 != 0 && timerfd_has_data(fd) { revents |= 1; }
            } else if f.active || fd <= 2 {
                // Console fds and regular file fds are always ready
                if events & 1 != 0 { revents |= 1; }   // POLLIN
                if events & 4 != 0 { revents |= 4; }   // POLLOUT
            } else {
                revents = 0x20; // POLLNVAL
            }

            *revents_ptr = revents;
            if revents != 0 { ready += 1; }
        }
        if ready > 0 { return ready as isize; }
        } // unsafe

        // Wait for next timer tick (yields CPU, allows timer ISR to process packets)
        unsafe { use rux_arch::HaltOps; crate::arch::Arch::halt_until_interrupt(); }
    }
    0 // timeout
}
