//! Memory mapping, poll, and epoll syscalls.

use rux_fs::fdtable as fdt;

// ── Shared helpers for virtual fd types (eventfd, timerfd, epoll) ──

/// Allocate an fd from the fd table, applying O_NONBLOCK if set in flags.
/// Returns the fd number on success, or negative errno.
unsafe fn alloc_virtual_fd(flags: usize) -> isize {
    let fd_table = &mut *fdt::fd_table();
    let fd = match (fdt::FIRST_FILE_FD..fdt::MAX_FDS).find(|&f| !fd_table[f].active) {
        Some(f) => f,
        None => return crate::errno::ENOMEM,
    };
    fd_table[fd] = fdt::EMPTY_FD;
    fd_table[fd].active = true;
    fd_table[fd].flags = 2; // O_RDWR — virtual fds are always readable+writable
    if flags & 0x800 != 0 { fd_table[fd].flags |= 0x800; } // O_NONBLOCK / EFD_NONBLOCK / TFD_NONBLOCK
    fd as isize
}

/// Yield the current task to allow other tasks to run during blocking syscalls.
///
/// When multiple tasks are active, uses the scheduler: puts current task to
/// sleep for 1ms, lets others run, then wakes up to re-poll.
///
/// When only one task is active (single-process scenario), falls back to
/// halt_until_interrupt which is more efficient (wakes on next IRQ, ~1ms).
pub(crate) unsafe fn yield_1ms() {
    // Count tasks that are actually READY to run (not sleeping/blocked).
    // Only yield if another task genuinely needs CPU time.
    let my_idx = crate::task_table::current_task_idx();
    let others_ready = crate::task_table::TASK_TABLE[1..].iter().enumerate()
        .any(|(i, t)| {
            let idx = i + 1; // skip slot 0 (idle)
            idx != my_idx && t.active && t.state == crate::task_table::TaskState::Ready
        });

    if others_ready {
        // Multiple tasks: yield via scheduler so they can run
        let task_idx = crate::task_table::current_task_idx();
        use rux_arch::TimerOps;
        let wake_at = crate::arch::Arch::ticks() + 1;
        crate::task_table::TASK_TABLE[task_idx].state = crate::task_table::TaskState::Sleeping;
        crate::task_table::TASK_TABLE[task_idx].wake_at = wake_at;
        let sched = crate::scheduler::get();
        sched.tasks[task_idx].entity.state = rux_sched::TaskState::Interruptible;
        sched.dequeue_current();
        sched.need_resched |= 1u64 << unsafe { crate::percpu::cpu_id() as u32 };
        sched.schedule();
    } else {
        // Single task: HLT until next interrupt (~1ms timer tick)
        use rux_arch::HaltOps;
        crate::arch::Arch::halt_until_interrupt();
    }
}

/// Blocking read that returns a u64 value. Polls `check` up to `max_iters`
/// times, writing the result to `buf` when ready. Respects O_NONBLOCK on fd.
unsafe fn blocking_read_u64<F>(fd: usize, buf: usize, max_iters: u32, mut check: F) -> isize
where F: FnMut() -> Option<u64>
{
    let nonblock = fd < fdt::MAX_FDS && ((*fdt::fd_table())[fd].flags & 0x800) != 0;
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

const MAX_EPOLL: usize = 8;
const MAX_EPOLL_FDS: usize = 64;

#[derive(Clone, Copy)]
struct EpollEntry {
    fd: i32,
    events: u32,
    data: u64,
    fired: bool, // for EPOLLONESHOT: true after first delivery, suppresses further reports
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
            entries: [EpollEntry { fd: -1, events: 0, data: 0, fired: false }; MAX_EPOLL_FDS],
            count: 0,
            epoll_fd: 0,
        }
    }
}

static mut EPOLL: [EpollInstance; MAX_EPOLL] = {
    const E: EpollInstance = EpollInstance::empty();
    [E; MAX_EPOLL]
};

/// epoll_create1(flags) → fd
pub fn epoll_create(_flags: usize) -> isize {
    unsafe {
        let idx = match (0..MAX_EPOLL).find(|&i| !EPOLL[i].active) {
            Some(i) => i,
            None => return crate::errno::ENOMEM,
        };
        // Allocate an FD for this epoll instance
        let fd_table = &mut *fdt::fd_table();
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
                let events = core::ptr::read_unaligned(event_ptr as *const u32);
                let data = core::ptr::read_unaligned((event_ptr + 4) as *const u64);
                let slot = ep.count;
                ep.entries[slot] = EpollEntry { fd: fd as i32, events, data, fired: false };
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
                let events = core::ptr::read_unaligned(event_ptr as *const u32);
                let data = core::ptr::read_unaligned((event_ptr + 4) as *const u64);
                if let Some(pos) = ep.entries[..ep.count].iter().position(|e| e.fd == fd as i32) {
                    ep.entries[pos].events = events;
                    ep.entries[pos].data = data;
                    ep.entries[pos].fired = false; // re-arm EPOLLONESHOT
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

    let timeout_ms = if timeout as isize == -1 { 600_000usize } else { timeout as usize };
    let has_sockets = unsafe {
        let ep = &EPOLL[idx];
        ep.entries[..ep.count].iter().any(|e| e.fd >= 0 && super::socket::is_socket(e.fd as usize))
    };

    // Compute absolute deadline for scheduler-based sleeping
    let deadline = if timeout_ms > 0 {
        use rux_arch::TimerOps;
        unsafe { crate::arch::Arch::ticks() + timeout_ms as u64 }
    } else {
        0
    };

    loop {
        #[cfg(feature = "net")]
        if has_sockets {
            unsafe { use rux_arch::TimerOps; rux_net::poll(crate::arch::Arch::ticks()); }
        }

        let mut ready = 0usize;
        unsafe {
            let ep = &mut EPOLL[idx];
            const EPOLLIN: u32 = 0x001;
            const EPOLLOUT: u32 = 0x004;
            const EPOLLERR: u32 = 0x008;
            const EPOLLHUP: u32 = 0x010;
            const EPOLLRDHUP: u32 = 0x2000;
            #[allow(dead_code)]
            const EPOLLET: u32 = 1 << 31;
            const EPOLLONESHOT: u32 = 1 << 30;

            for i in 0..ep.count {
                if ready >= out_count { break; }
                let e = &ep.entries[i];
                let fd = e.fd as usize;

                // EPOLLONESHOT: skip if already fired (must EPOLL_CTL_MOD to re-arm)
                if e.events & EPOLLONESHOT != 0 && e.fired { continue; }

                let mut revents: u32 = 0;
                if e.events & EPOLLIN != 0 {
                    if super::socket::is_socket(fd) {
                        if super::socket::socket_has_data(fd) { revents |= EPOLLIN; }
                    } else if is_eventfd(fd) {
                        if eventfd_has_data(fd) { revents |= EPOLLIN; }
                    } else if is_timerfd(fd) {
                        if timerfd_has_data(fd) { revents |= EPOLLIN; }
                    } else if is_signalfd(fd) {
                        if signalfd_has_data(fd) { revents |= EPOLLIN; }
                    } else if fd < rux_fs::fdtable::MAX_FDS && (*fdt::fd_table())[fd].is_pipe {
                        let pid = (*fdt::fd_table())[fd].pipe_id;
                        if crate::pipe::has_data(pid) { revents |= EPOLLIN; }
                        if crate::pipe::writers_closed(pid) { revents |= EPOLLHUP; }
                    } else if fd < rux_fs::fdtable::MAX_FDS && (*fdt::fd_table())[fd].is_console {
                        let tty = &*(&raw const crate::tty::TTY);
                        if tty.has_input() { revents |= EPOLLIN; }
                    } else {
                        revents |= EPOLLIN;
                    }
                }
                if e.events & EPOLLOUT != 0 {
                    if super::socket::is_socket(fd) {
                        if super::socket::socket_can_write(fd) { revents |= EPOLLOUT; }
                    } else if is_eventfd(fd) {
                        revents |= EPOLLOUT;
                    } else if fd < rux_fs::fdtable::MAX_FDS && (*fdt::fd_table())[fd].is_pipe && (*fdt::fd_table())[fd].pipe_write {
                        revents |= EPOLLOUT;
                    } else if !is_timerfd(fd) {
                        revents |= EPOLLOUT;
                    }
                }
                // EPOLLRDHUP: peer closed write side (half-close)
                if e.events & EPOLLRDHUP != 0 && super::socket::is_socket(fd) {
                    if !super::socket::socket_has_data(fd) && !super::socket::socket_can_write(fd) {
                        revents |= EPOLLRDHUP;
                    }
                }
                // EPOLLERR: always reported if fd is invalid
                if fd >= rux_fs::fdtable::MAX_FDS || (!(*fdt::fd_table())[fd].active && !super::socket::is_socket(fd)) {
                    revents |= EPOLLERR;
                }
                if revents != 0 {
                    let out = events_ptr + ready * 12;
                    core::ptr::write_unaligned(out as *mut u32, revents);
                    core::ptr::write_unaligned((out + 4) as *mut u64, e.data);
                    ready += 1;
                    // EPOLLONESHOT: mark as fired after first delivery
                    if e.events & EPOLLONESHOT != 0 {
                        ep.entries[i].fired = true;
                    }
                }
            }
        }
        if ready > 0 { return ready as isize; }
        if timeout == 0 { return 0; } // non-blocking

        // Check deadline
        if deadline > 0 {
            use rux_arch::TimerOps;
            if unsafe { crate::arch::Arch::ticks() } >= deadline {
                return 0; // timeout expired, no events
            }
        }

        // Sleep on poll wait queue until I/O event or timeout
        unsafe {
            let task_idx = crate::task_table::current_task_idx();
            crate::task_table::TASK_TABLE[task_idx].state =
                crate::task_table::TaskState::WaitingForPoll;
            use rux_arch::TimerOps;
            crate::task_table::TASK_TABLE[task_idx].wake_at =
                crate::arch::Arch::ticks() + timeout_ms.min(30_000) as u64;
            crate::task_table::poll_wait_register(task_idx);
            let sched = crate::scheduler::get();
            sched.tasks[task_idx].entity.state = rux_sched::TaskState::Interruptible;
            sched.dequeue_current();
            sched.need_resched |= 1u64 << crate::percpu::cpu_id() as u32;
            sched.schedule();

            // Woken — check if an unblocked signal is pending (return EINTR so post_syscall delivers it)
            let hot = &crate::task_table::TASK_TABLE[task_idx].signal_hot;
            let deliverable = hot.pending.0 & !hot.blocked.0;
            if deliverable != 0 {
                return crate::errno::EINTR;
            }
        }
    }
}

// ── eventfd ────────────────────────────────────────────────────────

const MAX_EVENTFD: usize = 16;

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

const MAX_TIMERFD: usize = 8;

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

// ── signalfd ──────────────────────────────────────────────────────

const MAX_SIGNALFD: usize = 8;

struct SignalFdSlot {
    active: bool,
    fd: usize,
    mask: u64, // signal mask (bit per signal, same as SignalSet)
}

static mut SIGNALFDS: [SignalFdSlot; MAX_SIGNALFD] = {
    const EMPTY: SignalFdSlot = SignalFdSlot { active: false, fd: 0, mask: 0 };
    [EMPTY; MAX_SIGNALFD]
};

fn find_signalfd(fd: usize) -> Option<usize> {
    unsafe { (0..MAX_SIGNALFD).find(|&i| SIGNALFDS[i].active && SIGNALFDS[i].fd == fd) }
}
pub fn is_signalfd(fd: usize) -> bool { find_signalfd(fd).is_some() }

/// signalfd4(fd, mask_ptr, flags) → fd
/// If fd == -1, allocate new signalfd. Otherwise update existing.
pub fn signalfd4(fd: usize, mask_ptr: usize, _flags: usize) -> isize {
    if crate::uaccess::validate_user_ptr(mask_ptr, 8).is_err() { return crate::errno::EFAULT; }
    let mask = unsafe { *(mask_ptr as *const u64) };

    unsafe {
        // Update existing signalfd
        if fd != usize::MAX { // -1 as usize
            if let Some(idx) = find_signalfd(fd) {
                SIGNALFDS[idx].mask = mask;
                return fd as isize;
            }
            return crate::errno::EINVAL;
        }

        // Allocate new signalfd
        let idx = match (0..MAX_SIGNALFD).find(|&i| !SIGNALFDS[i].active) {
            Some(i) => i,
            None => return crate::errno::ENOMEM,
        };

        let new_fd = alloc_virtual_fd(_flags);
        if new_fd < 0 { return new_fd; }

        SIGNALFDS[idx] = SignalFdSlot { active: true, fd: new_fd as usize, mask };
        new_fd
    }
}

/// Read from signalfd: returns struct signalfd_siginfo (128 bytes) per signal.
/// Blocks if no signal pending and fd is not O_NONBLOCK.
pub fn signalfd_read(fd: usize, buf: usize) -> isize {
    let idx = match find_signalfd(fd) {
        Some(i) => i,
        None => return crate::errno::EBADF,
    };
    if crate::uaccess::validate_user_ptr(buf, 128).is_err() { return crate::errno::EFAULT; }

    unsafe {
        let mask = SIGNALFDS[idx].mask;
        let hot = &mut (*super::process()).signal_hot;

        // Find a pending signal that matches the signalfd mask
        let mut pending_masked = hot.pending.0 & mask;
        if pending_masked == 0 {
            // Check O_NONBLOCK on the fd
            let f = &(*rux_fs::fdtable::fd_table())[fd];
            if f.flags & 0o4000 != 0 {
                return crate::errno::EAGAIN; // non-blocking
            }
            // Blocking: sleep until signal arrives or timeout
            let sig_deadline = {
                use rux_arch::TimerOps;
                crate::arch::Arch::ticks() + 30_000
            };
            loop {
                let task_idx = crate::task_table::current_task_idx();
                crate::task_table::TASK_TABLE[task_idx].state =
                    crate::task_table::TaskState::Sleeping;
                crate::task_table::TASK_TABLE[task_idx].wake_at = sig_deadline;
                let sched = crate::scheduler::get();
                sched.tasks[task_idx].entity.state = rux_sched::TaskState::Interruptible;
                sched.dequeue_current();
                sched.need_resched |= 1u64 << crate::percpu::cpu_id() as u32;
                sched.schedule();
                let hot = &mut (*super::process()).signal_hot;
                pending_masked = hot.pending.0 & mask;
                if pending_masked != 0 { break; }
                use rux_arch::TimerOps;
                if crate::arch::Arch::ticks() >= sig_deadline {
                    return crate::errno::EAGAIN; // timeout
                }
            }
            // Re-acquire hot reference after yield
            let hot_ref = &mut (*super::process()).signal_hot;
            let bit = pending_masked.trailing_zeros() as u8;
            let signo = bit + 1;
            hot_ref.pending = rux_proc::signal::SignalSet(hot_ref.pending.0 & !(1u64 << bit));
            let ptr = buf as *mut u8;
            core::ptr::write_bytes(ptr, 0, 128);
            *(ptr as *mut u32) = signo as u32;
            return 128;
        }

        // Dequeue the lowest pending signal
        let bit = pending_masked.trailing_zeros() as u8;
        let signo = bit + 1; // signals are 1-based
        hot.pending = rux_proc::signal::SignalSet(hot.pending.0 & !(1u64 << bit));

        // Write struct signalfd_siginfo (128 bytes)
        // Layout: ssi_signo(u32,+0) ssi_errno(i32,+4) ssi_code(i32,+8)
        //         ssi_pid(u32,+12) ssi_uid(u32,+16) ssi_fd(i32,+20)
        //         ssi_tid(u32,+24) ssi_band(u32,+28) ssi_overrun(u32,+32)
        //         ssi_trapno(u32,+36) ssi_status(i32,+40) ssi_int(i32,+44)
        //         ssi_ptr(u64,+48) ssi_utime(u64,+56) ssi_stime(u64,+64)
        //         ssi_addr(u64,+72) ssi_addr_lsb(u16,+80) ... pad to 128
        let p = buf as *mut u8;
        for i in 0..128 { *p.add(i) = 0; }
        *(buf as *mut u32) = signo as u32;                      // ssi_signo
        *((buf + 8) as *mut i32) = 0;                           // ssi_code = SI_USER
        *((buf + 12) as *mut u32) = crate::task_table::TASK_TABLE[crate::task_table::current_task_idx()].pid; // ssi_pid
        *((buf + 16) as *mut u32) = super::process().uid;         // ssi_uid

        128
    }
}

/// Check if signalfd has readable data (for poll/epoll).
pub fn signalfd_has_data(fd: usize) -> bool {
    find_signalfd(fd).map(|idx| unsafe {
        let mask = SIGNALFDS[idx].mask;
        let hot = &(*super::process()).signal_hot;
        (hot.pending.0 & mask) != 0
    }).unwrap_or(false)
}

/// Close a signalfd.
pub fn signalfd_close(fd: usize) {
    if let Some(idx) = find_signalfd(fd) {
        unsafe { SIGNALFDS[idx].active = false; }
    }
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
    for m in (*(&raw mut SHARED_MAPS)).iter_mut() {
        if !m.active { continue; }
        // Check overlap
        if m.va == 0 || m.len == 0 { continue; }
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
/// MS_ASYNC (1): hint, return immediately. MS_SYNC (4): synchronous write-back.
pub unsafe fn msync(addr: usize, len: usize, flags: usize) {
    const MS_ASYNC: usize = 1;
    if flags & MS_ASYNC != 0 { return; } // async: no-op (write-back on munmap)
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
    const MAP_FIXED_NOREPLACE: usize = 0x100000;
    const PROT_READ: usize = 1;
    const PROT_WRITE: usize = 2;
    const PROT_EXEC: usize = 4;

    if len == 0 { return crate::errno::EINVAL; }
    // Guard against integer overflow in alignment arithmetic
    use rux_arch::MemoryLayout;
    if len > crate::arch::Arch::USER_ADDR_LIMIT as usize { return crate::errno::ENOMEM; }

    unsafe {
        let aligned_len = (len + 0xFFF) & !0xFFF;

        let result = if (mmap_flags & MAP_FIXED != 0 || mmap_flags & MAP_FIXED_NOREPLACE != 0) && addr != 0 {
            let fixed_addr = addr & !0xFFF;
            // MAP_FIXED_NOREPLACE: fail if any page in range is already mapped
            if mmap_flags & MAP_FIXED_NOREPLACE != 0 {
                let upt = super::current_user_page_table();
                let mut va = fixed_addr;
                while va < fixed_addr + aligned_len {
                    if upt.translate(rux_klib::VirtAddr::new(va)).is_ok() {
                        return crate::errno::EEXIST;
                    }
                    va += 4096;
                }
            } else {
                // MAP_FIXED: unmap existing pages
                munmap(fixed_addr, aligned_len);
            }
            fixed_addr
        } else {
            let r = super::process().mmap_base;
            super::process().mmap_base += aligned_len;
            r
        };

        // Build page flags from prot (PROT_NONE = 0 → no permissions)
        let mut pg_flags = rux_mm::MappingFlags::USER;
        if prot & PROT_READ != 0 { pg_flags = pg_flags.or(rux_mm::MappingFlags::READ); }
        if prot & PROT_WRITE != 0 { pg_flags = pg_flags.or(rux_mm::MappingFlags::WRITE); }
        if prot & PROT_EXEC != 0 { pg_flags = pg_flags.or(rux_mm::MappingFlags::EXECUTE); }
        let is_prot_none = prot == 0;

        if mmap_flags & MAP_ANONYMOUS == 0 && fd < rux_fs::fdtable::MAX_FDS {
            // File-backed: allocate pages and read file data
            use rux_fs::FileSystem;
            let fs = crate::kstate::fs();
            let ino = (*rux_fs::fdtable::fd_table())[fd].ino;
            if (*rux_fs::fdtable::fd_table())[fd].active && ino != 0 {
                // Map pages with temporary WRITE permission for data loading.
                // Final permissions are applied after the file data is written.
                let load_flags = rux_mm::MappingFlags::USER
                    .or(rux_mm::MappingFlags::READ)
                    .or(rux_mm::MappingFlags::WRITE);
                super::map_user_pages(result, result + aligned_len, load_flags);
                let file_offset = offset as u64;

                // Write file data directly via user VA (pages are writable)
                let dst = core::slice::from_raw_parts_mut(result as *mut u8, len);
                let _ = fs.read(ino, file_offset, dst);

                // aarch64: flush I-cache after writing executable pages.
                #[cfg(target_arch = "aarch64")]
                if prot & PROT_EXEC != 0 {
                    sync_icache(result, aligned_len);
                }

                // Apply final permissions via remap (if different from load_flags)
                if pg_flags != load_flags {
                    let upt = super::current_user_page_table();
                    let final_pte_flags = crate::arch::PageTable::pte_flags(pg_flags);
                    for page_off in (0..aligned_len).step_by(4096) {
                        let va = rux_klib::VirtAddr::new(result + page_off);
                        if let Ok(pa) = upt.translate(va) {
                            upt.remap(va, pa, final_pte_flags);
                        }
                    }
                }

                // Track MAP_SHARED mappings for write-back on munmap
                if mmap_flags & MAP_SHARED != 0 {
                    if let Some(slot) = (*(&raw mut SHARED_MAPS)).iter_mut().find(|s| !s.active) {
                        *slot = SharedMapping {
                            active: true, va: result, len, ino, offset: file_offset,
                        };
                    }
                }
            }
        } else if mmap_flags & MAP_FIXED != 0 && !is_prot_none {
            // MAP_FIXED anonymous (BSS replacement by ld.so): allocate eagerly
            // because the old pages were just munmap'd and accessed immediately.
            super::map_user_pages(result, result + aligned_len, pg_flags);
        }
        // Non-MAP_FIXED anonymous: lazy — demand pager maps zero pages on fault.

        // Write software PTE markers for the demand pager:
        // - PROT_NONE: marker bit prevents demand-paging (→ SIGSEGV)
        // - Non-zero prot (lazy anonymous): marker encodes R/W/X bits so
        //   demand pager maps with correct permissions (not default RWX)
        if is_prot_none {
            let marker = crate::arch::PageTable::prot_none_bit();
            let mut upt = super::current_user_page_table();
            let alloc = crate::kstate::alloc();
            for va in (result..result + aligned_len).step_by(4096) {
                let _ = upt.unmap_4k(rux_klib::VirtAddr::new(va));
                upt.write_leaf_pte(rux_klib::VirtAddr::new(va), marker, alloc);
            }
        } else if mmap_flags & MAP_ANONYMOUS != 0 && mmap_flags & MAP_FIXED == 0 && prot != 7 {
            // Non-RWX anonymous lazy mapping: write prot markers so the demand
            // pager doesn't grant more permissions than requested.
            // Skip for prot==7 (RWX) since that's the default.
            let marker = crate::arch::PageTable::encode_prot_marker(prot as u8);
            let mut upt = super::current_user_page_table();
            let alloc = crate::kstate::alloc();
            for va in (result..result + aligned_len).step_by(4096) {
                upt.write_leaf_pte(rux_klib::VirtAddr::new(va), marker, alloc);
            }
        }

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
pub fn mremap(old_addr: usize, old_size: usize, new_size: usize, flags: usize, new_addr_arg: usize) -> isize {
    const MREMAP_MAYMOVE: usize = 1;
    const MREMAP_FIXED: usize = 2;
    if old_addr & 0xFFF != 0 { return crate::errno::EINVAL; }
    if new_size == 0 { return crate::errno::EINVAL; }

    // MREMAP_FIXED: move mapping to a specific address
    if flags & MREMAP_FIXED != 0 {
        if new_addr_arg & 0xFFF != 0 { return crate::errno::EINVAL; }
        let old_aligned = (old_size + 0xFFF) & !0xFFF;
        let new_aligned = (new_size + 0xFFF) & !0xFFF;
        unsafe {
            // Unmap target range
            munmap(new_addr_arg, new_aligned);
            // Map new pages at the fixed address
            let pg_flags = rux_mm::MappingFlags::READ
                .or(rux_mm::MappingFlags::WRITE)
                .or(rux_mm::MappingFlags::USER);
            super::map_user_pages(new_addr_arg, new_addr_arg + new_aligned, pg_flags);
            // Copy old data
            let copy_len = old_aligned.min(new_aligned);
            core::ptr::copy_nonoverlapping(
                old_addr as *const u8, new_addr_arg as *mut u8, copy_len,
            );
            // Unmap old range
            munmap(old_addr, old_aligned);
        }
        return new_addr_arg as isize;
    }

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
        // Extend in place — map the new pages
        let pg_flags = rux_mm::MappingFlags::READ
            .or(rux_mm::MappingFlags::WRITE)
            .or(rux_mm::MappingFlags::USER);
        unsafe { super::map_user_pages(grow_start, grow_end, pg_flags); }
        return old_addr as isize;
    }

    // Can't grow in place — relocate if MREMAP_MAYMOVE
    if flags & MREMAP_MAYMOVE == 0 {
        return crate::errno::ENOMEM;
    }

    // Allocate new region from mmap base
    unsafe {
        let new_addr = super::process().mmap_base;
        super::process().mmap_base += new_aligned;

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
pub fn futex(uaddr: usize, op: usize, val: usize, timeout_ptr: usize) -> isize {
    const FUTEX_WAIT: usize = 0;
    const FUTEX_WAKE: usize = 1;
    const FUTEX_WAIT_BITSET: usize = 9;
    const FUTEX_WAKE_BITSET: usize = 10;

    match op & 0x7F { // mask off FUTEX_PRIVATE_FLAG
        FUTEX_WAIT | FUTEX_WAIT_BITSET => futex_wait(uaddr, val as u32, timeout_ptr),
        FUTEX_WAKE | FUTEX_WAKE_BITSET => futex_wake(uaddr, val),
        _ => 0, // unsupported ops succeed silently
    }
}

fn futex_wait(uaddr: usize, expected: u32, timeout_ptr: usize) -> isize {
    unsafe {
        use crate::task_table::*;

        // Validate user pointer
        if uaddr < 0x1000 || uaddr >= 0x8000_0000_0000 {
            return crate::errno::EAGAIN;
        }

        // Check if the page is mapped before reading.
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

        // Parse timeout if provided
        let deadline = if timeout_ptr != 0
            && crate::uaccess::validate_user_ptr(timeout_ptr, 16).is_ok()
        {
            use rux_arch::TimerOps;
            let tv_sec = *(timeout_ptr as *const u64);
            let tv_nsec = *((timeout_ptr + 8) as *const u64);
            let ms = tv_sec * 1000 + tv_nsec / 1_000_000;
            if ms == 0 { return crate::errno::EAGAIN; } // zero timeout = non-blocking
            crate::arch::Arch::ticks() + ms
        } else {
            0 // no timeout — wait indefinitely
        };

        // Block until woken by FUTEX_WAKE or timeout
        let idx = current_task_idx();
        TASK_TABLE[idx].state = TaskState::WaitingForFutex;
        TASK_TABLE[idx].futex_addr = uaddr;
        if deadline > 0 { TASK_TABLE[idx].wake_at = deadline; }
        let sched = crate::scheduler::get();
        sched.tasks[idx].entity.state = rux_sched::TaskState::Interruptible;
        sched.dequeue_current();
        sched.need_resched |= 1u64 << unsafe { crate::percpu::cpu_id() as u32 };
        sched.schedule();

        // Check if we were woken by timeout (wake_sleepers sets state=Ready
        // but doesn't clear futex_addr — check if wake_at expired)
        if deadline > 0 {
            use rux_arch::TimerOps;
            if crate::arch::Arch::ticks() >= deadline {
                return -110; // ETIMEDOUT
            }
        }
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

    let needs_blocking = (0..nfds).any(|fd| {
        ((read_set | write_set) & (1u64 << fd)) != 0
            && fd < rux_fs::fdtable::MAX_FDS
            && (super::socket::is_socket(fd)
                || unsafe { (*fdt::fd_table())[fd].is_console })
    });
    let has_sockets = needs_blocking; // for net poll below

    let max_iters = if needs_blocking && timeout_ms > 0 { timeout_ms.min(30_000) } else { 1 };

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
                if super::socket::is_socket(fd) {
                    if super::socket::socket_has_data(fd) {
                        out_read |= bit;
                        ready += 1;
                    }
                } else if fd < rux_fs::fdtable::MAX_FDS && unsafe { (*fdt::fd_table())[fd].is_console } {
                    let tty = unsafe { &*(&raw const crate::tty::TTY) };
                    if tty.has_input() {
                        out_read |= bit;
                        ready += 1;
                    }
                } else {
                    // Regular files/pipes are always ready
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

        // Sleep on poll wait queue until I/O or timeout
        unsafe {
            let task_idx = crate::task_table::current_task_idx();
            crate::task_table::TASK_TABLE[task_idx].state =
                crate::task_table::TaskState::WaitingForPoll;
            use rux_arch::TimerOps;
            crate::task_table::TASK_TABLE[task_idx].wake_at =
                crate::arch::Arch::ticks() + timeout_ms.min(30_000) as u64;
            crate::task_table::poll_wait_register(task_idx);
            let sched = crate::scheduler::get();
            sched.tasks[task_idx].entity.state = rux_sched::TaskState::Interruptible;
            sched.dequeue_current();
            sched.need_resched |= 1u64 << crate::percpu::cpu_id() as u32;
            sched.schedule();

            // Woken — check if an unblocked signal is pending (return EINTR)
            let hot = &crate::task_table::TASK_TABLE[task_idx].signal_hot;
            let deliverable = hot.pending.0 & !hot.blocked.0;
            if deliverable != 0 {
                if readfds_ptr != 0 { *(readfds_ptr as *mut u64) = 0; }
                if writefds_ptr != 0 { *(writefds_ptr as *mut u64) = 0; }
                return crate::errno::EINTR;
            }
        }
    }

    // Timeout: clear all sets
    if readfds_ptr != 0 { unsafe { *(readfds_ptr as *mut u64) = 0; } }
    if writefds_ptr != 0 { unsafe { *(writefds_ptr as *mut u64) = 0; } }
    0
}

/// mincore(addr, length, vec) — check if pages are resident in memory.
/// All pages in rux are always resident (no swap), so fill vec with 1s.
pub fn mincore(addr: usize, length: usize, vec_ptr: usize) -> isize {
    if addr & 0xFFF != 0 { return crate::errno::EINVAL; }
    let pages = (length + 0xFFF) / 4096;
    if crate::uaccess::validate_user_ptr(vec_ptr, pages).is_err() { return crate::errno::EFAULT; }
    unsafe {
        let v = core::slice::from_raw_parts_mut(vec_ptr as *mut u8, pages);
        for byte in v.iter_mut() { *byte = 1; } // all pages resident
    }
    0
}

/// mprotect(addr, len, prot) — POSIX.1: change page protection.
pub fn mprotect(addr: usize, len: usize, prot: usize) -> isize {
    if addr & 0xFFF != 0 { return crate::errno::EINVAL; }
    use rux_arch::MemoryLayout;
    if len > crate::arch::Arch::USER_ADDR_LIMIT as usize { return crate::errno::EINVAL; }
    unsafe {
        let mut upt = super::current_user_page_table();
        let aligned_len = (len + 0xFFF) & !0xFFF;

        // Build flags from prot (PROT_NONE = 0 → USER only, no R/W/X)
        let mut flags = rux_mm::MappingFlags::USER;
        if prot & 1 != 0 { flags = flags.or(rux_mm::MappingFlags::READ); }
        if prot & 2 != 0 { flags = flags.or(rux_mm::MappingFlags::WRITE); }
        if prot & 4 != 0 { flags = flags.or(rux_mm::MappingFlags::EXECUTE); }

        let mut va = addr;
        while va < addr + aligned_len {
            let virt = rux_klib::VirtAddr::new(va);
            if prot == 0 {
                // PROT_NONE: unmap the page and write marker PTE
                let _ = upt.unmap_4k(virt);
                let alloc = crate::kstate::alloc();
                upt.write_leaf_pte(virt, crate::arch::PageTable::prot_none_bit(), alloc);
            } else if let Ok(pa) = upt.translate(virt) {
                // Page is physically mapped — remap with new permissions
                let pa_page = rux_klib::PhysAddr::new(pa.as_usize() & !0xFFF);
                let pte_flags = crate::arch::PageTable::pte_flags(flags);
                upt.remap(virt, pa_page, pte_flags);
            } else {
                // Page not mapped — might have a prot marker from lazy mmap.
                // Update the marker so the demand pager uses the new permissions.
                let raw_pte = upt.read_leaf_pte(virt);
                if raw_pte != 0 {
                    let alloc = crate::kstate::alloc();
                    let _ = upt.unmap_4k(virt);
                    let marker = crate::arch::PageTable::encode_prot_marker(prot as u8);
                    upt.write_leaf_pte(virt, marker, alloc);
                }
            }
            va += 4096;
        }
    }
    0
}

/// poll(fds, nfds, timeout) — POSIX.1: check fd readiness.
/// Returns number of fds with events, or 0 on timeout.
/// ppoll wrapper: reads timeout from timespec pointer.
/// NULL timeout_ptr = infinite wait (like Linux), capped at 30s per iteration.
pub fn ppoll(fds_ptr: usize, nfds: usize, timeout_ptr: usize, _sigmask: usize) -> isize {
    if fds_ptr != 0 && nfds > 0 {
        if crate::uaccess::validate_user_ptr(fds_ptr, nfds.min(256) * 8).is_err() { return crate::errno::EFAULT; }
    }
    let timeout_ms = if timeout_ptr >= 0x10000 && timeout_ptr < 0x8000_0000_0000 {
        unsafe {
            let sec: u64 = crate::uaccess::get_user(timeout_ptr);
            let nsec: u64 = crate::uaccess::get_user(timeout_ptr + 8);
            let ms = sec * 1000 + nsec / 1_000_000;
            if ms > 30_000 { 30_000 } else { ms as usize }
        }
    } else { 30_000 }; // NULL timeout = infinite; use 30s then re-enter from userspace
    poll(fds_ptr, nfds, timeout_ms)
}

pub fn poll(fds_ptr: usize, nfds: usize, timeout_ms: usize) -> isize {
    if fds_ptr == 0 || nfds == 0 { return 0; }

    // Check if we have blocking-capable fds (sockets, eventfd, timerfd, signalfd, pipes)
    // Console stdin uses IRQ-based ring buffer on x86_64; on aarch64 it still polls.
    // When the ring buffer has data, poll returns immediately; when empty, halt_until_interrupt
    // waits for the serial IRQ to fill it.
    let nfds = nfds.min(256);
    let needs_blocking = unsafe {
        (0..nfds).any(|i| {
            let entry = (fds_ptr + i * 8) as *const u8;
            let fd = *(entry as *const i32) as usize;
            fd < rux_fs::fdtable::MAX_FDS && (
                super::socket::is_socket(fd) || is_eventfd(fd) || is_timerfd(fd)
                || is_signalfd(fd) || (*fdt::fd_table())[fd].is_pipe
                || (*fdt::fd_table())[fd].is_console || fd <= 2
            )
        })
    };

    // Deadline: absolute tick count when timeout expires (0 = non-blocking)
    let deadline: u64 = if needs_blocking && timeout_ms > 0 {
        unsafe {
            use rux_arch::TimerOps;
            crate::arch::Arch::ticks() + timeout_ms.min(30_000) as u64
        }
    } else { 0 };

    loop {
        // Process pending network packets
        #[cfg(feature = "net")]
        unsafe {
            use rux_arch::TimerOps;
            rux_net::poll(crate::arch::Arch::ticks());
        }

        // Check all fds for readiness
        let ready = unsafe {
            let mut r = 0i32;
            for i in 0..nfds {
                let entry = (fds_ptr + i * 8) as *mut u8;
                let fd = *(entry as *const i32) as usize;
                let events = *((entry as usize + 4) as *const i16);
                let revents_ptr = (entry as usize + 6) as *mut i16;
                if fd >= fdt::MAX_FDS { *revents_ptr = 0; continue; }
                let f = &(*fdt::fd_table())[fd];
                let mut revents: i16 = 0;
                if f.active && f.is_socket {
                    if events & 4 != 0 && super::socket::socket_can_write(fd) { revents |= 4; }
                    if events & 1 != 0 && super::socket::socket_has_data(fd) { revents |= 1; }
                } else if f.active && is_eventfd(fd) {
                    if events & 1 != 0 && eventfd_has_data(fd) { revents |= 1; }
                    if events & 4 != 0 { revents |= 4; }
                } else if f.active && is_timerfd(fd) {
                    if events & 1 != 0 && timerfd_has_data(fd) { revents |= 1; }
                } else if f.active && f.is_pipe {
                    let pid = f.pipe_id;
                    if events & 1 != 0 && crate::pipe::has_data(pid) { revents |= 1; }
                    if events & 4 != 0 && f.pipe_write { revents |= 4; }
                    if crate::pipe::writers_closed(pid) { revents |= 0x10; }
                } else if f.active && f.is_console {
                    // Console: check actual data availability for POLLIN
                    if events & 1 != 0 {
                        let tty = &*(&raw const crate::tty::TTY);
                        if tty.has_input() { revents |= 1; }
                    }
                    if events & 4 != 0 { revents |= 4; } // always writable
                } else if fd <= 2 {
                    // fd 0-2 not marked as console/pipe/socket — treat as console
                    if events & 1 != 0 {
                        let tty = &*(&raw const crate::tty::TTY);
                        if tty.has_input() { revents |= 1; }
                    }
                    if events & 4 != 0 { revents |= 4; }
                } else if f.active {
                    // Regular files are always ready
                    if events & 1 != 0 { revents |= 1; }
                    if events & 4 != 0 { revents |= 4; }
                } else {
                    revents = 0x20;
                }
                *revents_ptr = revents;
                if revents != 0 { r += 1; }
            }
            r
        };

        if ready > 0 { return ready as isize; }
        if deadline == 0 { return 0; }
        unsafe {
            use rux_arch::TimerOps;
            if crate::arch::Arch::ticks() >= deadline { return 0; }
        }

        // Nothing ready — sleep on poll wait queue (like Linux wait_event).
        // Woken by poll_wake_all() on I/O or wake_sleepers() on timeout.
        unsafe {
            let task_idx = crate::task_table::current_task_idx();
            crate::task_table::TASK_TABLE[task_idx].state =
                crate::task_table::TaskState::WaitingForPoll;
            crate::task_table::TASK_TABLE[task_idx].wake_at = deadline;
            crate::task_table::poll_wait_register(task_idx);
            let sched = crate::scheduler::get();
            sched.tasks[task_idx].entity.state = rux_sched::TaskState::Interruptible;
            sched.dequeue_current();
            sched.need_resched |= 1u64 << crate::percpu::cpu_id() as u32;
            sched.schedule();

            // Woken — check if an unblocked signal is pending (return EINTR so post_syscall delivers it)
            let hot = &crate::task_table::TASK_TABLE[task_idx].signal_hot;
            let deliverable = hot.pending.0 & !hot.blocked.0;
            if deliverable != 0 {
                return crate::errno::EINTR;
            }
        }
    }
}
