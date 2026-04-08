//! Process control, CWD, and time syscalls.

use rux_arch::TimerOps;
type Arch = crate::arch::Arch;

/// Close all pipe FDs in the current process, waking blocked waiters.
/// Called from exit() so blocked pipe readers/writers see EOF/EPIPE.
unsafe fn close_all_pipes() {
    for i in 0..rux_fs::fdtable::MAX_FDS {
        if let Some(f) = rux_fs::fdtable::get_fd(i) {
            if f.is_pipe {
                let pid = f.pipe_id;
                let pw = f.pipe_write;
                (*rux_fs::fdtable::FD_TABLE)[i].active = false;
                (crate::pipe::PIPE.close)(pid, pw);
                crate::pipe::wake_pipe_waiters(pid);
            }
        }
    }
}

/// _exit(status) — POSIX.1
pub fn exit(status: i32) -> ! {
    unsafe { super::PROCESS.last_child_exit = status; }

    unsafe {
        // Close pipe FDs, mark zombie/free, wake parent, schedule.
        use crate::task_table::*;
        let idx = current_task_idx();
        if TASK_TABLE[idx].active && TASK_TABLE[idx].pid != 1 {
            // Close all pipe FDs so reader/writer counts drop correctly.
            close_all_pipes();

            // Restore fd 0-2 as console if they were corrupted by the child.
            // The global FD_TABLE is shared, so a child that dup2'd a file onto
            // fd 1 (e.g., apk redirecting stdout) leaves is_console=false after exit.
            for i in 0..3 {
                if !(*rux_fs::fdtable::FD_TABLE)[i].is_pipe
                    && !(*rux_fs::fdtable::FD_TABLE)[i].is_socket
                {
                    (*rux_fs::fdtable::FD_TABLE)[i] = rux_fs::fdtable::OpenFile {
                        ino: 0, offset: 0, flags: 0, fd_flags: 0, active: true, is_console: true,
                        is_pipe: false, pipe_id: 0, pipe_write: false,
                        is_socket: false, socket_idx: 0,
                    };
                }
            }

            TASK_TABLE[idx].exit_code = status;

            // Session leader exit: send SIGHUP to all processes in the session
            // (Linux: disassociate_ctty → kill_pgrp(SIGHUP) → kill_pgrp(SIGCONT))
            let my_pid = TASK_TABLE[idx].pid;
            let my_sid = TASK_TABLE[idx].sid;
            if my_sid == my_pid { // session leader
                for j in 0..MAX_PROCS {
                    if j != idx && TASK_TABLE[j].active && TASK_TABLE[j].sid == my_sid
                        && TASK_TABLE[j].state != TaskState::Zombie
                    {
                        TASK_TABLE[j].signal_hot.pending =
                            TASK_TABLE[j].signal_hot.pending.add(1); // SIGHUP = 1
                        if TASK_TABLE[j].state == TaskState::Stopped {
                            // Also send SIGCONT to wake stopped processes
                            TASK_TABLE[j].signal_hot.pending =
                                TASK_TABLE[j].signal_hot.pending.add(18); // SIGCONT = 18
                            TASK_TABLE[j].state = TaskState::Ready;
                            crate::scheduler::get().wake_task(j);
                        }
                    }
                }
            }

            // CLONE_THREAD: thread exit — write 0 to clear_child_tid, skip zombie.
            let is_thread = TASK_TABLE[idx].clone_flags as usize & crate::errno::CLONE_THREAD != 0;
            if is_thread {
                // clear_child_tid: write 0 to user address (for pthread_join / futex)
                let ctid = TASK_TABLE[idx].clear_child_tid;
                if ctid != 0 {
                    crate::uaccess::put_user(ctid, 0u32);
                    super::posix::futex_wake(ctid, 1);
                }
                // Thread doesn't become zombie — just free the slot
                TASK_TABLE[idx].active = false;
                TASK_TABLE[idx].state = TaskState::Free;
            } else if TASK_TABLE[idx].ppid == 1 {
                // Parent is init (PID 1): auto-reap immediately.
                // Init doesn't explicitly waitpid for every shell pipeline
                // child, so zombies would accumulate and exhaust slots.
                notify_parent_child_exit(1, status);
                // Free the child's address space (COW pages + page tables)
                let child_pt_root = TASK_TABLE[idx].pt_root;
                if child_pt_root != 0 {
                    let alloc = crate::kstate::alloc();
                    let child_pt = crate::arch::PageTable::from_root(
                        rux_klib::PhysAddr::new(child_pt_root as usize)
                    );
                    child_pt.free_user_address_space_cow(alloc, &mut |pa| crate::cow::dec_ref(pa));
                }
                TASK_TABLE[idx].active = false;
                TASK_TABLE[idx].state = TaskState::Free;
                TASK_TABLE[idx].pt_root = 0;
            } else {
                TASK_TABLE[idx].state = TaskState::Zombie;
                notify_parent_child_exit(TASK_TABLE[idx].ppid, status);
            }

            // Mark entity Dead so schedule() doesn't re-enqueue us.
            {
                let sched = crate::scheduler::get();
                sched.tasks[idx].entity.state = rux_sched::TaskState::Dead;
                sched.tasks[idx].active = false;
                sched.dequeue_current();
                sched.schedule();
                // Bug indicator: schedule() should never return for a dead task.
                use rux_arch::ConsoleOps;
                Arch::write_str("rux: exit: SCHEDULE RETURNED (should not happen)\n");
            }
            loop { core::hint::spin_loop(); }
        }
    }

    // Only PID 1 (init) reaches here.
    use rux_arch::ExitOps;
    crate::arch::Arch::exit(crate::arch::Arch::EXIT_SUCCESS);
}

/// waitpid(pid, wstatus, options) — POSIX.1
///
/// Supports:
/// - pid == usize::MAX (−1 as usize): wait for any child
/// - pid > 0: wait for specific PID
/// - options & 1 (WNOHANG): non-blocking
pub fn waitpid(pid: usize, wstatus_ptr: usize, options: usize) -> isize {
    if wstatus_ptr != 0 && crate::uaccess::validate_user_ptr(wstatus_ptr, 4).is_err() { return crate::errno::EFAULT; }
    unsafe {
        use crate::task_table::*;

        let my_pid = current_pid();
        const WNOHANG: usize = 1;
        const WUNTRACED: usize = 2;
        const WCONTINUED: usize = 8;

        loop {
            // Scan for zombie, stopped, or continued children.
            for i in 0..MAX_PROCS {
                let t = &TASK_TABLE[i];
                if !t.active || t.ppid != my_pid { continue; }
                let is_zombie = t.state == TaskState::Zombie;
                let is_stopped = t.state == TaskState::Stopped && (options & WUNTRACED != 0);
                // WCONTINUED: report children that were continued from stopped state
                // We detect this by checking: child is Ready and exit_code has the
                // WCONTINUED marker (0xFFFF). SIGCONT handler sets this.
                let is_continued = options & WCONTINUED != 0
                    && t.state == TaskState::Ready
                    && t.exit_code == 0xFFFF;
                if !is_zombie && !is_stopped && !is_continued { continue; }
                // pid matching: usize::MAX (-1) = any child, 0 = same process group,
                // pid < -1 = process group abs(pid)
                if pid == 0 {
                    if t.pgid != TASK_TABLE[current_task_idx()].pgid { continue; }
                } else if pid != usize::MAX {
                    let spid = pid as isize;
                    if spid < -1 {
                        if t.pgid != (-spid) as u32 { continue; }
                    } else if t.pid as usize != pid {
                        continue;
                    }
                }

                let child_pid = t.pid as isize;
                let exit_code = t.exit_code;

                // Stopped child: report but don't reap
                if is_stopped {
                    if wstatus_ptr != 0 {
                        crate::uaccess::put_user(wstatus_ptr, exit_code as u32);
                    }
                    return child_pid;
                }

                // Continued child: report, clear marker
                if is_continued {
                    TASK_TABLE[i].exit_code = 0; // clear WCONTINUED marker
                    if wstatus_ptr != 0 {
                        crate::uaccess::put_user(wstatus_ptr, 0xFFFFu32); // WIFCONTINUED
                    }
                    return child_pid;
                }

                // Zombie: reap
                let child_pt_root = t.pt_root;
                let slot = &mut TASK_TABLE[i];
                slot.active = false;
                slot.state = TaskState::Free;
                slot.pid = 0;
                slot.pt_root = 0;

                if child_pt_root != 0 {
                    let alloc = crate::kstate::alloc();
                    let child_pt = crate::arch::PageTable::from_root(
                        rux_klib::PhysAddr::new(child_pt_root as usize)
                    );
                    child_pt.free_user_address_space_cow(alloc, &mut |pa| crate::cow::dec_ref(pa));
                }

                if wstatus_ptr != 0 {
                    crate::uaccess::put_user(wstatus_ptr, (exit_code as u32) << 8);
                }
                return child_pid;
            }

            // WNOHANG: don't block, return 0 if no zombie yet.
            if options & WNOHANG != 0 { return 0; }

            // Check if this process has any children at all.
            let has_children = (0..MAX_PROCS).any(|i| {
                TASK_TABLE[i].active && TASK_TABLE[i].ppid == my_pid
                    && TASK_TABLE[i].state != TaskState::Zombie
            });
            if !has_children {
                // Also handle the legacy single-process fast path:
                // PID 1 calls waitpid and there are no multi-process children.
                if super::PROCESS.child_available {
                    super::PROCESS.child_available = false;
                    if wstatus_ptr != 0 {
                        let status = (super::PROCESS.last_child_exit as u32) << 8;
                        crate::uaccess::put_user(wstatus_ptr, status as u32);
                    }
                    return 42; // fake child PID for vfork path
                }
                return crate::errno::ECHILD;
            }

            // Block until a child exits.
            TASK_TABLE[current_task_idx()].state = TaskState::WaitingForChild;
            {
                let sched = crate::scheduler::get();
                // Mark Interruptible so schedule() doesn't re-enqueue the parent.
                sched.tasks[current_task_idx()].entity.state = rux_sched::TaskState::Interruptible;
                sched.dequeue_current();
                sched.schedule(); // returns when woken by child's exit()
            }
        }
    }
}

/// getcwd(buf, size) — POSIX.1
pub fn getcwd(buf: usize, size: usize) -> isize {
    unsafe {
        let len = super::PROCESS.fs_ctx.cwd_path_len;
        if crate::uaccess::validate_user_ptr(buf, size.max(1)).is_err() { return crate::errno::EFAULT; }
        if size < len + 1 { return crate::errno::ERANGE; }
        // dispatch() provides stac/clac wrapping — no inner pair needed
        let ptr = buf as *mut u8;
        for i in 0..len {
            *ptr.add(i) = super::PROCESS.fs_ctx.cwd_path[i];
        }
        *ptr.add(len) = 0;
    }
    buf as isize
}

/// uname(buf) — POSIX.1
pub fn uname(buf: usize) -> isize {
    if crate::uaccess::validate_user_ptr(buf, 325).is_err() { return crate::errno::EFAULT; }
    // dispatch() provides stac/clac wrapping for SMAP
    unsafe {
        let ptr = buf as *mut u8;
        for i in 0..325 { *ptr.add(i) = 0; }
        // sysname
        for (i, &b) in b"rux".iter().enumerate() { *ptr.add(i) = b; }
        // nodename (offset 65) — read from /etc/hostname
        {
            use rux_fs::FileSystem;
            let mut name = [0u8; 64];
            let mut len = 3usize;
            name[0] = b'r'; name[1] = b'u'; name[2] = b'x';
            let fs = crate::kstate::fs();
            if let Ok(ino) = rux_fs::path::resolve_path(fs, b"/etc/hostname") {
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
        for (i, &b) in env!("CARGO_PKG_VERSION").as_bytes().iter().enumerate() { *ptr.add(130 + i) = b; }
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
/// Base epoch for CLOCK_REALTIME: 2025-04-01 00:00:00 UTC.
/// Without an RTC, we use a fixed base and add monotonic ticks.
const EPOCH_BASE: u64 = 1743465600; // seconds since 1970-01-01

pub fn clock_gettime(clockid: usize, tp: usize) -> isize {
    if crate::uaccess::validate_user_ptr(tp, 16).is_err() { return crate::errno::EFAULT; }
    let ticks = Arch::ticks();
    let (sec, nsec) = if clockid == 0 {
        // CLOCK_REALTIME: wall clock = epoch base + boot ticks
        (EPOCH_BASE + ticks / 1000, (ticks % 1000) * 1_000_000)
    } else {
        // CLOCK_MONOTONIC and others: time since boot
        (ticks / 1000, (ticks % 1000) * 1_000_000)
    };
    unsafe {
        crate::uaccess::put_user(tp, sec);
        crate::uaccess::put_user(tp + 8, nsec);
    }
    0
}

pub fn nanosleep(req_ptr: usize) -> isize {
    if crate::uaccess::validate_user_ptr(req_ptr, 16).is_err() { return crate::errno::EFAULT; }
    unsafe {
        let tv_sec: u64 = crate::uaccess::get_user(req_ptr);
        let tv_nsec: u64 = crate::uaccess::get_user(req_ptr + 8);
        let ms = tv_sec * 1000 + tv_nsec / 1_000_000;
        if ms == 0 { return 0; }

        use rux_arch::TimerOps;
        let idx = crate::task_table::current_task_idx();
        let deadline = Arch::ticks() + ms;

        // Set sleep deadline and mark task as sleeping
        crate::task_table::TASK_TABLE[idx].wake_at = deadline;
        crate::task_table::TASK_TABLE[idx].state = crate::task_table::TaskState::Sleeping;

        // Yield to scheduler — we'll be woken by the timer tick
        // handler when wake_at is reached, or by a signal.
        let sched = crate::scheduler::get();
        sched.tasks[idx].entity.state = rux_sched::TaskState::Interruptible;
        sched.schedule();

        // Woke up — check why
        let now = Arch::ticks();
        if now < deadline {
            // Woken early (by signal) — return EINTR
            return crate::errno::EINTR;
        }
    }
    0
}

// ── Resource limits ─────────────────────────────────────────────────

/// prlimit64(pid, resource, new_limit, old_limit) — Linux
/// getrandom(buf, buflen, flags) — fill buffer with random bytes
pub fn getrandom(buf_ptr: usize, len: usize, _flags: usize) -> isize {
    if crate::uaccess::validate_user_ptr(buf_ptr, len).is_err() { return crate::errno::EFAULT; }
    unsafe {
        // Use the same xorshift64 PRNG as /dev/urandom
        use rux_arch::TimerOps;
        let mut state = crate::arch::Arch::ticks().wrapping_mul(6364136223846793005).wrapping_add(1);
        let ptr = buf_ptr as *mut u8;
        for i in 0..len {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *ptr.add(i) = state as u8;
        }
    }
    len as isize
}

/// dup3(oldfd, newfd, flags) — like dup2 but with flags (O_CLOEXEC)
pub fn dup3(oldfd: usize, newfd: usize, flags: usize) -> isize {
    if oldfd == newfd { return crate::errno::EINVAL; }
    let result = super::posix::dup2(oldfd, newfd);
    if result >= 0 && flags & 0x80000 != 0 { // O_CLOEXEC
        unsafe {
            if let Some(f) = rux_fs::fdtable::get_fd_mut(newfd) {
                f.fd_flags = rux_fs::fdtable::FD_CLOEXEC;
            }
        }
    }
    result
}

pub fn prlimit64(_pid: usize, resource: usize, _new_limit: usize, old_limit: usize) -> isize {
    if old_limit != 0 {
        if crate::uaccess::validate_user_ptr(old_limit, 16).is_err() { return crate::errno::EFAULT; }
        unsafe {
            let rlim_infinity: u64 = !0;
            // Return sensible defaults per resource
            let (cur, max) = match resource {
                7 => (256u64, 256),   // RLIMIT_NOFILE — matches MAX_FDS
                3 => (8 * 1024 * 1024, rlim_infinity), // RLIMIT_STACK — 8MB default
                _ => (rlim_infinity, rlim_infinity),
            };
            crate::uaccess::put_user(old_limit, cur);
            crate::uaccess::put_user(old_limit + 8, max);
        }
    }
    0
}

// ── User/group ID management ──────────────────────────────────────────

/// Check if a credential change is allowed: root can set anything,
/// non-root can only set to current real, effective, or saved value.
/// `u32::MAX` means "don't change" (returns true).
#[inline]
unsafe fn can_set_id(new: u32, real: u32, effective: u32, saved: u32) -> bool {
    new == u32::MAX || super::PROCESS.euid == 0 || new == real || new == effective || new == saved
}

/// setuid(uid) — POSIX.1
/// Root: sets real, effective, and saved. Non-root: sets effective only.
pub unsafe fn setuid(uid: u32) -> isize {
    if super::PROCESS.euid == 0 {
        super::PROCESS.uid = uid;
        super::PROCESS.euid = uid;
        super::PROCESS.suid = uid;
    } else if can_set_id(uid, super::PROCESS.uid, super::PROCESS.euid, super::PROCESS.suid) {
        super::PROCESS.euid = uid;
    } else {
        return crate::errno::EPERM;
    }
    0
}

/// setgid(gid) — POSIX.1
/// Root: sets real, effective, and saved. Non-root: sets effective only.
pub unsafe fn setgid(gid: u32) -> isize {
    if super::PROCESS.euid == 0 {
        super::PROCESS.gid = gid;
        super::PROCESS.egid = gid;
        super::PROCESS.sgid = gid;
    } else if can_set_id(gid, super::PROCESS.gid, super::PROCESS.egid, super::PROCESS.sgid) {
        super::PROCESS.egid = gid;
    } else {
        return crate::errno::EPERM;
    }
    0
}

/// setreuid(ruid, euid) — POSIX.1
/// If either real or effective changes, saved is set to new effective.
pub unsafe fn setreuid(ruid: u32, euid: u32) -> isize {
    if !can_set_id(ruid, super::PROCESS.uid, super::PROCESS.euid, super::PROCESS.suid) { return crate::errno::EPERM; }
    if !can_set_id(euid, super::PROCESS.uid, super::PROCESS.euid, super::PROCESS.suid) { return crate::errno::EPERM; }
    if ruid != u32::MAX { super::PROCESS.uid = ruid; }
    if euid != u32::MAX { super::PROCESS.euid = euid; }
    // POSIX: if either was changed, saved = new effective
    if ruid != u32::MAX || euid != u32::MAX { super::PROCESS.suid = super::PROCESS.euid; }
    0
}

/// setregid(rgid, egid) — POSIX.1
pub unsafe fn setregid(rgid: u32, egid: u32) -> isize {
    if !can_set_id(rgid, super::PROCESS.gid, super::PROCESS.egid, super::PROCESS.sgid) { return crate::errno::EPERM; }
    if !can_set_id(egid, super::PROCESS.gid, super::PROCESS.egid, super::PROCESS.sgid) { return crate::errno::EPERM; }
    if rgid != u32::MAX { super::PROCESS.gid = rgid; }
    if egid != u32::MAX { super::PROCESS.egid = egid; }
    if rgid != u32::MAX || egid != u32::MAX { super::PROCESS.sgid = super::PROCESS.egid; }
    0
}

// ── Process groups ─────────────────────────────────────────────────────

/// setpgid(pid, pgid) — POSIX.1
/// pid==0 means self. pgid==0 means use pid as the new pgid.
pub fn setpgid(pid: usize, pgid: usize) -> isize {
    unsafe {
        use crate::task_table::*;
        let my_pid = current_pid();
        let target_pid = if pid == 0 { my_pid } else { pid as u32 };
        let new_pgid = if pgid == 0 { target_pid } else { pgid as u32 };

        match find_task_by_pid(target_pid) {
            Some(i) => {
                let t = &mut TASK_TABLE[i];
                if target_pid != my_pid && t.ppid != my_pid {
                    return crate::errno::EPERM;
                }
                t.pgid = new_pgid;
                0
            }
            None => crate::errno::ESRCH,
        }
    }
}

/// getpgid(pid) — POSIX.1
/// pid==0 means self (also serves as getpgrp).
pub fn getpgid(pid: usize) -> isize {
    unsafe {
        use crate::task_table::*;
        if pid == 0 {
            return TASK_TABLE[current_task_idx()].pgid as isize;
        }
        match find_task_by_pid(pid as u32) {
            Some(i) => TASK_TABLE[i].pgid as isize,
            None => crate::errno::ESRCH,
        }
    }
}

/// setsid() — POSIX.1
/// Create a new session. Caller becomes session and process group leader.
/// Fails with EPERM if caller is already a process group leader.
pub fn setsid() -> isize {
    unsafe {
        use crate::task_table::*;
        let idx = current_task_idx();
        let pid = TASK_TABLE[idx].pid;
        // POSIX: fail if already a process group leader (pgid == pid)
        if TASK_TABLE[idx].pgid == pid { return crate::errno::EPERM; }
        TASK_TABLE[idx].pgid = pid;
        TASK_TABLE[idx].sid = pid;
        pid as isize
    }
}
