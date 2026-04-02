//! Process control, CWD, and time syscalls.

use rux_arch::TimerOps;
type Arch = crate::arch::Arch;
/// _exit(status) — POSIX.1
pub fn exit(status: i32) -> ! {
    unsafe { super::PROCESS.last_child_exit = status; }

    unsafe {
        // Close pipe FDs, mark zombie/free, wake parent, schedule.
        use crate::task_table::*;
        let idx = current_task_idx();
        if TASK_TABLE[idx].active && TASK_TABLE[idx].pid != 1 {
            // Close all pipe FDs so reader/writer counts drop correctly.
            // Without this, blocked pipe waiters never see EOF/EPIPE.
            for i in 0..rux_fs::fdtable::MAX_FDS {
                if (*rux_fs::fdtable::FD_TABLE)[i].active && (*rux_fs::fdtable::FD_TABLE)[i].is_pipe {
                    let pid = (*rux_fs::fdtable::FD_TABLE)[i].pipe_id;
                    let pw = (*rux_fs::fdtable::FD_TABLE)[i].pipe_write;
                    (*rux_fs::fdtable::FD_TABLE)[i].active = false;
                    (crate::pipe::PIPE.close)(pid, pw);
                    crate::pipe::wake_pipe_waiters(pid);
                }
            }

            TASK_TABLE[idx].exit_code = status;

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
    unsafe {
        use crate::task_table::*;

        let my_pid = current_pid();
        const WNOHANG: usize = 1;

        loop {
            // Scan for a zombie child matching the pid criteria.
            for i in 0..MAX_PROCS {
                let t = &TASK_TABLE[i];
                if !t.active || t.ppid != my_pid { continue; }
                if t.state != TaskState::Zombie { continue; }
                // pid matching: usize::MAX (-1) = any child, 0 = same process group
                if pid == 0 {
                    if t.pgid != TASK_TABLE[current_task_idx()].pgid { continue; }
                } else if pid != usize::MAX && t.pid as usize != pid {
                    continue;
                }

                // Found a zombie — reap it.
                let child_pid = t.pid as isize;
                let exit_code = t.exit_code;
                let child_pt_root = t.pt_root;
                let slot = &mut TASK_TABLE[i];
                slot.active = false;
                slot.state = TaskState::Free;
                slot.pid = 0;
                slot.pt_root = 0;

                // Free the child's address space. Fork children bypass begin_child so
                // their PT is not in CHILD_PAGES — free it here instead.
                // Use the COW-aware variant: if the child exited before exec-ing,
                // its pages may still be shared with the parent via COW and must
                // not be freed until the last owner releases them.
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
        if buf == 0 || size < len + 1 { return crate::errno::ERANGE; }
        crate::uaccess::stac();
        let ptr = buf as *mut u8;
        for i in 0..len {
            *ptr.add(i) = super::PROCESS.fs_ctx.cwd_path[i];
        }
        *ptr.add(len) = 0;
        crate::uaccess::clac();
    }
    buf as isize
}

/// uname(buf) — POSIX.1
pub fn uname(buf: usize) -> isize {
    if buf == 0 { return crate::errno::EFAULT; }
    unsafe {
        crate::uaccess::stac();
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
        crate::uaccess::clac();
    }
    0
}
pub fn clock_gettime(_clockid: usize, tp: usize) -> isize {
    if tp == 0 { return crate::errno::EFAULT; }
    let ticks = Arch::ticks();
    unsafe {
        crate::uaccess::put_user(tp, ticks / 1000);
        crate::uaccess::put_user(tp + 8, (ticks % 1000) * 1_000_000);
    }
    0
}

pub fn nanosleep(req_ptr: usize) -> isize {
    if req_ptr == 0 { return crate::errno::EFAULT; }
    unsafe {
        use rux_arch::HaltOps;
        let tv_sec: u64 = crate::uaccess::get_user(req_ptr);
        let tv_nsec: u64 = crate::uaccess::get_user(req_ptr + 8);
        let ms = tv_sec * 1000 + tv_nsec / 1_000_000;
        // Ensure timer is running for accurate sleep
        use rux_arch::TimerControl;
        Arch::start_timer();
        let target = Arch::ticks() + ms;
        while Arch::ticks() < target {
            Arch::halt_until_interrupt();
        }
    }
    0
}

// ── Resource limits ─────────────────────────────────────────────────

/// prlimit64(pid, resource, new_limit, old_limit) — Linux
pub fn prlimit64(_pid: usize, _resource: usize, _new_limit: usize, old_limit: usize) -> isize {
    // Return RLIM_INFINITY for all resources
    if old_limit != 0 {
        unsafe {
            let rlim_infinity: u64 = !0;
            crate::uaccess::put_user(old_limit, rlim_infinity);
            crate::uaccess::put_user(old_limit + 8, rlim_infinity);
        }
    }
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
pub fn setsid() -> isize {
    unsafe {
        use crate::task_table::*;
        let idx = current_task_idx();
        let pid = TASK_TABLE[idx].pid;
        TASK_TABLE[idx].pgid = pid;
        pid as isize
    }
}
