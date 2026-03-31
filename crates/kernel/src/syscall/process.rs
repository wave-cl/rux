//! Process control, CWD, and time syscalls.

use rux_arch::TimerOps;
type Arch = crate::arch::Arch;
/// _exit(status) — POSIX.1
pub fn exit(status: i32) -> ! {
    unsafe { super::PROCESS.last_child_exit = status; }

    unsafe {
        use rux_arch::VforkContext;
        // Check vfork child first — longjmp resumes the parent.
        if crate::arch::Arch::jmp_active() {
            crate::arch::Arch::longjmp(42);
        }

        // Forked child (not vfork): mark zombie, wake parent, dequeue, schedule.
        use crate::task_table::*;
        let idx = CURRENT_TASK_IDX;
        if TASK_TABLE[idx].active && TASK_TABLE[idx].pid != 1 {
            TASK_TABLE[idx].exit_code = status;
            TASK_TABLE[idx].state = TaskState::Zombie;

            // Find parent and wake it if it's blocked in waitpid.
            let ppid = TASK_TABLE[idx].ppid;
            for i in 0..MAX_PROCS {
                let t = &mut TASK_TABLE[i];
                if !t.active || t.pid != ppid { continue; }
                t.last_child_exit = status;
                t.child_available = true;
                if t.state == TaskState::WaitingForChild {
                    t.state = TaskState::Ready;
                    crate::scheduler::get().wake_task(i);
                }
                break;
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
                // pid == usize::MAX (-1) means "any child"
                if pid != usize::MAX && pid != 0 && t.pid as usize != pid { continue; }

                // Found a zombie — reap it.
                let child_pid = t.pid as isize;
                let exit_code = t.exit_code;
                let child_pt_root = t.pt_root;
                let slot = &mut TASK_TABLE[i];
                slot.active = false;
                slot.state = TaskState::Free;
                slot.pid = 0;
                slot.pt_root = 0;

                // Free the exec'd address space. Fork children bypass begin_child so
                // their exec'd PT is not in CHILD_PAGES — free it here instead.
                if child_pt_root != 0 {
                    let alloc = crate::kstate::alloc();
                    let child_pt = crate::arch::PageTable::from_root(
                        rux_klib::PhysAddr::new(child_pt_root as usize)
                    );
                    child_pt.free_user_address_space(alloc);
                }

                if wstatus_ptr != 0 {
                    *(wstatus_ptr as *mut u32) = (exit_code as u32) << 8;
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
                        *(wstatus_ptr as *mut u32) = status;
                    }
                    return 42; // fake child PID for vfork path
                }
                return -10; // -ECHILD
            }

            // Block until a child exits.
            TASK_TABLE[CURRENT_TASK_IDX].state = TaskState::WaitingForChild;
            {
                let sched = crate::scheduler::get();
                // Mark Interruptible so schedule() doesn't re-enqueue the parent.
                sched.tasks[CURRENT_TASK_IDX].entity.state = rux_sched::TaskState::Interruptible;
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
        if buf == 0 || size < len + 1 { return -34; } // -ERANGE
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
    if buf == 0 { return -14; }
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
pub fn clock_gettime(_clockid: usize, tp: usize) -> isize {
    if tp == 0 { return -14; }
    let ticks = Arch::ticks();
    unsafe {
        *(tp as *mut u64) = ticks / 1000;
        *((tp + 8) as *mut u64) = (ticks % 1000) * 1_000_000;
    }
    0
}

pub fn nanosleep(req_ptr: usize) -> isize {
    if req_ptr == 0 { return -14; }
    unsafe {
        use rux_arch::HaltOps;
        let tv_sec = *(req_ptr as *const u64);
        let tv_nsec = *((req_ptr + 8) as *const u64);
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
            *(old_limit as *mut u64) = rlim_infinity; // rlim_cur
            *((old_limit + 8) as *mut u64) = rlim_infinity; // rlim_max
        }
    }
    0
}
