//! POSIX per-process timers (timer_create / timer_settime / timer_gettime /
//! timer_delete / timer_getoverrun).
//!
//! Stores timers in a global table indexed by timer ID.  Expiry is driven
//! by the deadline queue (KIND_POSIX_TIMER) and processed in wake_sleepers().

use crate::deadline_queue::{dq_insert, KIND_POSIX_TIMER};
use crate::task_table::{current_task_idx, TASK_TABLE};
use rux_arch::TimerOps;

/// Maximum simultaneous POSIX timers across all processes.
const MAX_POSIX_TIMERS: usize = 128;

/// SIGEV_* notification modes (from <signal.h>).
const SIGEV_SIGNAL: i32 = 0;
const SIGEV_NONE: i32 = 1;
const SIGEV_THREAD_ID: i32 = 4;

/// TIMER_ABSTIME flag for timer_settime.
const TIMER_ABSTIME: usize = 1;

#[derive(Clone, Copy)]
struct PosixTimer {
    active: bool,
    owner_idx: u16,     // task table index of creating process
    clock_id: u8,       // CLOCK_REALTIME=0, CLOCK_MONOTONIC=1, CPUTIME=2/3
    signo: u8,          // signal to deliver (0 = SIGEV_NONE)
    #[allow(dead_code)] // retained for future SIGEV_NONE handling
    sigev_notify: u8,   // SIGEV_SIGNAL=0, SIGEV_NONE=1, SIGEV_THREAD_ID=4
    target_idx: u16,    // task index for signal delivery (SIGEV_THREAD_ID)
    // Wall-clock fields (ms, used for clock_id 0/1/4/6/7)
    interval_ms: u64,   // reload interval in ticks (0 = one-shot)
    deadline: u64,       // next expiry in ticks (0 = disarmed)
    // CPU-time fields (ns, used for clock_id 2/3)
    interval_ns: u64,    // reload interval in ns (0 = one-shot)
    cpu_deadline_ns: u64,// next expiry as accumulated CPU ns (0 = disarmed)
    overrun: u32,        // overrun count
}

impl PosixTimer {
    const EMPTY: Self = Self {
        active: false, owner_idx: 0, clock_id: 0, signo: 0,
        sigev_notify: 0, target_idx: 0,
        interval_ms: 0, deadline: 0,
        interval_ns: 0, cpu_deadline_ns: 0,
        overrun: 0,
    };
    /// True if this timer uses a CPU-time clock (CLOCK_PROCESS/THREAD_CPUTIME_ID).
    fn is_cpu_clock(&self) -> bool { self.clock_id == 2 || self.clock_id == 3 }
}

static mut POSIX_TIMERS: [PosixTimer; MAX_POSIX_TIMERS] = [PosixTimer::EMPTY; MAX_POSIX_TIMERS];

// ── Helpers ────────────────────────────────────────────────────────────

fn valid_clock(id: usize) -> bool {
    matches!(id, 0 | 1 | 2 | 3 | 4 | 6 | 7) // REALTIME, MONOTONIC, PROC_CPUTIME, THREAD_CPUTIME, MONOTONIC_RAW, BOOTTIME, REALTIME_ALARM
}

/// Read accumulated CPU time (ns) for a CPU-time timer's reference clock.
/// CLOCK_PROCESS_CPUTIME_ID (2): sum across all threads in the tgid.
/// CLOCK_THREAD_CPUTIME_ID  (3): just the target task.
unsafe fn cpu_time_baseline(timer: &PosixTimer) -> u64 {
    if timer.clock_id == 3 {
        // Per-thread: target task's CPU time
        TASK_TABLE[timer.target_idx as usize].cpu_time_ns
    } else {
        // Per-process: sum across thread group
        let tgid = TASK_TABLE[timer.owner_idx as usize].tgid;
        let mut ns = 0u64;
        for i in 0..crate::task_table::MAX_PROCS {
            if TASK_TABLE[i].active && TASK_TABLE[i].tgid == tgid {
                ns += TASK_TABLE[i].cpu_time_ns;
            }
        }
        ns
    }
}

/// Read itimerspec from user pointer: {interval: {sec,nsec}, value: {sec,nsec}}
unsafe fn read_itimerspec(ptr: usize) -> (u64, u64) {
    let int_sec: u64 = crate::uaccess::get_user(ptr);
    let int_nsec: u64 = crate::uaccess::get_user(ptr + 8);
    let val_sec: u64 = crate::uaccess::get_user(ptr + 16);
    let val_nsec: u64 = crate::uaccess::get_user(ptr + 24);
    let interval_ms = int_sec * 1000 + int_nsec / 1_000_000;
    let value_ms = val_sec * 1000 + val_nsec / 1_000_000;
    (interval_ms, value_ms)
}

/// Read itimerspec as nanoseconds (used for CPU-time clocks).
unsafe fn read_itimerspec_ns(ptr: usize) -> (u64, u64) {
    let int_sec: u64 = crate::uaccess::get_user(ptr);
    let int_nsec: u64 = crate::uaccess::get_user(ptr + 8);
    let val_sec: u64 = crate::uaccess::get_user(ptr + 16);
    let val_nsec: u64 = crate::uaccess::get_user(ptr + 24);
    (int_sec * 1_000_000_000 + int_nsec, val_sec * 1_000_000_000 + val_nsec)
}

/// Write itimerspec to user pointer from (interval_ms, remaining_ms).
unsafe fn write_itimerspec(ptr: usize, interval_ms: u64, remaining_ms: u64) {
    crate::uaccess::put_user(ptr, interval_ms / 1000);                 // interval.tv_sec
    crate::uaccess::put_user(ptr + 8, (interval_ms % 1000) * 1_000_000); // interval.tv_nsec
    crate::uaccess::put_user(ptr + 16, remaining_ms / 1000);            // value.tv_sec
    crate::uaccess::put_user(ptr + 24, (remaining_ms % 1000) * 1_000_000); // value.tv_nsec
}

/// Write itimerspec from nanoseconds.
unsafe fn write_itimerspec_ns(ptr: usize, interval_ns: u64, remaining_ns: u64) {
    crate::uaccess::put_user(ptr, interval_ns / 1_000_000_000);
    crate::uaccess::put_user(ptr + 8, interval_ns % 1_000_000_000);
    crate::uaccess::put_user(ptr + 16, remaining_ns / 1_000_000_000);
    crate::uaccess::put_user(ptr + 24, remaining_ns % 1_000_000_000);
}

// ── Syscall handlers ───────────────────────────────────────────────────

/// timer_create(clockid, sevp, timerid_ptr) → 0 or -errno
pub fn sys_timer_create(clockid: usize, sevp: usize, timerid_ptr: usize) -> isize {
    if !valid_clock(clockid) { return crate::errno::EINVAL; }
    if timerid_ptr == 0 || crate::uaccess::validate_user_ptr(timerid_ptr, 4).is_err() {
        return crate::errno::EFAULT;
    }

    // Parse sigevent (if provided)
    let mut signo: u8 = 14; // default: SIGALRM
    let mut notify_mode: u8 = SIGEV_SIGNAL as u8;
    let mut target_tid: u32 = 0;
    if sevp != 0 {
        if crate::uaccess::validate_user_ptr(sevp, 64).is_err() {
            return crate::errno::EFAULT;
        }
        unsafe {
            // struct sigevent layout (Linux x86_64/aarch64):
            //   sigev_value:  offset 0  (8 bytes, union sigval)
            //   sigev_signo:  offset 8  (4 bytes)
            //   sigev_notify: offset 12 (4 bytes)
            //   sigev_notify_thread_id / sigev_notify_function: offset 16
            let notify: i32 = crate::uaccess::get_user(sevp + 12);
            let sig: i32 = crate::uaccess::get_user(sevp + 8);
            match notify {
                n if n == SIGEV_SIGNAL || n == SIGEV_THREAD_ID => {
                    if sig < 1 || sig > 64 { return crate::errno::EINVAL; }
                    signo = sig as u8;
                    notify_mode = n as u8;
                    if n == SIGEV_THREAD_ID {
                        target_tid = crate::uaccess::get_user(sevp + 16);
                    }
                }
                n if n == SIGEV_NONE => {
                    signo = 0;
                    notify_mode = SIGEV_NONE as u8;
                }
                _ => return crate::errno::EINVAL,
            }
        }
    }

    unsafe {
        let idx = current_task_idx();

        // Resolve target task for SIGEV_THREAD_ID
        let target_idx = if notify_mode == SIGEV_THREAD_ID as u8 {
            match crate::task_table::find_task_by_pid(target_tid) {
                Some(ti) => ti as u16,
                None => return crate::errno::EINVAL,
            }
        } else {
            idx as u16
        };

        // Allocate a free slot
        let slot = match (0..MAX_POSIX_TIMERS).find(|&i| !POSIX_TIMERS[i].active) {
            Some(i) => i,
            None => return crate::errno::EAGAIN,
        };
        POSIX_TIMERS[slot] = PosixTimer {
            active: true,
            owner_idx: idx as u16,
            clock_id: clockid as u8,
            signo,
            sigev_notify: notify_mode,
            target_idx,
            interval_ms: 0,
            deadline: 0,
            interval_ns: 0,
            cpu_deadline_ns: 0,
            overrun: 0,
        };
        // Write timer ID to user
        crate::uaccess::put_user(timerid_ptr, slot as u32);
    }
    0
}

/// timer_settime(timerid, flags, new_value, old_value) → 0 or -errno
pub fn sys_timer_settime(timerid: usize, flags: usize, new_ptr: usize, old_ptr: usize) -> isize {
    if new_ptr == 0 || crate::uaccess::validate_user_ptr(new_ptr, 32).is_err() {
        return crate::errno::EFAULT;
    }
    if timerid >= MAX_POSIX_TIMERS { return crate::errno::EINVAL; }
    unsafe {
        let t = &mut POSIX_TIMERS[timerid];
        if !t.active || t.owner_idx != current_task_idx() as u16 {
            return crate::errno::EINVAL;
        }

        let now = crate::arch::Arch::ticks();

        if t.is_cpu_clock() {
            // CPU-time timer path
            if old_ptr != 0 {
                if crate::uaccess::validate_user_ptr(old_ptr, 32).is_err() {
                    return crate::errno::EFAULT;
                }
                let baseline = cpu_time_baseline(t);
                let remaining = if t.cpu_deadline_ns > baseline {
                    t.cpu_deadline_ns - baseline
                } else { 0 };
                write_itimerspec_ns(old_ptr, t.interval_ns, remaining);
            }
            let (interval_ns, value_ns) = read_itimerspec_ns(new_ptr);
            t.interval_ns = interval_ns;
            t.overrun = 0;
            if value_ns > 0 {
                let baseline = cpu_time_baseline(t);
                t.cpu_deadline_ns = if flags & TIMER_ABSTIME != 0 {
                    value_ns // absolute ns of accumulated CPU time
                } else {
                    baseline + value_ns
                };
            } else {
                t.cpu_deadline_ns = 0; // disarm
            }
            return 0;
        }

        // Wall-clock timer path
        if old_ptr != 0 {
            if crate::uaccess::validate_user_ptr(old_ptr, 32).is_err() {
                return crate::errno::EFAULT;
            }
            let remaining = if t.deadline > 0 && t.deadline > now {
                t.deadline - now
            } else { 0 };
            write_itimerspec(old_ptr, t.interval_ms, remaining);
        }

        // Read new itimerspec
        let (interval_ms, value_ms) = read_itimerspec(new_ptr);
        t.interval_ms = interval_ms;
        t.overrun = 0;

        if value_ms > 0 {
            if flags & TIMER_ABSTIME != 0 {
                if t.clock_id == 0 {
                    // CLOCK_REALTIME: value_ms is unix-epoch ms.
                    // Convert to monotonic deadline by subtracting boot epoch.
                    let boot_ms = crate::syscall::process::boot_epoch() * 1000;
                    if value_ms <= boot_ms {
                        t.deadline = now + 1;
                    } else {
                        let monotonic_target = value_ms - boot_ms;
                        t.deadline = if monotonic_target <= now { now + 1 } else { monotonic_target };
                    }
                } else {
                    // CLOCK_MONOTONIC etc.: value_ms is already ms-since-boot.
                    t.deadline = if value_ms <= now { now + 1 } else { value_ms };
                }
            } else {
                t.deadline = now + value_ms;
            }
            dq_insert(t.deadline, t.owner_idx, KIND_POSIX_TIMER);
        } else {
            t.deadline = 0; // disarm
        }
    }
    0
}

/// timer_gettime(timerid, curr_value) → 0 or -errno
pub fn sys_timer_gettime(timerid: usize, value_ptr: usize) -> isize {
    if value_ptr == 0 || crate::uaccess::validate_user_ptr(value_ptr, 32).is_err() {
        return crate::errno::EFAULT;
    }
    if timerid >= MAX_POSIX_TIMERS { return crate::errno::EINVAL; }
    unsafe {
        let t = &POSIX_TIMERS[timerid];
        if !t.active || t.owner_idx != current_task_idx() as u16 {
            return crate::errno::EINVAL;
        }
        if t.is_cpu_clock() {
            let baseline = cpu_time_baseline(t);
            let remaining = if t.cpu_deadline_ns > baseline {
                t.cpu_deadline_ns - baseline
            } else { 0 };
            write_itimerspec_ns(value_ptr, t.interval_ns, remaining);
        } else {
            let now = crate::arch::Arch::ticks();
            let remaining = if t.deadline > 0 && t.deadline > now {
                t.deadline - now
            } else { 0 };
            write_itimerspec(value_ptr, t.interval_ms, remaining);
        }
    }
    0
}

/// timer_delete(timerid) → 0 or -errno
pub fn sys_timer_delete(timerid: usize) -> isize {
    if timerid >= MAX_POSIX_TIMERS { return crate::errno::EINVAL; }
    unsafe {
        let t = &mut POSIX_TIMERS[timerid];
        if !t.active || t.owner_idx != current_task_idx() as u16 {
            return crate::errno::EINVAL;
        }
        t.active = false;
        t.deadline = 0;
        t.cpu_deadline_ns = 0;
        // Lazy removal: stale deadline queue entries are skipped in wake_sleepers
    }
    0
}

/// timer_getoverrun(timerid) → overrun count or -errno
pub fn sys_timer_getoverrun(timerid: usize) -> isize {
    if timerid >= MAX_POSIX_TIMERS { return crate::errno::EINVAL; }
    unsafe {
        let t = &mut POSIX_TIMERS[timerid];
        if !t.active || t.owner_idx != current_task_idx() as u16 {
            return crate::errno::EINVAL;
        }
        let count = t.overrun;
        t.overrun = 0;
        count as isize
    }
}

// ── Deadline queue callback ────────────────────────────────────────────

/// Called from wake_sleepers() when a KIND_POSIX_TIMER entry expires.
/// `task_idx` is the owner (stored in deadline entry's task_idx field).
pub unsafe fn handle_posix_timer_expiry(task_idx: u16, now: u64) {
    for i in 0..MAX_POSIX_TIMERS {
        let t = &mut POSIX_TIMERS[i];
        if !t.active || t.owner_idx != task_idx { continue; }
        if t.deadline == 0 || t.deadline > now { continue; }

        // Deliver signal (if not SIGEV_NONE)
        if t.signo > 0 {
            let deliver_to = t.target_idx as usize;
            let info = rux_proc::signal::SigInfo {
                signo: t.signo,
                code: rux_proc::signal::SigCode::Timer,
                _pad0: [0; 2],
                pid: rux_proc::id::Pid(0),
                uid: rux_proc::id::Uid(0),
                _pad1: [0; 4],
                addr: i,         // timer ID (slot index)
                status: t.overrun as i32,
                _pad2: [0; 4],
            };
            crate::task_table::send_signal_to_with_info(deliver_to, t.signo, info);
        }

        // Re-arm or disarm
        if t.interval_ms > 0 {
            // Count overruns: how many intervals elapsed since deadline
            let elapsed = now - t.deadline;
            if elapsed > t.interval_ms {
                t.overrun += (elapsed / t.interval_ms) as u32;
            }
            t.deadline = now + t.interval_ms;
            dq_insert(t.deadline, task_idx, KIND_POSIX_TIMER);
        } else {
            t.deadline = 0; // one-shot: done
        }

        return; // process one timer per expiry event
    }
}

/// Clean up all POSIX timers owned by a task (called on exit).
pub unsafe fn cleanup_posix_timers(task_idx: usize) {
    for i in 0..MAX_POSIX_TIMERS {
        if POSIX_TIMERS[i].active && POSIX_TIMERS[i].owner_idx == task_idx as u16 {
            POSIX_TIMERS[i].active = false;
            POSIX_TIMERS[i].deadline = 0;
            POSIX_TIMERS[i].cpu_deadline_ns = 0;
        }
    }
}

/// Called from the scheduler tick after CPU time accounting.
/// Checks all CPU-time POSIX timers owned by tasks in `task_idx`'s
/// thread group (for CLOCK_PROCESS_CPUTIME_ID) or by `task_idx`
/// directly (for CLOCK_THREAD_CPUTIME_ID).
pub unsafe fn check_cpu_timers(task_idx: usize) {
    if task_idx >= crate::task_table::MAX_PROCS { return; }
    if !TASK_TABLE[task_idx].active { return; }
    let my_tgid = TASK_TABLE[task_idx].tgid;

    for i in 0..MAX_POSIX_TIMERS {
        let t = &mut POSIX_TIMERS[i];
        if !t.active || t.cpu_deadline_ns == 0 { continue; }
        if !t.is_cpu_clock() { continue; }

        // Only check timers belonging to this task's process or thread.
        let belongs = if t.clock_id == 3 {
            t.target_idx as usize == task_idx
        } else {
            // Per-process: any task in the same tgid as the timer's owner
            TASK_TABLE[t.owner_idx as usize].tgid == my_tgid
        };
        if !belongs { continue; }

        let baseline = cpu_time_baseline(t);
        if baseline < t.cpu_deadline_ns { continue; }

        // Fire signal
        if t.signo > 0 {
            let deliver_to = t.target_idx as usize;
            let info = rux_proc::signal::SigInfo {
                signo: t.signo,
                code: rux_proc::signal::SigCode::Timer,
                _pad0: [0; 2],
                pid: rux_proc::id::Pid(0),
                uid: rux_proc::id::Uid(0),
                _pad1: [0; 4],
                addr: i,
                status: t.overrun as i32,
                _pad2: [0; 4],
            };
            crate::task_table::send_signal_to_with_info(deliver_to, t.signo, info);
        }

        // Re-arm or disarm
        if t.interval_ns > 0 {
            let elapsed = baseline - t.cpu_deadline_ns;
            if elapsed > t.interval_ns {
                t.overrun += (elapsed / t.interval_ns) as u32;
            }
            t.cpu_deadline_ns = baseline + t.interval_ns;
        } else {
            t.cpu_deadline_ns = 0;
        }
    }
}
