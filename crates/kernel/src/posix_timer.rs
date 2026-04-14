//! POSIX per-process timers (timer_create / timer_settime / timer_gettime /
//! timer_delete / timer_getoverrun).
//!
//! Stores timers in a global table indexed by timer ID.  Expiry is driven
//! by the deadline queue (KIND_POSIX_TIMER) and processed in wake_sleepers().

use crate::deadline_queue::{DEADLINE_QUEUE, KIND_POSIX_TIMER};
use crate::task_table::{current_task_idx, TASK_TABLE};
use rux_arch::TimerOps;

/// Maximum simultaneous POSIX timers across all processes.
const MAX_POSIX_TIMERS: usize = 128;

/// SIGEV_* notification modes (from <signal.h>).
const SIGEV_SIGNAL: i32 = 0;
const SIGEV_NONE: i32 = 1;

/// TIMER_ABSTIME flag for timer_settime.
const TIMER_ABSTIME: usize = 1;

#[derive(Clone, Copy)]
struct PosixTimer {
    active: bool,
    owner_idx: u16,     // task table index
    clock_id: u8,       // CLOCK_REALTIME=0, CLOCK_MONOTONIC=1, etc.
    signo: u8,          // signal to deliver (0 = SIGEV_NONE)
    interval_ms: u64,   // reload interval in ticks (0 = one-shot)
    deadline: u64,       // next expiry in ticks (0 = disarmed)
    overrun: u32,        // overrun count
}

impl PosixTimer {
    const EMPTY: Self = Self {
        active: false, owner_idx: 0, clock_id: 0, signo: 0,
        interval_ms: 0, deadline: 0, overrun: 0,
    };
}

static mut POSIX_TIMERS: [PosixTimer; MAX_POSIX_TIMERS] = [PosixTimer::EMPTY; MAX_POSIX_TIMERS];

// ── Helpers ────────────────────────────────────────────────────────────

fn valid_clock(id: usize) -> bool {
    matches!(id, 0 | 1 | 4 | 6 | 7) // REALTIME, MONOTONIC, MONOTONIC_RAW, BOOTTIME, REALTIME_ALARM (accept broadly)
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

/// Write itimerspec to user pointer from (interval_ms, remaining_ms).
unsafe fn write_itimerspec(ptr: usize, interval_ms: u64, remaining_ms: u64) {
    crate::uaccess::put_user(ptr, interval_ms / 1000);                 // interval.tv_sec
    crate::uaccess::put_user(ptr + 8, (interval_ms % 1000) * 1_000_000); // interval.tv_nsec
    crate::uaccess::put_user(ptr + 16, remaining_ms / 1000);            // value.tv_sec
    crate::uaccess::put_user(ptr + 24, (remaining_ms % 1000) * 1_000_000); // value.tv_nsec
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
    if sevp != 0 {
        if crate::uaccess::validate_user_ptr(sevp, 64).is_err() {
            return crate::errno::EFAULT;
        }
        unsafe {
            // struct sigevent layout (Linux x86_64):
            //   sigev_value:  offset 0  (8 bytes, union sigval)
            //   sigev_signo:  offset 8  (4 bytes)
            //   sigev_notify: offset 12 (4 bytes)
            let notify: i32 = crate::uaccess::get_user(sevp + 12);
            let sig: i32 = crate::uaccess::get_user(sevp + 8);
            match notify {
                n if n == SIGEV_SIGNAL => {
                    if sig < 1 || sig > 64 { return crate::errno::EINVAL; }
                    signo = sig as u8;
                }
                n if n == SIGEV_NONE => {
                    signo = 0; // no signal delivery
                }
                _ => return crate::errno::EINVAL, // SIGEV_THREAD etc. not supported
            }
        }
    }

    unsafe {
        let idx = current_task_idx();
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
            interval_ms: 0,
            deadline: 0,
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

        // Write old value if requested
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
                // Absolute time: convert to deadline. For simplicity, treat
                // as ms offset from boot (CLOCK_MONOTONIC) or epoch-based.
                // Since our ticks() is ms-since-boot, absolute MONOTONIC
                // deadlines map directly. For REALTIME, this is approximate.
                t.deadline = value_ms;
                if t.deadline <= now {
                    // Already expired — fire immediately on next tick
                    t.deadline = now + 1;
                }
            } else {
                t.deadline = now + value_ms;
            }
            DEADLINE_QUEUE.insert(t.deadline, t.owner_idx, KIND_POSIX_TIMER);
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
        let now = crate::arch::Arch::ticks();
        let remaining = if t.deadline > 0 && t.deadline > now {
            t.deadline - now
        } else { 0 };
        write_itimerspec(value_ptr, t.interval_ms, remaining);
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
            crate::task_table::send_signal_to(task_idx as usize, t.signo);
        }

        // Re-arm or disarm
        if t.interval_ms > 0 {
            // Count overruns: how many intervals elapsed since deadline
            let elapsed = now - t.deadline;
            if elapsed > t.interval_ms {
                t.overrun += (elapsed / t.interval_ms) as u32;
            }
            t.deadline = now + t.interval_ms;
            DEADLINE_QUEUE.insert(t.deadline, task_idx, KIND_POSIX_TIMER);
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
        }
    }
}
