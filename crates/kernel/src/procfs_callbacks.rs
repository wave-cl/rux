/// Shared ProcFs kernel callbacks — eliminates triple duplication across
/// x86_64/init.rs, aarch64/init.rs, and syscall/mount.rs.

use crate::task_table::*;

pub fn get_active_pids(buf: &mut [u32]) -> usize {
    unsafe {
        let mut count = 0;
        for i in 0..MAX_PROCS {
            if TASK_TABLE[i].active && TASK_TABLE[i].pid > 0
                && TASK_TABLE[i].state != TaskState::Free
                && TASK_TABLE[i].state != TaskState::Zombie
                && count < buf.len()
            {
                buf[count] = TASK_TABLE[i].pid;
                count += 1;
            }
        }
        count
    }
}

pub fn get_current_pid() -> u32 {
    current_pid()
}

pub fn get_task_cmdline(pid: u32, buf: &mut [u8]) -> usize {
    unsafe {
        for i in 0..MAX_PROCS {
            if TASK_TABLE[i].active && TASK_TABLE[i].pid == pid {
                let len = (TASK_TABLE[i].cmdline_len as usize).min(buf.len());
                buf[..len].copy_from_slice(&TASK_TABLE[i].cmdline[..len]);
                return len;
            }
        }
        0
    }
}

pub fn get_task_info(pid: u32) -> rux_fs::procfs::TaskInfo {
    unsafe {
        for i in 0..MAX_PROCS {
            if TASK_TABLE[i].active && TASK_TABLE[i].pid == pid {
                return rux_fs::procfs::TaskInfo {
                    pid: TASK_TABLE[i].pid, ppid: TASK_TABLE[i].ppid,
                    pgid: TASK_TABLE[i].pgid, sid: TASK_TABLE[i].sid,
                    uid: TASK_TABLE[i].uid, gid: TASK_TABLE[i].gid,
                    state: TASK_TABLE[i].state as u8, threads: 1,
                    rss_pages: TASK_TABLE[i].rss_pages,
                    brk_addr: TASK_TABLE[i].program_brk,
                };
            }
        }
        rux_fs::procfs::TaskInfo::default()
    }
}

pub fn get_idle_ticks() -> u64 {
    crate::idle::idle_ticks()
}

pub fn get_task_cwd(pid: u32, buf: &mut [u8]) -> usize {
    unsafe {
        for i in 0..MAX_PROCS {
            if TASK_TABLE[i].active && TASK_TABLE[i].pid == pid {
                let len = TASK_TABLE[i].fs_ctx.cwd_path_len.min(buf.len());
                buf[..len].copy_from_slice(&TASK_TABLE[i].fs_ctx.cwd_path[..len]);
                return len;
            }
        }
        0
    }
}

pub fn get_task_environ(pid: u32, buf: &mut [u8]) -> usize {
    unsafe {
        for i in 0..MAX_PROCS {
            if TASK_TABLE[i].active && TASK_TABLE[i].pid == pid {
                let len = (TASK_TABLE[i].environ_len as usize).min(buf.len());
                buf[..len].copy_from_slice(&TASK_TABLE[i].environ[..len]);
                return len;
            }
        }
        0
    }
}

/// Build a ProcFs with the standard kernel callbacks.
/// `get_ticks` and `get_total_frames` are parameterized for arch differences.
pub const fn new_procfs(
    get_ticks: fn() -> u64,
    get_total_frames: fn() -> usize,
    get_free_frames: fn() -> usize,
) -> rux_fs::procfs::ProcFs {
    rux_fs::procfs::ProcFs::new(
        get_ticks,
        get_total_frames,
        get_free_frames,
        get_active_pids,
        get_current_pid,
        get_task_cmdline,
        get_task_info,
        get_idle_ticks,
        get_task_cwd,
        get_task_environ,
    )
}
