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

/// Helper: look up a task slot by PID and apply a closure.
/// Returns the closure's result, or a default if not found.
unsafe fn with_task<T>(pid: u32, default: T, f: impl FnOnce(usize) -> T) -> T {
    match find_task_by_pid(pid) {
        Some(i) => f(i),
        None => default,
    }
}

pub fn get_task_comm(pid: u32, buf: &mut [u8]) -> usize {
    unsafe { with_task(pid, 0, |i| {
        let len = (TASK_TABLE[i].comm_len as usize).min(buf.len());
        buf[..len].copy_from_slice(&TASK_TABLE[i].comm[..len]);
        len
    })}
}

pub fn get_task_cmdline(pid: u32, buf: &mut [u8]) -> usize {
    unsafe { with_task(pid, 0, |i| {
        let len = (TASK_TABLE[i].cmdline_len as usize).min(buf.len());
        buf[..len].copy_from_slice(&TASK_TABLE[i].cmdline[..len]);
        len
    })}
}

pub fn get_task_info(pid: u32) -> rux_fs::procfs::TaskInfo {
    unsafe { with_task(pid, rux_fs::procfs::TaskInfo::default(), |i| {
        let t = &TASK_TABLE[i];
        rux_fs::procfs::TaskInfo {
            pid: t.pid, ppid: t.ppid, pgid: t.pgid, sid: t.sid,
            uid: t.uid, gid: t.gid, state: t.state as u8, threads: 1,
            rss_pages: t.rss_pages, brk_addr: t.program_brk,
        }
    })}
}

pub fn get_idle_ticks() -> u64 {
    crate::idle::idle_ticks()
}

pub fn get_task_cwd(pid: u32, buf: &mut [u8]) -> usize {
    unsafe { with_task(pid, 0, |i| {
        let len = TASK_TABLE[i].fs_ctx.cwd_path_len.min(buf.len());
        buf[..len].copy_from_slice(&TASK_TABLE[i].fs_ctx.cwd_path[..len]);
        len
    })}
}

pub fn get_task_environ(pid: u32, buf: &mut [u8]) -> usize {
    unsafe { with_task(pid, 0, |i| {
        let len = (TASK_TABLE[i].environ_len as usize).min(buf.len());
        buf[..len].copy_from_slice(&TASK_TABLE[i].environ[..len]);
        len
    })}
}

/// Generate /proc/[pid]/maps from VMA list.
pub fn get_task_maps(pid: u32, buf: &mut [u8]) -> usize {
    unsafe { with_task(pid, 0, |i| {
        let vmas = crate::task_table::vma_list(i);
        let mut pos = 0;
        for v in 0..vmas.count as usize {
            let vma = &vmas.entries[v];
            if pos + 80 > buf.len() { break; }
            pos += fmt_hex_pad(&mut buf[pos..], vma.start.as_usize());
            buf[pos] = b'-'; pos += 1;
            pos += fmt_hex_pad(&mut buf[pos..], vma.end.as_usize());
            buf[pos] = b' '; pos += 1;
            buf[pos] = if vma.flags.contains(rux_mm::MappingFlags::READ) { b'r' } else { b'-' }; pos += 1;
            buf[pos] = if vma.flags.contains(rux_mm::MappingFlags::WRITE) { b'w' } else { b'-' }; pos += 1;
            buf[pos] = if vma.flags.contains(rux_mm::MappingFlags::EXECUTE) { b'x' } else { b'-' }; pos += 1;
            buf[pos] = if vma.kind == rux_mm::vma::VmaKind::Shared { b's' } else { b'p' }; pos += 1;
            buf[pos] = b' '; pos += 1;
            pos += fmt_hex_pad(&mut buf[pos..], vma.offset as usize);
            let tail = b" 00:00 0\n";
            buf[pos..pos + tail.len()].copy_from_slice(tail);
            pos += tail.len();
        }
        pos
    })}
}

fn fmt_hex_pad(buf: &mut [u8], val: usize) -> usize {
    let mut tmp = [0u8; 16];
    let bytes = rux_klib::fmt::usize_to_hex(&mut tmp, val);
    let pad = if bytes.len() < 8 { 8 - bytes.len() } else { 0 };
    let total = pad + bytes.len();
    if total > buf.len() { return 0; }
    for i in 0..pad { buf[i] = b'0'; }
    buf[pad..total].copy_from_slice(bytes);
    total
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
        get_task_comm,
        get_task_info,
        get_idle_ticks,
        get_task_cwd,
        get_task_environ,
        get_task_maps,
    )
}
