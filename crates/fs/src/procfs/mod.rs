/// procfs — read-only virtual filesystem that synthesizes content on read.
///
/// Implements the FileSystem trait with:
/// - Fixed inodes for system info files (/proc/uptime, meminfo, etc.)
/// - Dynamic inodes for per-PID directories (/proc/1/stat, etc.)
///
/// Content is generated on-the-fly from kernel state via injected callbacks.

use crate::{FileSystem, FileName, InodeId, InodeStat, DirEntry, VfsError, InodeType};
use crate::{S_IFDIR, S_IFREG};

// ── Inode scheme ────────────────────────────────────────────────────
//
// 0         = /proc (root directory)
// 1-5       = system files (uptime, meminfo, stat, version, loadavg)
// 100+pid   = /proc/[pid] directory
// 1000+pid  = /proc/[pid]/stat
// 2000+pid  = /proc/[pid]/cmdline
// 3000+pid  = /proc/[pid]/statm
// 4000+pid  = /proc/[pid]/status

const INO_ROOT: InodeId = 0;
const INO_UPTIME: InodeId = 1;
const INO_MEMINFO: InodeId = 2;
const INO_STAT: InodeId = 3;
const INO_VERSION: InodeId = 4;
const INO_LOADAVG: InodeId = 5;
const INO_SELF: InodeId = 6; // symlink "self" → "1"
const INO_MOUNTS: InodeId = 7;
const INO_FILESYSTEMS: InodeId = 8;
const INO_CMDLINE: InodeId = 9;
// /proc/sys/ hierarchy
const INO_SYS_DIR: InodeId = 10;         // /proc/sys
const INO_SYS_KERNEL_DIR: InodeId = 11;  // /proc/sys/kernel
const INO_SYS_VM_DIR: InodeId = 12;      // /proc/sys/vm
const INO_SYS_K_OSRELEASE: InodeId = 13; // /proc/sys/kernel/osrelease
const INO_SYS_K_HOSTNAME: InodeId = 14;  // /proc/sys/kernel/hostname
const INO_SYS_K_OSTYPE: InodeId = 15;    // /proc/sys/kernel/ostype
const INO_SYS_K_RANDOM_DIR: InodeId = 16;// /proc/sys/kernel/random
const INO_SYS_K_RANDOM_UUID: InodeId = 17;// /proc/sys/kernel/random/uuid
const INO_SYS_VM_OVERCOMMIT: InodeId = 18;// /proc/sys/vm/overcommit_memory
const INO_NET_DIR: InodeId = 19;          // /proc/net
const INO_NET_TCP: InodeId = 20;          // /proc/net/tcp
const INO_NET_UDP: InodeId = 21;          // /proc/net/udp
const INO_CPUINFO: InodeId = 22;          // /proc/cpuinfo
const INO_NET_DEV: InodeId = 23;          // /proc/net/dev

const NUM_SYS_ENTRIES: usize = 12;

const SYS_ENTRIES: [(&[u8], InodeId); NUM_SYS_ENTRIES] = [
    (b"uptime", INO_UPTIME),
    (b"meminfo", INO_MEMINFO),
    (b"stat", INO_STAT),
    (b"version", INO_VERSION),
    (b"loadavg", INO_LOADAVG),
    (b"self", INO_SELF),
    (b"mounts", INO_MOUNTS),
    (b"filesystems", INO_FILESYSTEMS),
    (b"cmdline", INO_CMDLINE),
    (b"sys", INO_SYS_DIR),
    (b"net", INO_NET_DIR),
    (b"cpuinfo", INO_CPUINFO),
];

const PID_DIR_BASE: InodeId = 100;
const PID_STAT_BASE: InodeId = 1000;
const PID_CMDLINE_BASE: InodeId = 2000;
const PID_STATM_BASE: InodeId = 3000;
const PID_STATUS_BASE: InodeId = 4000;
const PID_EXE_BASE: InodeId = 5000;    // /proc/[pid]/exe symlink
const PID_MAPS_BASE: InodeId = 6000;   // /proc/[pid]/maps
const PID_FD_DIR_BASE: InodeId = 7000; // /proc/[pid]/fd directory
const PID_COMM_BASE: InodeId = 8000;  // /proc/[pid]/comm
const PID_ENVIRON_BASE: InodeId = 8100; // /proc/[pid]/environ
const PID_CGROUP_BASE: InodeId = 8200;  // /proc/[pid]/cgroup
const PID_MOUNTINFO_BASE: InodeId = 8300; // /proc/[pid]/mountinfo
const PID_OOM_BASE: InodeId = 8400;   // /proc/[pid]/oom_score
const PID_CWD_BASE: InodeId = 8500;   // /proc/[pid]/cwd (symlink)
const PID_ROOT_BASE: InodeId = 8600;  // /proc/[pid]/root (symlink)
const PID_LIMITS_BASE: InodeId = 8700; // /proc/[pid]/limits
const PID_IO_BASE: InodeId = 8800;    // /proc/[pid]/io
const PID_TASK_DIR_BASE: InodeId = 8900; // /proc/[pid]/task directory

const PID_SUBENTRIES: [(&[u8], InodeId); 17] = [
    (b"stat", PID_STAT_BASE),
    (b"cmdline", PID_CMDLINE_BASE),
    (b"statm", PID_STATM_BASE),
    (b"status", PID_STATUS_BASE),
    (b"exe", PID_EXE_BASE),
    (b"maps", PID_MAPS_BASE),
    (b"fd", PID_FD_DIR_BASE),
    (b"comm", PID_COMM_BASE),
    (b"environ", PID_ENVIRON_BASE),
    (b"cgroup", PID_CGROUP_BASE),
    (b"mountinfo", PID_MOUNTINFO_BASE),
    (b"oom_score", PID_OOM_BASE),
    (b"cwd", PID_CWD_BASE),
    (b"root", PID_ROOT_BASE),
    (b"limits", PID_LIMITS_BASE),
    (b"io", PID_IO_BASE),
    (b"task", PID_TASK_DIR_BASE),
];

fn is_pid_dir(ino: InodeId) -> bool { ino >= PID_DIR_BASE && ino < PID_STAT_BASE }
fn is_pid_fd_dir(ino: InodeId) -> bool { ino >= PID_FD_DIR_BASE && ino < PID_FD_DIR_BASE + 100 }
fn is_pid_task_dir(ino: InodeId) -> bool { ino >= PID_TASK_DIR_BASE && ino < PID_TASK_DIR_BASE + 100 }
fn is_pid_exe(ino: InodeId) -> bool { ino >= PID_EXE_BASE && ino < PID_MAPS_BASE }
fn is_pid_cwd(ino: InodeId) -> bool { ino >= PID_CWD_BASE && ino < PID_ROOT_BASE }
fn is_pid_root(ino: InodeId) -> bool { ino >= PID_ROOT_BASE && ino < PID_LIMITS_BASE }
fn is_pid_symlink(ino: InodeId) -> bool { is_pid_exe(ino) || is_pid_cwd(ino) || is_pid_root(ino) }
fn is_pid_file(ino: InodeId) -> bool { ino >= PID_STAT_BASE && !is_pid_fd_dir(ino) && !is_pid_symlink(ino) }
fn pid_from_dir(ino: InodeId) -> u64 { ino - PID_DIR_BASE }
/// All per-PID inode bases, sorted descending for pid_from_file lookup.
const PID_BASES: [InodeId; 15] = [
    PID_TASK_DIR_BASE, PID_IO_BASE, PID_LIMITS_BASE, PID_ROOT_BASE,
    PID_CWD_BASE, PID_OOM_BASE, PID_MOUNTINFO_BASE, PID_CGROUP_BASE,
    PID_ENVIRON_BASE, PID_COMM_BASE, PID_FD_DIR_BASE, PID_MAPS_BASE,
    PID_EXE_BASE, PID_STATUS_BASE, PID_STATM_BASE,
];

fn pid_from_file(ino: InodeId) -> u64 {
    for &base in &PID_BASES {
        if ino >= base { return ino - base; }
    }
    if ino >= PID_CMDLINE_BASE { ino - PID_CMDLINE_BASE }
    else { ino - PID_STAT_BASE }
}

/// Per-task information for procfs.
#[derive(Clone, Copy, Default)]
pub struct TaskInfo {
    pub pid: u32,
    pub ppid: u32,
    pub pgid: u32,
    pub sid: u32,
    pub uid: u32,
    pub gid: u32,
    pub state: u8,     // 0=free, 1=ready, 2=running, 3=sleeping, 5=zombie, 6=pipe, 8=stopped
    pub threads: u32,
    pub rss_pages: u32,  // resident set size in 4K pages
    pub brk_addr: usize, // program break address (top of heap)
}

/// Kernel callbacks for dynamic data.
pub struct ProcFs {
    pub get_ticks: fn() -> u64,
    pub get_total_frames: fn() -> usize,
    pub get_free_frames: fn() -> usize,
    pub get_active_pids: fn(&mut [u32]) -> usize,
    pub get_current_pid: fn() -> u32,
    pub get_task_cmdline: fn(u32, &mut [u8]) -> usize,
    pub get_task_comm: fn(u32, &mut [u8]) -> usize,
    pub get_task_info: fn(u32) -> TaskInfo,
    pub get_idle_ticks: fn() -> u64,
    pub get_task_cwd: fn(u32, &mut [u8]) -> usize,
    pub get_task_environ: fn(u32, &mut [u8]) -> usize,
    pub num_cpus: u32,
}

impl ProcFs {
    pub const fn new(
        get_ticks: fn() -> u64,
        get_total_frames: fn() -> usize,
        get_free_frames: fn() -> usize,
        get_active_pids: fn(&mut [u32]) -> usize,
        get_current_pid: fn() -> u32,
        get_task_cmdline: fn(u32, &mut [u8]) -> usize,
        get_task_comm: fn(u32, &mut [u8]) -> usize,
        get_task_info: fn(u32) -> TaskInfo,
        get_idle_ticks: fn() -> u64,
        get_task_cwd: fn(u32, &mut [u8]) -> usize,
        get_task_environ: fn(u32, &mut [u8]) -> usize,
    ) -> Self {
        Self { get_ticks, get_total_frames, get_free_frames, get_active_pids, get_current_pid, get_task_cmdline, get_task_comm, get_task_info, get_idle_ticks, get_task_cwd, get_task_environ, num_cpus: 1 }
    }

    /// Check if a PID exists by querying the kernel task table.
    fn pid_exists(&self, pid: u64) -> bool {
        let mut pids = [0u32; 64];
        let count = (self.get_active_pids)(&mut pids);
        pids[..count].iter().any(|&p| p as u64 == pid)
    }

    /// Generate content for a virtual file into a buffer.
    fn generate(&self, ino: InodeId, buf: &mut [u8]) -> usize {
        match ino {
            INO_UPTIME => {
                let ticks = (self.get_ticks)();
                let idle = (self.get_idle_ticks)();
                let secs = ticks / 1000;
                let frac = (ticks % 1000) / 10;
                let idle_secs = idle / 1000;
                let idle_frac = (idle % 1000) / 10;
                let mut pos = 0;
                pos += fmt_u64(&mut buf[pos..], secs);
                buf[pos] = b'.'; pos += 1;
                pos += fmt_u64_pad2(&mut buf[pos..], frac);
                buf[pos] = b' '; pos += 1;
                pos += fmt_u64(&mut buf[pos..], idle_secs);
                buf[pos] = b'.'; pos += 1;
                pos += fmt_u64_pad2(&mut buf[pos..], idle_frac);
                buf[pos] = b'\n'; pos += 1;
                pos
            }
            INO_MEMINFO => {
                let total = (self.get_total_frames)() * 4;
                let free = (self.get_free_frames)() * 4;
                fmt_meminfo(buf, total, free)
            }
            INO_STAT => {
                let ticks = (self.get_ticks)();
                let idle = (self.get_idle_ticks)();
                self.gen_cpu_stat(buf, ticks, idle)
            }
            INO_VERSION => {
                let s = concat!("rux version ", env!("CARGO_PKG_VERSION"), "\n");
                let len = s.len().min(buf.len());
                buf[..len].copy_from_slice(&s.as_bytes()[..len]);
                len
            }
            INO_LOADAVG => {
                // Count running tasks for a simple load estimate
                let mut pids = [0u32; 64];
                let total = (self.get_active_pids)(&mut pids);
                let running = total.max(1); // at least 1 (ourselves)
                // Format: "load1 load5 load15 running/total last_pid\n"
                // Simple: load = nr_running * 0.01 (approximate)
                let mut pos = 0;
                pos += copy_str(&mut buf[pos..], b"0.");
                pos += fmt_u64_pad2(&mut buf[pos..], (running as u64).min(99));
                buf[pos] = b' '; pos += 1;
                pos += copy_str(&mut buf[pos..], b"0.");
                pos += fmt_u64_pad2(&mut buf[pos..], (running as u64).min(99));
                buf[pos] = b' '; pos += 1;
                pos += copy_str(&mut buf[pos..], b"0.");
                pos += fmt_u64_pad2(&mut buf[pos..], (running as u64).min(99));
                buf[pos] = b' '; pos += 1;
                pos += fmt_u64(&mut buf[pos..], running as u64);
                buf[pos] = b'/'; pos += 1;
                pos += fmt_u64(&mut buf[pos..], total as u64);
                buf[pos] = b' '; pos += 1;
                pos += fmt_u64(&mut buf[pos..], pids[..total].iter().copied().max().unwrap_or(1) as u64);
                buf[pos] = b'\n'; pos += 1;
                pos
            }
            INO_MOUNTS => {
                // Linux /proc/mounts format: device mountpoint fstype options dump pass
                let s = b"/dev/vda / ext2 rw,relatime 0 0\nproc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\ndevtmpfs /dev devtmpfs rw,nosuid 0 0\n";
                let len = s.len().min(buf.len());
                buf[..len].copy_from_slice(&s[..len]);
                len
            }
            INO_FILESYSTEMS => {
                let s = b"nodev\tramfs\nnodev\tprocfs\nnodev\tdevfs\n";
                let len = s.len().min(buf.len());
                buf[..len].copy_from_slice(&s[..len]);
                len
            }
            INO_CMDLINE => {
                buf[0] = b'\n';
                1
            }
            INO_CPUINFO => {
                self.gen_cpuinfo(buf)
            }
            INO_NET_TCP => {
                let s = b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
                let len = s.len().min(buf.len());
                buf[..len].copy_from_slice(&s[..len]);
                len
            }
            INO_NET_UDP => {
                let s = b"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
                let len = s.len().min(buf.len());
                buf[..len].copy_from_slice(&s[..len]);
                len
            }
            INO_NET_DEV => {
                let s = b"Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n  eth0:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n";
                let len = s.len().min(buf.len());
                buf[..len].copy_from_slice(&s[..len]);
                len
            }
            INO_SYS_K_OSRELEASE => {
                let s = concat!(env!("CARGO_PKG_VERSION"), "\n");
                let len = s.len().min(buf.len());
                buf[..len].copy_from_slice(&s.as_bytes()[..len]);
                len
            }
            INO_SYS_K_HOSTNAME => {
                let s = b"rux\n";
                let len = s.len().min(buf.len());
                buf[..len].copy_from_slice(&s[..len]);
                len
            }
            INO_SYS_K_OSTYPE => {
                let s = b"Linux\n";
                let len = s.len().min(buf.len());
                buf[..len].copy_from_slice(&s[..len]);
                len
            }
            INO_SYS_K_RANDOM_UUID => {
                // Generate a pseudo-random UUID (v4 format)
                let mut pos = 0;
                let hex = b"0123456789abcdef";
                let ticks = (self.get_ticks)();
                let mut x = ticks ^ 0x12345678_9ABCDEF0;
                for i in 0..36u8 {
                    if i == 8 || i == 13 || i == 18 || i == 23 {
                        buf[pos] = b'-'; pos += 1;
                    } else {
                        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
                        buf[pos] = hex[(x & 0xF) as usize]; pos += 1;
                    }
                }
                buf[pos] = b'\n'; pos += 1;
                pos
            }
            INO_SYS_VM_OVERCOMMIT => {
                let s = b"0\n";
                buf[..s.len()].copy_from_slice(s);
                s.len()
            }
            _ if ino >= PID_MAPS_BASE && ino < PID_FD_DIR_BASE => {
                // /proc/[pid]/maps — synthesized memory map
                let pid = ino - PID_MAPS_BASE;
                self.gen_pid_maps(pid, buf)
            }
            _ if is_pid_file(ino) => {
                let pid = pid_from_file(ino);
                if !self.pid_exists(pid) { return 0; }
                self.gen_pid_file(ino, pid, buf)
            }
            _ => 0,
        }
    }

    /// Generate /proc/[pid]/stat
    /// Format: pid (comm) state ppid pgrp session tty tpgid flags minflt cminflt
    ///         majflt cmajflt utime stime cutime cstime priority nice threads
    ///         itrealvalue starttime vsize rss rsslim ...
    /// Dispatch per-PID file content generation by inode range.
    fn gen_pid_file(&self, ino: InodeId, pid: u64, buf: &mut [u8]) -> usize {
        // Static content files — served from fixed byte slices
        const STATIC_PID_FILES: &[(InodeId, &[u8])] = &[
            (PID_IO_BASE, b"rchar: 0\nwchar: 0\nsyscr: 0\nsyscw: 0\nread_bytes: 0\nwrite_bytes: 0\ncancelled_write_bytes: 0\n"),
            (PID_LIMITS_BASE, b"Limit                     Soft Limit           Hard Limit           Units     \nMax cpu time              unlimited            unlimited            seconds   \nMax file size             unlimited            unlimited            bytes     \nMax data size             unlimited            unlimited            bytes     \nMax stack size            8388608              unlimited            bytes     \nMax core file size        0                    unlimited            bytes     \nMax resident set          unlimited            unlimited            bytes     \nMax processes             63704                63704                processes \nMax open files            1024                 1048576              files     \nMax locked memory         8388608              8388608              bytes     \nMax address space         unlimited            unlimited            bytes     \nMax file locks            unlimited            unlimited            locks     \nMax pending signals       63704                63704                signals   \nMax msgqueue size         819200               819200               bytes     \nMax nice priority         0                    0                    \nMax realtime priority     0                    0                    \nMax realtime timeout      unlimited            unlimited            us        \n"),
            (PID_OOM_BASE, b"0\n"),
            (PID_MOUNTINFO_BASE, b"1 1 254:0 / / rw,relatime - ext2 /dev/vda rw\n"),
            (PID_CGROUP_BASE, b"0::/\n"),
        ];

        // Check static files first
        for &(base, content) in STATIC_PID_FILES {
            if ino >= base && ino < base + 100 {
                let len = content.len().min(buf.len());
                buf[..len].copy_from_slice(&content[..len]);
                return len;
            }
        }

        // Dynamic content files
        if ino >= PID_ENVIRON_BASE && ino < PID_COMM_BASE {
            let len = (self.get_task_environ)(pid as u32, buf);
            if len > 0 { return len; }
            let s = b"PATH=/bin:/sbin:/usr/bin:/usr/sbin\0HOME=/root\0";
            let l = s.len().min(buf.len());
            buf[..l].copy_from_slice(&s[..l]);
            return l;
        }
        if ino >= PID_COMM_BASE && ino < PID_CWD_BASE {
            return self.gen_pid_comm(pid, buf);
        }
        if ino >= PID_STATUS_BASE && ino < PID_EXE_BASE {
            return self.gen_pid_status(pid, buf);
        }
        if ino >= PID_STATM_BASE && ino < PID_STATUS_BASE {
            return self.gen_pid_statm(pid, buf);
        }
        if ino >= PID_CMDLINE_BASE && ino < PID_STATM_BASE {
            return self.gen_pid_cmdline(pid, buf);
        }
        self.gen_pid_stat(pid, buf)
    }

    /// Generate /proc/[pid]/comm — process name (basename of argv[0])
    fn gen_pid_comm(&self, pid: u64, buf: &mut [u8]) -> usize {
        let mut nb = [0u8; 16];
        let nl = (self.get_task_comm)(pid as u32, &mut nb);
        let name = if nl > 0 { &nb[..nl] } else { b"sh" as &[u8] };
        let len = name.len().min(buf.len().saturating_sub(1));
        buf[..len].copy_from_slice(&name[..len]);
        buf[len] = b'\n';
        len + 1
    }

    fn gen_pid_stat(&self, pid: u64, buf: &mut [u8]) -> usize {
        let info = (self.get_task_info)(pid as u32);
        // Cap rss_pages to sane limit (256MB = 65536 pages) to avoid display issues
        let rss = if info.rss_pages > 0 && info.rss_pages <= 65536 { info.rss_pages as usize } else { 64 };
        let vsize = rss * 4096;
        let mut pos = 0;
        // pid (comm) state ppid pgrp session tty_nr tpgid flags
        pos += fmt_u64(&mut buf[pos..], pid);
        let mut nb = [0u8; 16];
        let nl = (self.get_task_comm)(pid as u32, &mut nb);
        let name = if nl > 0 { &nb[..nl] } else { b"sh" as &[u8] };
        buf[pos] = b' '; pos += 1;
        buf[pos] = b'('; pos += 1;
        let nlen = name.len().min(15);
        buf[pos..pos+nlen].copy_from_slice(&name[..nlen]);
        pos += nlen;
        // state ppid pgrp session tty_nr tpgid flags
        let state_ch = match info.state {
            1 | 2 => b'R', // Running / Ready
            5 => b'Z',     // Zombie
            8 => b'T',     // Stopped
            _ => b'S',     // Sleeping (3), WaitingForChild (4), WaitingForPipe (6), WaitingForFutex (7), etc.
        };
        buf[pos] = b')'; pos += 1;
        buf[pos] = b' '; pos += 1;
        buf[pos] = state_ch; pos += 1;
        buf[pos] = b' '; pos += 1;
        pos += fmt_u64(&mut buf[pos..], info.ppid as u64);
        buf[pos] = b' '; pos += 1;
        pos += fmt_u64(&mut buf[pos..], info.pgid as u64);
        buf[pos] = b' '; pos += 1;
        pos += fmt_u64(&mut buf[pos..], info.sid as u64);
        pos += copy_str(&mut buf[pos..], b" 0 -1 0 ");
        // minflt cminflt majflt cmajflt utime stime cutime cstime
        pos += copy_str(&mut buf[pos..], b"0 0 0 0 0 0 0 0 ");
        // priority nice num_threads itrealvalue starttime
        pos += copy_str(&mut buf[pos..], b"20 0 1 0 0 ");
        // vsize rss rsslim
        pos += fmt_u64(&mut buf[pos..], vsize as u64);
        buf[pos] = b' '; pos += 1;
        pos += fmt_u64(&mut buf[pos..], rss as u64);
        pos += copy_str(&mut buf[pos..], b" 4294967295");
        // remaining fields 26-52 (zeros): startcode endcode startstack kstkesp kstkeip
        // signal blocked sigignore sigcatch wchan nswap cnswap exit_signal processor
        // rt_priority policy delayacct_blkio_ticks guest_time cguest_time start_data
        // end_data start_brk arg_start arg_end env_start env_end exit_code
        pos += copy_str(&mut buf[pos..], b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n");
        pos
    }

    /// Generate /proc/[pid]/cmdline — null-separated argv from task slot
    fn gen_pid_cmdline(&self, pid: u64, buf: &mut [u8]) -> usize {
        let len = (self.get_task_cmdline)(pid as u32, buf);
        if len > 0 { len } else {
            // Fallback for tasks without cmdline (e.g., init)
            let s = b"/bin/sh\0";
            let n = s.len().min(buf.len());
            buf[..n].copy_from_slice(&s[..n]);
            n
        }
    }

    /// Generate /proc/[pid]/statm — memory in pages
    /// Format: size resident shared text lib data dt
    fn gen_pid_statm(&self, pid: u64, buf: &mut [u8]) -> usize {
        let info = (self.get_task_info)(pid as u32);
        let used = if info.rss_pages > 0 && info.rss_pages <= 65536 { info.rss_pages as usize } else { 64 };
        let mut pos = 0;
        pos += fmt_u64(&mut buf[pos..], used as u64); // size
        buf[pos] = b' '; pos += 1;
        pos += fmt_u64(&mut buf[pos..], used as u64); // resident
        pos += copy_str(&mut buf[pos..], b" 0 ");
        pos += fmt_u64(&mut buf[pos..], (used / 4).max(1) as u64); // text
        pos += copy_str(&mut buf[pos..], b" 0 ");
        pos += fmt_u64(&mut buf[pos..], (used * 3 / 4) as u64); // data
        pos += copy_str(&mut buf[pos..], b" 0\n");
        pos
    }

    /// Generate /proc/[pid]/status — human-readable
    fn gen_pid_status(&self, pid: u64, buf: &mut [u8]) -> usize {
        let info = (self.get_task_info)(pid as u32);
        let used_kb = if info.rss_pages > 0 && info.rss_pages <= 65536 { info.rss_pages as usize * 4 } else { 256 };

        let mut nb = [0u8; 16];
        let nl = (self.get_task_comm)(pid as u32, &mut nb);
        let name = if nl > 0 { &nb[..nl] } else { b"sh" as &[u8] };

        let state_str = match info.state {
            5 => b"Z (zombie)" as &[u8], 8 => b"T (stopped)",
            3 => b"S (sleeping)", 6 | 7 => b"D (disk sleep)",
            2 => b"R (running)", _ => b"S (sleeping)",
        };

        let mut pos = 0;
        pos += copy_str(&mut buf[pos..], b"Name:\t");
        let nlen = name.len().min(15);
        buf[pos..pos+nlen].copy_from_slice(&name[..nlen]);
        pos += nlen;
        pos += copy_str(&mut buf[pos..], b"\nUmask:\t0022\nState:\t");
        pos += copy_str(&mut buf[pos..], state_str);
        pos += copy_str(&mut buf[pos..], b"\nTgid:\t");
        pos += fmt_u64(&mut buf[pos..], pid); // Tgid = pid (no threads)
        pos += copy_str(&mut buf[pos..], b"\nNgid:\t0\nPid:\t");
        pos += fmt_u64(&mut buf[pos..], pid);
        pos += copy_str(&mut buf[pos..], b"\nPPid:\t"); // Note: PPid not Ppid
        pos += fmt_u64(&mut buf[pos..], info.ppid as u64);
        pos += copy_str(&mut buf[pos..], b"\nTracerPid:\t0\nUid:\t");
        pos += fmt_u64(&mut buf[pos..], info.uid as u64);
        buf[pos] = b'\t'; pos += 1;
        pos += fmt_u64(&mut buf[pos..], info.uid as u64);
        pos += copy_str(&mut buf[pos..], b"\t0\t0\nGid:\t");
        pos += fmt_u64(&mut buf[pos..], info.gid as u64);
        buf[pos] = b'\t'; pos += 1;
        pos += fmt_u64(&mut buf[pos..], info.gid as u64);
        pos += copy_str(&mut buf[pos..], b"\t0\t0\nFDSize:\t64\nGroups:\t\nVmPeak:\t");
        pos += fmt_u64(&mut buf[pos..], used_kb as u64);
        pos += copy_str(&mut buf[pos..], b" kB\nVmSize:\t");
        pos += fmt_u64(&mut buf[pos..], used_kb as u64);
        pos += copy_str(&mut buf[pos..], b" kB\nVmLck:\t0 kB\nVmPin:\t0 kB\nVmHWM:\t");
        pos += fmt_u64(&mut buf[pos..], used_kb as u64);
        pos += copy_str(&mut buf[pos..], b" kB\nVmRSS:\t");
        pos += fmt_u64(&mut buf[pos..], used_kb as u64);
        pos += copy_str(&mut buf[pos..], b" kB\nRssAnon:\t");
        pos += fmt_u64(&mut buf[pos..], used_kb as u64);
        pos += copy_str(&mut buf[pos..], b" kB\nRssFile:\t0 kB\nRssShmem:\t0 kB\nVmData:\t");
        pos += fmt_u64(&mut buf[pos..], used_kb as u64);
        pos += copy_str(&mut buf[pos..], b" kB\nVmStk:\t132 kB\nVmExe:\t4 kB\nVmLib:\t0 kB\nVmPTE:\t4 kB\nVmSwap:\t0 kB\nThreads:\t");
        pos += fmt_u64(&mut buf[pos..], info.threads.max(1) as u64);
        pos += copy_str(&mut buf[pos..], b"\nSigQ:\t0/63704\nSigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\nSigBlk:\t0000000000000000\nSigIgn:\t0000000000000000\nSigCgt:\t0000000000000000\nCapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\nCapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\nCpus_allowed:\tff\nCpus_allowed_list:\t0-7\nvoluntary_ctxt_switches:\t0\nnonvoluntary_ctxt_switches:\t0\n");
        pos
    }

    /// Generate /proc/cpuinfo — one entry per CPU.
    fn gen_cpuinfo(&self, buf: &mut [u8]) -> usize {
        let mut pos = 0;
        for cpu in 0..self.num_cpus {
            pos += copy_str(&mut buf[pos..], b"processor\t: ");
            pos += fmt_u64(&mut buf[pos..], cpu as u64);
            pos += copy_str(&mut buf[pos..], b"\n");
            #[cfg(target_arch = "x86_64")]
            {
                pos += copy_str(&mut buf[pos..], b"vendor_id\t: GenuineIntel\n");
                pos += copy_str(&mut buf[pos..], b"model name\t: QEMU Virtual CPU\n");
                pos += copy_str(&mut buf[pos..], b"cpu MHz\t\t: 2000.000\n");
                pos += copy_str(&mut buf[pos..], b"cache size\t: 4096 KB\n");
                pos += copy_str(&mut buf[pos..], b"bogomips\t: 4000.00\n");
            }
            #[cfg(target_arch = "aarch64")]
            {
                pos += copy_str(&mut buf[pos..], b"BogoMIPS\t: 48.00\n");
                pos += copy_str(&mut buf[pos..], b"Features\t: fp asimd\n");
                pos += copy_str(&mut buf[pos..], b"CPU implementer\t: 0x41\n");
                pos += copy_str(&mut buf[pos..], b"CPU architecture: 8\n");
            }
            pos += copy_str(&mut buf[pos..], b"\n");
            if pos + 200 > buf.len() { break; } // prevent overflow
        }
        pos
    }

    /// Generate /proc/stat with per-CPU lines and real idle time.
    fn gen_cpu_stat(&self, buf: &mut [u8], ticks: u64, idle: u64) -> usize {
        let ncpu = (self.num_cpus as u64).max(1);
        let user = ticks.saturating_sub(idle) / ncpu;
        let idle_per = idle / ncpu;
        let mut pos = 0;
        // Aggregate "cpu" line: user nice system idle iowait irq softirq steal guest guest_nice
        pos += copy_str(&mut buf[pos..], b"cpu  ");
        pos += fmt_u64(&mut buf[pos..], user);
        pos += copy_str(&mut buf[pos..], b" 0 0 ");
        pos += fmt_u64(&mut buf[pos..], idle);
        pos += copy_str(&mut buf[pos..], b" 0 0 0 0 0 0\n");
        // Per-CPU lines
        for cpu in 0..self.num_cpus {
            pos += copy_str(&mut buf[pos..], b"cpu");
            pos += fmt_u64(&mut buf[pos..], cpu as u64);
            pos += copy_str(&mut buf[pos..], b" ");
            pos += fmt_u64(&mut buf[pos..], user);
            pos += copy_str(&mut buf[pos..], b" 0 0 ");
            pos += fmt_u64(&mut buf[pos..], idle_per);
            pos += copy_str(&mut buf[pos..], b" 0 0 0 0 0 0\n");
            if pos + 100 > buf.len() { break; }
        }
        // Count running tasks
        let mut pids = [0u32; 64];
        let total = (self.get_active_pids)(&mut pids);
        pos += copy_str(&mut buf[pos..], b"intr 0\nctxt 0\nbtime 1700000000\nprocesses ");
        pos += fmt_u64(&mut buf[pos..], total as u64);
        pos += copy_str(&mut buf[pos..], b"\nprocs_running ");
        pos += fmt_u64(&mut buf[pos..], total.max(1) as u64);
        pos += copy_str(&mut buf[pos..], b"\nprocs_blocked 0\n");
        pos
    }

    /// Generate /proc/[pid]/maps — synthesized from per-process brk/rss.
    /// Format: start-end perms offset dev inode pathname
    fn gen_pid_maps(&self, pid: u64, buf: &mut [u8]) -> usize {
        let info = (self.get_task_info)(pid as u32);
        let brk = if info.brk_addr > 0 { info.brk_addr } else { 0x800000 };
        // Infer text start: brk is typically just past text+data, so text ~ brk - rss*4096
        let rss_bytes = (info.rss_pages as usize).max(16) * 4096;
        let text_start = if brk > rss_bytes { brk - rss_bytes } else { 0x400000 };
        let text_start_page = text_start & !0xFFF;
        // Split: ~75% text (r-x), ~25% data (rw-)
        let text_pages = (info.rss_pages as usize * 3 / 4).max(1);
        let text_end = text_start_page + text_pages * 4096;
        let data_end = (brk + 0xFFF) & !0xFFF;
        let heap_end = data_end + 0x100000; // assume ~1MB heap

        let mut pos = 0;
        // Text
        pos += fmt_hex(&mut buf[pos..], text_start_page);
        buf[pos] = b'-'; pos += 1;
        pos += fmt_hex(&mut buf[pos..], text_end);
        pos += copy_str(&mut buf[pos..], b" r-xp 00000000 fe:00 1 ");
        // Get exe name from cmdline
        let mut cmd = [0u8; 128];
        let clen = (self.get_task_cmdline)(pid as u32, &mut cmd);
        let end = cmd[..clen].iter().position(|&b| b == 0).unwrap_or(clen);
        let name = &cmd[..end];
        let nlen = name.len().min(buf.len() - pos - 1);
        buf[pos..pos+nlen].copy_from_slice(&name[..nlen]);
        pos += nlen;
        buf[pos] = b'\n'; pos += 1;
        // Data/BSS
        pos += fmt_hex(&mut buf[pos..], text_end);
        buf[pos] = b'-'; pos += 1;
        pos += fmt_hex(&mut buf[pos..], data_end);
        pos += copy_str(&mut buf[pos..], b" rw-p 00000000 fe:00 1 ");
        buf[pos..pos+nlen].copy_from_slice(&name[..nlen]);
        pos += nlen;
        buf[pos] = b'\n'; pos += 1;
        // Heap
        pos += fmt_hex(&mut buf[pos..], data_end);
        buf[pos] = b'-'; pos += 1;
        pos += fmt_hex(&mut buf[pos..], heap_end);
        pos += copy_str(&mut buf[pos..], b" rw-p 00000000 00:00 0 [heap]\n");
        // Stack
        pos += copy_str(&mut buf[pos..], b"7ffe0000-80000000 rw-p 00000000 00:00 0 [stack]\n");
        pos
    }
}

impl FileSystem for ProcFs {
    fn root_inode(&self) -> InodeId { INO_ROOT }

    fn stat(&self, ino: InodeId, buf: &mut InodeStat) -> Result<(), VfsError> {
        unsafe { *buf = core::mem::MaybeUninit::zeroed().assume_init(); }
        buf.ino = ino;
        buf.blksize = 4096;

        if ino == INO_SELF {
            buf.mode = crate::S_IFLNK | 0o777;
            buf.nlink = 1;
            buf.size = 1;
            return Ok(());
        }

        // /proc/[pid]/exe — symlink to executable
        if is_pid_exe(ino) {
            buf.mode = crate::S_IFLNK | 0o777;
            buf.nlink = 1;
            buf.size = 7; // "/bin/sh"
            return Ok(());
        }

        // Directories: /proc, /proc/[pid], /proc/[pid]/fd, /proc/sys/*, /proc/net
        if ino == INO_SYS_DIR || ino == INO_SYS_KERNEL_DIR || ino == INO_SYS_VM_DIR
            || ino == INO_SYS_K_RANDOM_DIR || ino == INO_NET_DIR
        {
            buf.mode = S_IFDIR | 0o555;
            buf.nlink = 2;
            return Ok(());
        }
        // /proc/sys/kernel/* files
        if ino >= INO_SYS_K_OSRELEASE && ino <= INO_SYS_VM_OVERCOMMIT
            && ino != INO_SYS_K_RANDOM_DIR
        {
            buf.mode = S_IFREG | 0o444;
            buf.nlink = 1;
            buf.size = 32;
            return Ok(());
        }
        if ino == INO_ROOT || is_pid_dir(ino) || is_pid_fd_dir(ino) || is_pid_task_dir(ino) {
            let pid = if is_pid_dir(ino) { pid_from_dir(ino) }
                     else if is_pid_task_dir(ino) { ino - PID_TASK_DIR_BASE }
                     else if is_pid_fd_dir(ino) { ino - PID_FD_DIR_BASE }
                     else { 0 };
            if (is_pid_dir(ino) || is_pid_fd_dir(ino)) && !self.pid_exists(pid) {
                return Err(VfsError::NotFound);
            }
            buf.mode = S_IFDIR | 0o555;
            buf.nlink = 2;
            return Ok(());
        }

        // /proc/[pid]/fd/N — symlinks
        if ino >= 10000 {
            buf.mode = crate::S_IFLNK | 0o777;
            buf.nlink = 1;
            buf.size = 12; // "/dev/console"
            return Ok(());
        }

        // System files or PID files
        if (ino >= INO_UPTIME && ino <= INO_NET_DEV && ino != INO_SELF
            && !matches!(ino, INO_SYS_DIR | INO_SYS_KERNEL_DIR | INO_SYS_VM_DIR | INO_SYS_K_RANDOM_DIR | INO_NET_DIR))
            || is_pid_file(ino) {
            if is_pid_file(ino) && !self.pid_exists(pid_from_file(ino)) {
                return Err(VfsError::NotFound);
            }
            buf.mode = S_IFREG | 0o444;
            buf.nlink = 1;
            // Report a fixed size so sys_read_fd's stat-based EOF check
            // never fires before the actual read. The read() generates
            // content dynamically and returns Ok(0) at real EOF.
            buf.size = 4096;
            return Ok(());
        }

        Err(VfsError::NotFound)
    }

    fn read(&self, ino: InodeId, offset: u64, buf: &mut [u8]) -> Result<usize, VfsError> {
        if ino == INO_ROOT || is_pid_dir(ino) || is_pid_fd_dir(ino) || is_pid_task_dir(ino)
            || ino == INO_SYS_DIR || ino == INO_SYS_KERNEL_DIR || ino == INO_SYS_VM_DIR
            || ino == INO_SYS_K_RANDOM_DIR || ino == INO_NET_DIR
        {
            return Err(VfsError::IsADirectory);
        }
        let mut tmp = [0u8; 2048];
        let total = self.generate(ino, &mut tmp);
        if total == 0 { return Err(VfsError::NotFound); }
        let off = offset as usize;
        if off >= total { return Ok(0); }
        let to_copy = (total - off).min(buf.len());
        buf[..to_copy].copy_from_slice(&tmp[off..off + to_copy]);
        Ok(to_copy)
    }

    fn lookup(&self, dir: InodeId, name: FileName<'_>) -> Result<InodeId, VfsError> {
        let name_bytes = name.as_bytes();

        if dir == INO_ROOT {
            // System files
            for &(entry_name, entry_ino) in &SYS_ENTRIES {
                if entry_name == name_bytes {
                    return Ok(entry_ino);
                }
            }
            // PID directories — parse numeric name
            if let Some(pid) = parse_u64(name_bytes) {
                if self.pid_exists(pid) {
                    return Ok(PID_DIR_BASE + pid);
                }
            }
            return Err(VfsError::NotFound);
        }

        if is_pid_dir(dir) {
            let pid = pid_from_dir(dir);
            if !self.pid_exists(pid) { return Err(VfsError::NotFound); }
            for &(entry_name, base) in &PID_SUBENTRIES {
                if entry_name == name_bytes {
                    return Ok(base + pid);
                }
            }
            return Err(VfsError::NotFound);
        }

        // /proc/[pid]/task/N — thread directories (single-threaded: only has PID itself)
        if is_pid_task_dir(dir) {
            let _pid = dir - PID_TASK_DIR_BASE;
            if let Some(tid) = parse_u64(name_bytes) {
                if self.pid_exists(tid) {
                    return Ok(PID_DIR_BASE + tid); // Reuse PID dir for thread entries
                }
            }
            return Err(VfsError::NotFound);
        }

        // /proc/[pid]/fd/N — each FD is a symlink
        if is_pid_fd_dir(dir) {
            if let Some(fd_num) = parse_u64(name_bytes) {
                if fd_num < 64 {
                    let pid = dir - PID_FD_DIR_BASE;
                    return Ok(10000 + pid * 64 + fd_num);
                }
            }
            return Err(VfsError::NotFound);
        }

        // /proc/sys
        if dir == INO_SYS_DIR {
            return match name_bytes {
                b"kernel" => Ok(INO_SYS_KERNEL_DIR),
                b"vm" => Ok(INO_SYS_VM_DIR),
                _ => Err(VfsError::NotFound),
            };
        }
        // /proc/sys/kernel
        if dir == INO_SYS_KERNEL_DIR {
            return match name_bytes {
                b"osrelease" => Ok(INO_SYS_K_OSRELEASE),
                b"hostname" => Ok(INO_SYS_K_HOSTNAME),
                b"ostype" => Ok(INO_SYS_K_OSTYPE),
                b"random" => Ok(INO_SYS_K_RANDOM_DIR),
                _ => Err(VfsError::NotFound),
            };
        }
        // /proc/sys/kernel/random
        if dir == INO_SYS_K_RANDOM_DIR {
            return match name_bytes {
                b"uuid" => Ok(INO_SYS_K_RANDOM_UUID),
                _ => Err(VfsError::NotFound),
            };
        }
        // /proc/sys/vm
        if dir == INO_SYS_VM_DIR {
            return match name_bytes {
                b"overcommit_memory" => Ok(INO_SYS_VM_OVERCOMMIT),
                _ => Err(VfsError::NotFound),
            };
        }

        // /proc/net
        if dir == INO_NET_DIR {
            return match name_bytes {
                b"tcp" => Ok(INO_NET_TCP),
                b"udp" => Ok(INO_NET_UDP),
                b"dev" => Ok(INO_NET_DEV),
                _ => Err(VfsError::NotFound),
            };
        }

        Err(VfsError::NotADirectory)
    }

    fn readdir(&self, dir: InodeId, offset: usize, buf: &mut DirEntry) -> Result<bool, VfsError> {
        if dir == INO_ROOT {
            // First: system files
            if offset < NUM_SYS_ENTRIES {
                let (name, ino) = SYS_ENTRIES[offset];
                buf.ino = ino;
                buf.kind = if ino == INO_SELF { InodeType::Symlink }
                           else if ino == INO_SYS_DIR || ino == INO_NET_DIR { InodeType::Directory }
                           else { InodeType::File };
                buf.name_len = name.len() as u8;
                buf.name[..name.len()].copy_from_slice(name);
                return Ok(true);
            }
            // Then: PID directories (enumerate all active PIDs)
            let pid_offset = offset - NUM_SYS_ENTRIES;
            let mut pids = [0u32; 64];
            let count = (self.get_active_pids)(&mut pids);
            if pid_offset < count {
                let pid = pids[pid_offset];
                buf.ino = PID_DIR_BASE + pid as u64;
                buf.kind = InodeType::Directory;
                let mut name_buf = [0u8; 10];
                let n = fmt_u64(&mut name_buf, pid as u64);
                buf.name_len = n as u8;
                buf.name[..n].copy_from_slice(&name_buf[..n]);
                return Ok(true);
            }
            return Ok(false);
        }

        if is_pid_dir(dir) {
            let pid = pid_from_dir(dir);
            if !self.pid_exists(pid) { return Err(VfsError::NotFound); }
            if offset >= PID_SUBENTRIES.len() { return Ok(false); }
            let (name, base) = PID_SUBENTRIES[offset];
            buf.ino = base + pid;
            buf.kind = if base == PID_EXE_BASE || base == PID_CWD_BASE || base == PID_ROOT_BASE {
                           InodeType::Symlink
                       } else if base == PID_FD_DIR_BASE || base == PID_TASK_DIR_BASE { InodeType::Directory }
                       else { InodeType::File };
            buf.name_len = name.len() as u8;
            buf.name[..name.len()].copy_from_slice(name);
            return Ok(true);
        }

        // /proc/[pid]/task — list threads (single-threaded: just the PID itself)
        if is_pid_task_dir(dir) {
            let pid = dir - PID_TASK_DIR_BASE;
            if !self.pid_exists(pid) { return Err(VfsError::NotFound); }
            if offset >= 1 { return Ok(false); } // only 1 "thread"
            buf.ino = PID_DIR_BASE + pid;
            buf.kind = InodeType::Directory;
            let mut name_buf = [0u8; 10];
            let n = fmt_u64(&mut name_buf, pid);
            buf.name_len = n as u8;
            buf.name[..n].copy_from_slice(&name_buf[..n]);
            return Ok(true);
        }

        // /proc/[pid]/fd — list open FDs from actual fd table
        if is_pid_fd_dir(dir) {
            let pid = dir - PID_FD_DIR_BASE;
            unsafe {
                let ft = &*crate::fdtable::FD_TABLE;
                // Find the Nth active fd (offset = entry index, not fd number)
                let mut count = 0usize;
                for fd in 0..crate::fdtable::MAX_FDS {
                    if ft[fd].active {
                        if count == offset {
                            buf.ino = 10000 + pid * 64 + fd as u64;
                            buf.kind = InodeType::Symlink;
                            // Write fd number as string
                            let s = fd_to_str(fd);
                            buf.name_len = s.len() as u8;
                            buf.name[..s.len()].copy_from_slice(s.as_bytes());
                            return Ok(true);
                        }
                        count += 1;
                    }
                }
            }
            return Ok(false);
        }

        // /proc/sys
        if dir == INO_SYS_DIR {
            let entries: &[(&[u8], InodeId)] = &[(b"kernel", INO_SYS_KERNEL_DIR), (b"vm", INO_SYS_VM_DIR)];
            return readdir_static(entries, offset, buf, true);
        }
        // /proc/sys/kernel
        if dir == INO_SYS_KERNEL_DIR {
            let entries: &[(&[u8], InodeId)] = &[
                (b"osrelease", INO_SYS_K_OSRELEASE), (b"hostname", INO_SYS_K_HOSTNAME),
                (b"ostype", INO_SYS_K_OSTYPE), (b"random", INO_SYS_K_RANDOM_DIR),
            ];
            return readdir_static(entries, offset, buf, false);
        }
        // /proc/sys/kernel/random
        if dir == INO_SYS_K_RANDOM_DIR {
            let entries: &[(&[u8], InodeId)] = &[(b"uuid", INO_SYS_K_RANDOM_UUID)];
            return readdir_static(entries, offset, buf, false);
        }
        // /proc/sys/vm
        if dir == INO_SYS_VM_DIR {
            let entries: &[(&[u8], InodeId)] = &[(b"overcommit_memory", INO_SYS_VM_OVERCOMMIT)];
            return readdir_static(entries, offset, buf, false);
        }
        // /proc/net
        if dir == INO_NET_DIR {
            let entries: &[(&[u8], InodeId)] = &[(b"tcp", INO_NET_TCP), (b"udp", INO_NET_UDP), (b"dev", INO_NET_DEV)];
            return readdir_static(entries, offset, buf, false);
        }

        Err(VfsError::NotADirectory)
    }

    fn write(&mut self, _ino: InodeId, _offset: u64, _buf: &[u8]) -> Result<usize, VfsError> { Err(VfsError::ReadOnly) }
    fn truncate(&mut self, _ino: InodeId, _size: u64) -> Result<(), VfsError> { Err(VfsError::ReadOnly) }
    fn create(&mut self, _dir: InodeId, _name: FileName<'_>, _mode: u32) -> Result<InodeId, VfsError> { Err(VfsError::ReadOnly) }
    fn mkdir(&mut self, _dir: InodeId, _name: FileName<'_>, _mode: u32) -> Result<InodeId, VfsError> { Err(VfsError::ReadOnly) }
    fn unlink(&mut self, _dir: InodeId, _name: FileName<'_>) -> Result<(), VfsError> { Err(VfsError::ReadOnly) }
    fn rmdir(&mut self, _dir: InodeId, _name: FileName<'_>) -> Result<(), VfsError> { Err(VfsError::ReadOnly) }
    fn link(&mut self, _dir: InodeId, _name: FileName<'_>, _target: InodeId) -> Result<(), VfsError> { Err(VfsError::ReadOnly) }
    fn symlink(&mut self, _dir: InodeId, _name: FileName<'_>, _target: &[u8]) -> Result<InodeId, VfsError> { Err(VfsError::ReadOnly) }
    fn readlink(&self, ino: InodeId, buf: &mut [u8]) -> Result<usize, VfsError> {
        if ino == INO_SELF && !buf.is_empty() {
            let pid = (self.get_current_pid)();
            let mut tmp = [0u8; 10];
            let n = fmt_u64(&mut tmp, pid as u64);
            let len = n.min(buf.len());
            buf[..len].copy_from_slice(&tmp[..len]);
            return Ok(len);
        }
        // /proc/[pid]/exe → path from cmdline argv[0]
        if is_pid_exe(ino) {
            let pid = pid_from_file(ino);
            let mut cmdline = [0u8; 128];
            let clen = (self.get_task_cmdline)(pid as u32, &mut cmdline);
            if clen > 0 {
                // argv[0] is the first null-terminated string in cmdline
                let end = cmdline[..clen].iter().position(|&b| b == 0).unwrap_or(clen);
                let len = end.min(buf.len());
                buf[..len].copy_from_slice(&cmdline[..len]);
                return Ok(len);
            }
            let s = b"/bin/sh";
            let len = s.len().min(buf.len());
            buf[..len].copy_from_slice(&s[..len]);
            return Ok(len);
        }
        // /proc/[pid]/cwd → current working directory
        if is_pid_cwd(ino) {
            let pid = pid_from_file(ino);
            let len = (self.get_task_cwd)(pid as u32, buf);
            if len > 0 { return Ok(len); }
            buf[0] = b'/';
            return Ok(1);
        }
        // /proc/[pid]/root → process root directory
        if is_pid_root(ino) {
            let s = b"/";
            let len = s.len().min(buf.len());
            buf[..len].copy_from_slice(&s[..len]);
            return Ok(len);
        }
        // /proc/[pid]/fd/N → target path
        if ino >= 10000 {
            let fd = (ino % 64) as usize;
            unsafe {
                let ft = &*crate::fdtable::FD_TABLE;
                if fd < crate::fdtable::MAX_FDS && ft[fd].active {
                    let s = if ft[fd].is_console {
                        b"/dev/console" as &[u8]
                    } else if ft[fd].is_pipe {
                        b"pipe:" as &[u8]
                    } else if ft[fd].is_socket {
                        b"socket:" as &[u8]
                    } else {
                        b"/dev/vda" as &[u8] // file on ext2
                    };
                    let len = s.len().min(buf.len());
                    buf[..len].copy_from_slice(&s[..len]);
                    return Ok(len);
                }
            }
        }
        Err(VfsError::NotSupported)
    }
    fn rename(&mut self, _old_dir: InodeId, _old_name: FileName<'_>, _new_dir: InodeId, _new_name: FileName<'_>) -> Result<(), VfsError> { Err(VfsError::ReadOnly) }
    fn chmod(&mut self, _ino: InodeId, _mode: u32) -> Result<(), VfsError> { Err(VfsError::ReadOnly) }
    fn chown(&mut self, _ino: InodeId, _uid: u32, _gid: u32) -> Result<(), VfsError> { Err(VfsError::ReadOnly) }
    fn utimes(&mut self, _ino: InodeId, _atime: u64, _mtime: u64) -> Result<(), VfsError> { Err(VfsError::ReadOnly) }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Format a file descriptor number as a string (no alloc).
fn fd_to_str(fd: usize) -> &'static str {
    // Common fds as static strings to avoid formatting
    match fd {
        0 => "0", 1 => "1", 2 => "2", 3 => "3", 4 => "4",
        5 => "5", 6 => "6", 7 => "7", 8 => "8", 9 => "9",
        10 => "10", 11 => "11", 12 => "12", 13 => "13", 14 => "14",
        15 => "15", 16 => "16", 17 => "17", 18 => "18", 19 => "19",
        _ => "??",
    }
}

/// Helper for readdir on static directory entries.
fn readdir_static(entries: &[(&[u8], InodeId)], offset: usize, buf: &mut DirEntry, all_dirs: bool) -> Result<bool, VfsError> {
    if offset >= entries.len() { return Ok(false); }
    let (name, ino) = entries[offset];
    buf.ino = ino;
    buf.kind = if all_dirs || ino == INO_SYS_K_RANDOM_DIR { InodeType::Directory } else { InodeType::File };
    buf.name_len = name.len() as u8;
    buf.name[..name.len()].copy_from_slice(name);
    Ok(true)
}

fn parse_u64(s: &[u8]) -> Option<u64> {
    if s.is_empty() { return None; }
    let mut n = 0u64;
    for &b in s {
        if b < b'0' || b > b'9' { return None; }
        n = n.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(n)
}

#[allow(dead_code)]
fn fmt_uptime(buf: &mut [u8], secs: u64, centisecs: u64) -> usize {
    let mut pos = 0;
    pos += fmt_u64(&mut buf[pos..], secs);
    buf[pos] = b'.'; pos += 1;
    pos += fmt_u64_pad2(&mut buf[pos..], centisecs);
    buf[pos] = b' '; pos += 1;
    pos += fmt_u64(&mut buf[pos..], secs);
    buf[pos] = b'.'; pos += 1;
    pos += fmt_u64_pad2(&mut buf[pos..], centisecs);
    buf[pos] = b'\n'; pos += 1;
    pos
}

fn fmt_meminfo(buf: &mut [u8], total_kb: usize, free_kb: usize) -> usize {
    let mut pos = 0;
    pos += copy_str(&mut buf[pos..], b"MemTotal:    ");
    pos += fmt_usize(&mut buf[pos..], total_kb);
    pos += copy_str(&mut buf[pos..], b" kB\nMemFree:     ");
    pos += fmt_usize(&mut buf[pos..], free_kb);
    pos += copy_str(&mut buf[pos..], b" kB\nMemAvailable:");
    pos += fmt_usize(&mut buf[pos..], free_kb);
    pos += copy_str(&mut buf[pos..], b" kB\nBuffers:         0 kB\nCached:          0 kB\n");
    pos
}


fn copy_str(buf: &mut [u8], s: &[u8]) -> usize {
    let len = s.len().min(buf.len());
    buf[..len].copy_from_slice(&s[..len]);
    len
}

fn fmt_u64(buf: &mut [u8], mut n: u64) -> usize {
    if n == 0 { buf[0] = b'0'; return 1; }
    let mut tmp = [0u8; 20];
    let mut i = 20;
    while n > 0 { i -= 1; tmp[i] = b'0' + (n % 10) as u8; n /= 10; }
    let len = (20 - i).min(buf.len());
    buf[..len].copy_from_slice(&tmp[i..i + len]);
    len
}

fn fmt_u64_pad2(buf: &mut [u8], n: u64) -> usize {
    if buf.len() < 2 { return 0; }
    buf[0] = b'0' + ((n / 10) % 10) as u8;
    buf[1] = b'0' + (n % 10) as u8;
    2
}

fn fmt_usize(buf: &mut [u8], n: usize) -> usize {
    fmt_u64(buf, n as u64)
}

fn fmt_hex(buf: &mut [u8], mut n: usize) -> usize {
    if n == 0 { buf[0] = b'0'; return 1; }
    let hex = b"0123456789abcdef";
    let mut tmp = [0u8; 16];
    let mut i = 16;
    while n > 0 { i -= 1; tmp[i] = hex[n & 0xF]; n >>= 4; }
    let len = (16 - i).min(buf.len());
    buf[..len].copy_from_slice(&tmp[i..i + len]);
    len
}
