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

const NUM_SYS_ENTRIES: usize = 9;

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
];

const PID_DIR_BASE: InodeId = 100;
const PID_STAT_BASE: InodeId = 1000;
const PID_CMDLINE_BASE: InodeId = 2000;
const PID_STATM_BASE: InodeId = 3000;
const PID_STATUS_BASE: InodeId = 4000;
const PID_EXE_BASE: InodeId = 5000;    // /proc/[pid]/exe symlink
const PID_MAPS_BASE: InodeId = 6000;   // /proc/[pid]/maps
const PID_FD_DIR_BASE: InodeId = 7000; // /proc/[pid]/fd directory

const PID_SUBENTRIES: [(&[u8], InodeId); 7] = [
    (b"stat", PID_STAT_BASE),
    (b"cmdline", PID_CMDLINE_BASE),
    (b"statm", PID_STATM_BASE),
    (b"status", PID_STATUS_BASE),
    (b"exe", PID_EXE_BASE),
    (b"maps", PID_MAPS_BASE),
    (b"fd", PID_FD_DIR_BASE),
];

fn is_pid_dir(ino: InodeId) -> bool { ino >= PID_DIR_BASE && ino < PID_STAT_BASE }
fn is_pid_fd_dir(ino: InodeId) -> bool { ino >= PID_FD_DIR_BASE && ino < PID_FD_DIR_BASE + 100 }
fn is_pid_exe(ino: InodeId) -> bool { ino >= PID_EXE_BASE && ino < PID_MAPS_BASE }
fn is_pid_file(ino: InodeId) -> bool { ino >= PID_STAT_BASE && !is_pid_fd_dir(ino) }
fn pid_from_dir(ino: InodeId) -> u64 { ino - PID_DIR_BASE }
fn pid_from_file(ino: InodeId) -> u64 {
    if ino >= PID_MAPS_BASE && ino < PID_FD_DIR_BASE { ino - PID_MAPS_BASE }
    else if ino >= PID_EXE_BASE { ino - PID_EXE_BASE }
    else if ino >= PID_STATUS_BASE { ino - PID_STATUS_BASE }
    else if ino >= PID_STATM_BASE { ino - PID_STATM_BASE }
    else if ino >= PID_CMDLINE_BASE { ino - PID_CMDLINE_BASE }
    else { ino - PID_STAT_BASE }
}

/// Kernel callbacks for dynamic data.
pub struct ProcFs {
    pub get_ticks: fn() -> u64,
    pub get_total_frames: fn() -> usize,
    pub get_free_frames: fn() -> usize,
}

impl ProcFs {
    pub const fn new(
        get_ticks: fn() -> u64,
        get_total_frames: fn() -> usize,
        get_free_frames: fn() -> usize,
    ) -> Self {
        Self { get_ticks, get_total_frames, get_free_frames }
    }

    /// Check if a PID exists. Accept PIDs 1..64 (single-user stub).
    fn pid_exists(&self, pid: u64) -> bool {
        pid >= 1 && pid < 64
    }

    /// Generate content for a virtual file into a buffer.
    fn generate(&self, ino: InodeId, buf: &mut [u8]) -> usize {
        match ino {
            INO_UPTIME => {
                let ticks = (self.get_ticks)();
                let secs = ticks / 1000;
                let frac = (ticks % 1000) / 10;
                fmt_uptime(buf, secs, frac)
            }
            INO_MEMINFO => {
                let total = (self.get_total_frames)() * 4;
                let free = (self.get_free_frames)() * 4;
                fmt_meminfo(buf, total, free)
            }
            INO_STAT => {
                let ticks = (self.get_ticks)();
                fmt_cpu_stat(buf, ticks)
            }
            INO_VERSION => {
                let s = concat!("rux version ", env!("CARGO_PKG_VERSION"), "\n");
                let len = s.len().min(buf.len());
                buf[..len].copy_from_slice(&s.as_bytes()[..len]);
                len
            }
            INO_LOADAVG => {
                let s = b"0.00 0.00 0.00 1/1 1\n";
                let len = s.len().min(buf.len());
                buf[..len].copy_from_slice(&s[..len]);
                len
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
                // Kernel command line (empty for now)
                buf[0] = b'\n';
                1
            }
            _ if ino >= PID_MAPS_BASE && ino < PID_FD_DIR_BASE => {
                // /proc/[pid]/maps — stub empty file
                0
            }
            _ if is_pid_file(ino) => {
                let pid = pid_from_file(ino);
                if !self.pid_exists(pid) { return 0; }
                if ino >= PID_STATUS_BASE && ino < PID_EXE_BASE {
                    self.gen_pid_status(pid, buf)
                } else if ino >= PID_STATM_BASE {
                    self.gen_pid_statm(buf)
                } else if ino >= PID_CMDLINE_BASE {
                    self.gen_pid_cmdline(buf)
                } else {
                    self.gen_pid_stat(pid, buf)
                }
            }
            _ => 0,
        }
    }

    /// Generate /proc/[pid]/stat
    /// Format: pid (comm) state ppid pgrp session tty tpgid flags minflt cminflt
    ///         majflt cmajflt utime stime cutime cstime priority nice threads
    ///         itrealvalue starttime vsize rss rsslim ...
    fn gen_pid_stat(&self, pid: u64, buf: &mut [u8]) -> usize {
        let ticks = (self.get_ticks)();
        let used_frames = (self.get_total_frames)().saturating_sub((self.get_free_frames)());
        let vsize = used_frames * 4096;
        let rss = used_frames;
        let mut pos = 0;
        // pid (comm) state ppid pgrp session tty_nr tpgid flags
        pos += fmt_u64(&mut buf[pos..], pid);
        pos += copy_str(&mut buf[pos..], b" (sh) S 0 1 1 0 -1 0 ");
        // minflt cminflt majflt cmajflt utime stime cutime cstime
        pos += copy_str(&mut buf[pos..], b"0 0 0 0 ");
        pos += fmt_u64(&mut buf[pos..], ticks / 10); // utime in ticks (HZ=100)
        buf[pos] = b' '; pos += 1;
        pos += copy_str(&mut buf[pos..], b"0 0 0 ");
        // priority nice num_threads itrealvalue starttime
        pos += copy_str(&mut buf[pos..], b"20 0 1 0 0 ");
        // vsize rss rsslim
        pos += fmt_u64(&mut buf[pos..], vsize as u64);
        buf[pos] = b' '; pos += 1;
        pos += fmt_u64(&mut buf[pos..], rss as u64);
        pos += copy_str(&mut buf[pos..], b" 4294967295");
        // remaining fields (zeros to fill 44 fields)
        pos += copy_str(&mut buf[pos..], b" 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n");
        pos
    }

    /// Generate /proc/[pid]/cmdline — null-separated argv
    fn gen_pid_cmdline(&self, buf: &mut [u8]) -> usize {
        let s = b"/bin/sh\0";
        let len = s.len().min(buf.len());
        buf[..len].copy_from_slice(&s[..len]);
        len
    }

    /// Generate /proc/[pid]/statm — memory in pages
    /// Format: size resident shared text lib data dt
    fn gen_pid_statm(&self, buf: &mut [u8]) -> usize {
        let used = (self.get_total_frames)().saturating_sub((self.get_free_frames)());
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
        let used_kb = (self.get_total_frames)().saturating_sub((self.get_free_frames)()) * 4;
        let mut pos = 0;
        pos += copy_str(&mut buf[pos..], b"Name:\tsh\n");
        pos += copy_str(&mut buf[pos..], b"State:\tS (sleeping)\n");
        pos += copy_str(&mut buf[pos..], b"Pid:\t");
        pos += fmt_u64(&mut buf[pos..], pid);
        pos += copy_str(&mut buf[pos..], b"\nPpid:\t0\n");
        pos += copy_str(&mut buf[pos..], b"Uid:\t0\t0\t0\t0\n");
        pos += copy_str(&mut buf[pos..], b"Gid:\t0\t0\t0\t0\n");
        pos += copy_str(&mut buf[pos..], b"VmSize:\t");
        pos += fmt_u64(&mut buf[pos..], used_kb as u64);
        pos += copy_str(&mut buf[pos..], b" kB\nVmRSS:\t");
        pos += fmt_u64(&mut buf[pos..], used_kb as u64);
        pos += copy_str(&mut buf[pos..], b" kB\nThreads:\t1\n");
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

        // Directories: /proc, /proc/[pid], /proc/[pid]/fd
        if ino == INO_ROOT || is_pid_dir(ino) || is_pid_fd_dir(ino) {
            let pid = if is_pid_dir(ino) { pid_from_dir(ino) }
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
        if (ino >= INO_UPTIME && ino <= INO_CMDLINE && ino != INO_SELF) || is_pid_file(ino) {
            if is_pid_file(ino) && !self.pid_exists(pid_from_file(ino)) {
                return Err(VfsError::NotFound);
            }
            buf.mode = S_IFREG | 0o444;
            buf.nlink = 1;
            let mut tmp = [0u8; 512];
            buf.size = self.generate(ino, &mut tmp) as u64;
            return Ok(());
        }

        Err(VfsError::NotFound)
    }

    fn read(&self, ino: InodeId, offset: u64, buf: &mut [u8]) -> Result<usize, VfsError> {
        if ino == INO_ROOT || is_pid_dir(ino) {
            return Err(VfsError::IsADirectory);
        }
        let mut tmp = [0u8; 512];
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

        // /proc/[pid]/fd/N — each FD is a symlink
        if is_pid_fd_dir(dir) {
            if let Some(fd_num) = parse_u64(name_bytes) {
                if fd_num < 64 {
                    // Use a high inode range for fd symlinks: 10000 + pid*64 + fd
                    let pid = dir - PID_FD_DIR_BASE;
                    return Ok(10000 + pid * 64 + fd_num);
                }
            }
            return Err(VfsError::NotFound);
        }

        Err(VfsError::NotADirectory)
    }

    fn readdir(&self, dir: InodeId, offset: usize, buf: &mut DirEntry) -> Result<bool, VfsError> {
        if dir == INO_ROOT {
            // First: system files
            if offset < NUM_SYS_ENTRIES {
                let (name, ino) = SYS_ENTRIES[offset];
                buf.ino = ino;
                buf.kind = if ino == INO_SELF { InodeType::Symlink } else { InodeType::File };
                buf.name_len = name.len() as u8;
                buf.name[..name.len()].copy_from_slice(name);
                return Ok(true);
            }
            // Then: PID directories (just PID 1 for now)
            let pid_offset = offset - NUM_SYS_ENTRIES;
            if pid_offset == 0 && self.pid_exists(1) {
                buf.ino = PID_DIR_BASE + 1;
                buf.kind = InodeType::Directory;
                buf.name_len = 1;
                buf.name[0] = b'1';
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
            buf.kind = if base == PID_EXE_BASE { InodeType::Symlink }
                       else if base == PID_FD_DIR_BASE { InodeType::Directory }
                       else { InodeType::File };
            buf.name_len = name.len() as u8;
            buf.name[..name.len()].copy_from_slice(name);
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
            buf[0] = b'1';
            return Ok(1);
        }
        // /proc/[pid]/exe → path to executable
        if is_pid_exe(ino) {
            let s = b"/bin/sh";
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

fn parse_u64(s: &[u8]) -> Option<u64> {
    if s.is_empty() { return None; }
    let mut n = 0u64;
    for &b in s {
        if b < b'0' || b > b'9' { return None; }
        n = n.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(n)
}

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

fn fmt_cpu_stat(buf: &mut [u8], ticks: u64) -> usize {
    let mut pos = 0;
    pos += copy_str(&mut buf[pos..], b"cpu  0 0 0 ");
    pos += fmt_u64(&mut buf[pos..], ticks);
    pos += copy_str(&mut buf[pos..], b" 0 0 0 0 0 0\n");
    // Per-CPU line (htop expects at least cpu0)
    pos += copy_str(&mut buf[pos..], b"cpu0 0 0 0 ");
    pos += fmt_u64(&mut buf[pos..], ticks);
    pos += copy_str(&mut buf[pos..], b" 0 0 0 0 0 0\n");
    // Additional fields htop requires
    pos += copy_str(&mut buf[pos..], b"intr 0\n");
    pos += copy_str(&mut buf[pos..], b"ctxt 0\n");
    pos += copy_str(&mut buf[pos..], b"btime 1700000000\n");
    pos += copy_str(&mut buf[pos..], b"processes 1\n");
    pos += copy_str(&mut buf[pos..], b"procs_running 1\n");
    pos += copy_str(&mut buf[pos..], b"procs_blocked 0\n");
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
