/// procfs — read-only virtual filesystem that synthesizes content on read.
///
/// Implements the FileSystem trait with fixed inodes for system info files.
/// Content is generated on-the-fly from kernel state via injected callbacks.

use crate::{FileSystem, FileName, InodeId, InodeStat, DirEntry, VfsError, InodeType};
use crate::{S_IFDIR, S_IFREG};

/// Fixed inode assignments.
const INO_ROOT: InodeId = 0;
const INO_UPTIME: InodeId = 1;
const INO_MEMINFO: InodeId = 2;
const INO_STAT: InodeId = 3;
const INO_VERSION: InodeId = 4;
const INO_LOADAVG: InodeId = 5;

const NUM_ENTRIES: usize = 5;

/// Entry metadata (name, inode, type).
const ENTRIES: [(&[u8], InodeId); NUM_ENTRIES] = [
    (b"uptime", INO_UPTIME),
    (b"meminfo", INO_MEMINFO),
    (b"stat", INO_STAT),
    (b"version", INO_VERSION),
    (b"loadavg", INO_LOADAVG),
];

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

    /// Generate content for a virtual file into a buffer.
    /// Returns the number of bytes written.
    fn generate(&self, ino: InodeId, buf: &mut [u8]) -> usize {
        match ino {
            INO_UPTIME => {
                let ticks = (self.get_ticks)();
                let secs = ticks / 1000;
                let frac = (ticks % 1000) / 10; // centiseconds
                fmt_uptime(buf, secs, frac)
            }
            INO_MEMINFO => {
                let total = (self.get_total_frames)() * 4; // KB (4K pages)
                let free = (self.get_free_frames)() * 4;
                fmt_meminfo(buf, total, free)
            }
            INO_STAT => {
                let ticks = (self.get_ticks)();
                fmt_stat(buf, ticks)
            }
            INO_VERSION => {
                let s = concat!("rux version ", env!("CARGO_PKG_VERSION"), "\n");
                let len = s.len().min(buf.len());
                buf[..len].copy_from_slice(&s.as_bytes()[..len]);
                len
            }
            INO_LOADAVG => {
                // Stub: 0.00 0.00 0.00 1/1 1
                let s = b"0.00 0.00 0.00 1/1 1\n";
                let len = s.len().min(buf.len());
                buf[..len].copy_from_slice(&s[..len]);
                len
            }
            _ => 0,
        }
    }
}

impl FileSystem for ProcFs {
    fn root_inode(&self) -> InodeId { INO_ROOT }

    fn stat(&self, ino: InodeId, buf: &mut InodeStat) -> Result<(), VfsError> {
        unsafe { *buf = core::mem::MaybeUninit::zeroed().assume_init(); }
        buf.ino = ino;
        match ino {
            INO_ROOT => {
                buf.mode = S_IFDIR | 0o555;
                buf.nlink = 2;
                buf.size = 0;
            }
            INO_UPTIME | INO_MEMINFO | INO_STAT | INO_VERSION | INO_LOADAVG => {
                buf.mode = S_IFREG | 0o444;
                buf.nlink = 1;
                // Generate content to get the size
                let mut tmp = [0u8; 512];
                buf.size = self.generate(ino, &mut tmp) as u64;
            }
            _ => return Err(VfsError::NotFound),
        }
        buf.blksize = 4096;
        Ok(())
    }

    fn read(&self, ino: InodeId, offset: u64, buf: &mut [u8]) -> Result<usize, VfsError> {
        if ino == INO_ROOT { return Err(VfsError::IsADirectory); }

        // Generate full content, then copy from offset
        let mut tmp = [0u8; 512];
        let total = self.generate(ino, &mut tmp);
        let off = offset as usize;
        if off >= total { return Ok(0); }
        let avail = total - off;
        let to_copy = avail.min(buf.len());
        buf[..to_copy].copy_from_slice(&tmp[off..off + to_copy]);
        Ok(to_copy)
    }

    fn write(&mut self, _ino: InodeId, _offset: u64, _buf: &[u8]) -> Result<usize, VfsError> {
        Err(VfsError::ReadOnly)
    }

    fn truncate(&mut self, _ino: InodeId, _size: u64) -> Result<(), VfsError> {
        Err(VfsError::ReadOnly)
    }

    fn lookup(&self, dir: InodeId, name: FileName<'_>) -> Result<InodeId, VfsError> {
        if dir != INO_ROOT { return Err(VfsError::NotADirectory); }
        let name_bytes = name.as_bytes();
        for &(entry_name, entry_ino) in &ENTRIES {
            if entry_name == name_bytes {
                return Ok(entry_ino);
            }
        }
        Err(VfsError::NotFound)
    }

    fn create(&mut self, _dir: InodeId, _name: FileName<'_>, _mode: u32) -> Result<InodeId, VfsError> {
        Err(VfsError::ReadOnly)
    }

    fn mkdir(&mut self, _dir: InodeId, _name: FileName<'_>, _mode: u32) -> Result<InodeId, VfsError> {
        Err(VfsError::ReadOnly)
    }

    fn unlink(&mut self, _dir: InodeId, _name: FileName<'_>) -> Result<(), VfsError> {
        Err(VfsError::ReadOnly)
    }

    fn rmdir(&mut self, _dir: InodeId, _name: FileName<'_>) -> Result<(), VfsError> {
        Err(VfsError::ReadOnly)
    }

    fn link(&mut self, _dir: InodeId, _name: FileName<'_>, _target: InodeId) -> Result<(), VfsError> {
        Err(VfsError::ReadOnly)
    }

    fn symlink(&mut self, _dir: InodeId, _name: FileName<'_>, _target: &[u8]) -> Result<InodeId, VfsError> {
        Err(VfsError::ReadOnly)
    }

    fn readlink(&self, _ino: InodeId, _buf: &mut [u8]) -> Result<usize, VfsError> {
        Err(VfsError::NotSupported)
    }

    fn readdir(&self, dir: InodeId, offset: usize, buf: &mut DirEntry) -> Result<bool, VfsError> {
        if dir != INO_ROOT { return Err(VfsError::NotADirectory); }
        if offset >= NUM_ENTRIES { return Ok(false); }
        let (name, ino) = ENTRIES[offset];
        buf.ino = ino;
        buf.kind = InodeType::File;
        buf.name_len = name.len() as u8;
        buf.name[..name.len()].copy_from_slice(name);
        Ok(true)
    }

    fn rename(&mut self, _old_dir: InodeId, _old_name: FileName<'_>, _new_dir: InodeId, _new_name: FileName<'_>) -> Result<(), VfsError> {
        Err(VfsError::ReadOnly)
    }

    fn chmod(&mut self, _ino: InodeId, _mode: u32) -> Result<(), VfsError> {
        Err(VfsError::ReadOnly)
    }

    fn chown(&mut self, _ino: InodeId, _uid: u32, _gid: u32) -> Result<(), VfsError> {
        Err(VfsError::ReadOnly)
    }
}

// ── Formatting helpers ──────────────────────────────────────────────

fn fmt_uptime(buf: &mut [u8], secs: u64, centisecs: u64) -> usize {
    // "123.45 123.45\n"
    let mut pos = 0;
    pos += fmt_u64(&mut buf[pos..], secs);
    buf[pos] = b'.'; pos += 1;
    pos += fmt_u64_pad2(&mut buf[pos..], centisecs);
    buf[pos] = b' '; pos += 1;
    // idle time (approximate — same as uptime for now)
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

fn fmt_stat(buf: &mut [u8], ticks: u64) -> usize {
    // "cpu  0 0 0 <idle> 0 0 0 0 0 0\n"
    let mut pos = 0;
    pos += copy_str(&mut buf[pos..], b"cpu  0 0 0 ");
    pos += fmt_u64(&mut buf[pos..], ticks);
    pos += copy_str(&mut buf[pos..], b" 0 0 0 0 0 0\n");
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
