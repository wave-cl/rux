/// devfs — virtual filesystem for device special files.
///
/// Provides /dev/null, /dev/zero, /dev/urandom, /dev/console, /dev/tty.
/// Implements FileSystem trait with fixed inodes.

use crate::{FileSystem, FileName, InodeId, InodeStat, DirEntry, VfsError, InodeType};
use crate::{S_IFDIR, S_IFCHR};

const INO_ROOT: InodeId = 0;
const INO_NULL: InodeId = 1;
const INO_ZERO: InodeId = 2;
const INO_URANDOM: InodeId = 3;
const INO_CONSOLE: InodeId = 4;
const INO_TTY: InodeId = 5;
const INO_RANDOM: InodeId = 6;
const INO_FULL: InodeId = 7;
const INO_STDIN: InodeId = 8;
const INO_STDOUT: InodeId = 9;
const INO_STDERR: InodeId = 10;

const NUM_ENTRIES: usize = 10;

const ENTRIES: [(&[u8], InodeId); NUM_ENTRIES] = [
    (b"null", INO_NULL),
    (b"zero", INO_ZERO),
    (b"urandom", INO_URANDOM),
    (b"console", INO_CONSOLE),
    (b"tty", INO_TTY),
    (b"random", INO_RANDOM),
    (b"full", INO_FULL),
    (b"stdin", INO_STDIN),
    (b"stdout", INO_STDOUT),
    (b"stderr", INO_STDERR),
];

/// Linux major:minor encoded as (major << 8) | minor.
fn dev_rdev(ino: InodeId) -> u32 {
    match ino {
        INO_NULL => (1 << 8) | 3,       // 1:3
        INO_ZERO => (1 << 8) | 5,       // 1:5
        INO_FULL => (1 << 8) | 7,       // 1:7
        INO_RANDOM | INO_URANDOM => (1 << 8) | 9, // 1:9
        INO_CONSOLE => (5 << 8) | 1,    // 5:1
        INO_TTY => (5 << 8) | 0,        // 5:0
        _ => 0,
    }
}

/// Simple PRNG state for /dev/urandom (xorshift64).
static mut RNG_STATE: u64 = 0x12345678_9ABCDEF0;

fn next_random() -> u64 {
    unsafe {
        let mut x = RNG_STATE;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        RNG_STATE = x;
        x
    }
}

pub struct DevFs;

impl DevFs {
    pub const fn new() -> Self { Self }
}

impl FileSystem for DevFs {
    fn root_inode(&self) -> InodeId { INO_ROOT }

    fn stat(&self, ino: InodeId, buf: &mut InodeStat) -> Result<(), VfsError> {
        unsafe { *buf = core::mem::MaybeUninit::zeroed().assume_init(); }
        buf.ino = ino;
        buf.blksize = 4096;
        match ino {
            INO_ROOT => {
                buf.mode = S_IFDIR | 0o755;
                buf.nlink = 2;
            }
            INO_NULL | INO_ZERO | INO_URANDOM | INO_CONSOLE | INO_TTY |
            INO_RANDOM | INO_FULL => {
                buf.mode = S_IFCHR | 0o666;
                buf.nlink = 1;
                buf.rdev = dev_rdev(ino);
            }
            INO_STDIN | INO_STDOUT | INO_STDERR => {
                buf.mode = crate::S_IFLNK | 0o777;
                buf.nlink = 1;
                buf.size = 15; // "/proc/self/fd/N"
            }
            _ => return Err(VfsError::NotFound),
        }
        Ok(())
    }

    fn read(&self, ino: InodeId, _offset: u64, buf: &mut [u8]) -> Result<usize, VfsError> {
        match ino {
            INO_ROOT => Err(VfsError::IsADirectory),
            INO_NULL => Ok(0), // always EOF
            INO_ZERO => {
                for b in buf.iter_mut() { *b = 0; }
                Ok(buf.len())
            }
            INO_URANDOM => {
                let mut i = 0;
                while i + 8 <= buf.len() {
                    let r = next_random();
                    buf[i..i+8].copy_from_slice(&r.to_le_bytes());
                    i += 8;
                }
                while i < buf.len() {
                    buf[i] = next_random() as u8;
                    i += 1;
                }
                Ok(buf.len())
            }
            INO_RANDOM => {
                // /dev/random: same as urandom (no blocking entropy pool distinction)
                let mut i = 0;
                while i + 8 <= buf.len() {
                    let r = next_random();
                    buf[i..i+8].copy_from_slice(&r.to_le_bytes());
                    i += 8;
                }
                while i < buf.len() { buf[i] = next_random() as u8; i += 1; }
                Ok(buf.len())
            }
            INO_FULL => {
                // /dev/full: reads return zeros (like /dev/zero)
                for b in buf.iter_mut() { *b = 0; }
                Ok(buf.len())
            }
            INO_CONSOLE | INO_TTY => Ok(0),
            _ => Err(VfsError::NotFound),
        }
    }

    fn write(&mut self, ino: InodeId, _offset: u64, buf: &[u8]) -> Result<usize, VfsError> {
        match ino {
            INO_NULL => Ok(buf.len()),
            INO_FULL => Err(VfsError::NoSpace), // /dev/full: always ENOSPC
            INO_CONSOLE | INO_TTY => Ok(buf.len()),
            _ => Err(VfsError::NotSupported),
        }
    }

    fn truncate(&mut self, _ino: InodeId, _size: u64) -> Result<(), VfsError> { Ok(()) }

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

    fn readdir(&self, dir: InodeId, offset: usize, buf: &mut DirEntry) -> Result<bool, VfsError> {
        if dir != INO_ROOT { return Err(VfsError::NotADirectory); }
        if offset >= NUM_ENTRIES { return Ok(false); }
        let (name, ino) = ENTRIES[offset];
        buf.ino = ino;
        buf.kind = InodeType::CharDevice;
        buf.name_len = name.len() as u8;
        buf.name[..name.len()].copy_from_slice(name);
        Ok(true)
    }

    fn create(&mut self, _dir: InodeId, _name: FileName<'_>, _mode: u32) -> Result<InodeId, VfsError> { Err(VfsError::ReadOnly) }
    fn mkdir(&mut self, _dir: InodeId, _name: FileName<'_>, _mode: u32) -> Result<InodeId, VfsError> { Err(VfsError::ReadOnly) }
    fn unlink(&mut self, _dir: InodeId, _name: FileName<'_>) -> Result<(), VfsError> { Err(VfsError::ReadOnly) }
    fn rmdir(&mut self, _dir: InodeId, _name: FileName<'_>) -> Result<(), VfsError> { Err(VfsError::ReadOnly) }
    fn link(&mut self, _dir: InodeId, _name: FileName<'_>, _target: InodeId) -> Result<(), VfsError> { Err(VfsError::ReadOnly) }
    fn symlink(&mut self, _dir: InodeId, _name: FileName<'_>, _target: &[u8]) -> Result<InodeId, VfsError> { Err(VfsError::ReadOnly) }
    fn readlink(&self, ino: InodeId, buf: &mut [u8]) -> Result<usize, VfsError> {
        let target: &[u8] = match ino {
            INO_STDIN => b"/proc/self/fd/0",
            INO_STDOUT => b"/proc/self/fd/1",
            INO_STDERR => b"/proc/self/fd/2",
            _ => return Err(VfsError::NotSupported),
        };
        let len = target.len().min(buf.len());
        buf[..len].copy_from_slice(&target[..len]);
        Ok(len)
    }
    fn rename(&mut self, _old_dir: InodeId, _old_name: FileName<'_>, _new_dir: InodeId, _new_name: FileName<'_>) -> Result<(), VfsError> { Err(VfsError::ReadOnly) }
    fn chmod(&mut self, _ino: InodeId, _mode: u32) -> Result<(), VfsError> { Ok(()) }
    fn chown(&mut self, _ino: InodeId, _uid: u32, _gid: u32) -> Result<(), VfsError> { Ok(()) }
    fn utimes(&mut self, _ino: InodeId, _atime: u64, _mtime: u64) -> Result<(), VfsError> { Ok(()) }
}
