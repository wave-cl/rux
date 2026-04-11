#![cfg_attr(not(test), no_std)]

pub mod ramfs;
pub mod ext2;
pub mod path;
pub mod fdtable;
pub mod cpio;
pub mod vfs;
pub mod procfs;
pub mod devfs;
pub mod getdents;

// ── POSIX constants ─────────────────────────────────────────────────────

pub const PATH_MAX: usize = 4096;
pub const NAME_MAX: usize = 255;
pub const SYMLOOP_MAX: usize = 8;

// ── Open flags (O_*) — raw u32 values for kernel code ──────────────────

pub const O_RDONLY: u32     = 0;
pub const O_WRONLY: u32     = 1;
pub const O_RDWR: u32       = 2;
pub const O_ACCMODE: u32    = 3;
pub const O_CREAT: u32      = 0o100;
pub const O_EXCL: u32       = 0o200;
pub const O_TRUNC: u32      = 0o1000;
pub const O_APPEND: u32     = 0o2000;
pub const O_NONBLOCK: u32   = 0o4000;
pub const O_CLOEXEC: u32    = 0o2000000;
pub const FD_CLOEXEC: u8    = 1;

// ── File type constants (S_IFMT) ────────────────────────────────────────

pub const S_IFMT: u32   = 0o170000;
pub const S_IFREG: u32  = 0o100000;
pub const S_IFDIR: u32  = 0o040000;
pub const S_IFLNK: u32  = 0o120000;
pub const S_IFCHR: u32  = 0o020000;
pub const S_IFBLK: u32  = 0o060000;
pub const S_IFIFO: u32  = 0o010000;
pub const S_IFSOCK: u32 = 0o140000;
pub const S_ISVTX: u32  = 0o001000; // sticky bit

// ── Inode type enum ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InodeType {
    File,
    Directory,
    Symlink,
    CharDevice,
    BlockDevice,
    Pipe,
    Socket,
}

impl InodeType {
    #[inline(always)]
    pub const fn to_mode(self) -> u32 {
        match self {
            Self::File => S_IFREG,
            Self::Directory => S_IFDIR,
            Self::Symlink => S_IFLNK,
            Self::CharDevice => S_IFCHR,
            Self::BlockDevice => S_IFBLK,
            Self::Pipe => S_IFIFO,
            Self::Socket => S_IFSOCK,
        }
    }

    pub const fn from_mode(mode: u32) -> Option<Self> {
        match mode & S_IFMT {
            S_IFREG => Some(Self::File),
            S_IFDIR => Some(Self::Directory),
            S_IFLNK => Some(Self::Symlink),
            S_IFCHR => Some(Self::CharDevice),
            S_IFBLK => Some(Self::BlockDevice),
            S_IFIFO => Some(Self::Pipe),
            S_IFSOCK => Some(Self::Socket),
            _ => None,
        }
    }
}

// ── Seek ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeekFrom {
    Start(u64),
    Current(i64),
    End(i64),
}

// ── Open flags ──────────────────────────────────────────────────────────

/// POSIX open(2) flags. Bitmask newtype — values match Linux O_* on x86_64.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct OpenFlags(pub u32);

impl OpenFlags {
    pub const RDONLY: Self    = Self(0);
    pub const WRONLY: Self    = Self(1);
    pub const RDWR: Self      = Self(2);
    pub const CREAT: Self     = Self(0o100);
    pub const EXCL: Self      = Self(0o200);
    pub const NOCTTY: Self    = Self(0o400);
    pub const TRUNC: Self     = Self(0o1000);
    pub const APPEND: Self    = Self(0o2000);
    pub const NONBLOCK: Self  = Self(0o4000);
    pub const DIRECTORY: Self = Self(0o200000);
    pub const NOFOLLOW: Self  = Self(0o400000);
    pub const CLOEXEC: Self   = Self(0o2000000);

    #[inline(always)]
    pub const fn or(self, other: Self) -> Self { Self(self.0 | other.0) }
    #[inline(always)]
    pub const fn and(self, other: Self) -> Self { Self(self.0 & other.0) }
    #[inline(always)]
    pub const fn contains(self, flag: Self) -> bool { self.0 & flag.0 == flag.0 }
    #[inline(always)]
    pub const fn access_mode(self) -> u32 { self.0 & 3 }
    #[inline(always)]
    pub const fn is_read(self) -> bool { self.access_mode() != 1 }
    #[inline(always)]
    pub const fn is_write(self) -> bool { self.access_mode() != 0 }
}

// ── VFS errors ──────────────────────────────────────────────���───────────

// ── Credentials ────────────────────────────────────────────────────────

/// Caller credentials for VFS permission checks.
/// Passed into `Vfs::checked_*` methods by the syscall layer.
#[derive(Clone, Copy)]
pub struct Credentials {
    pub euid: u32,
    pub egid: u32,
}

/// Permission bits for access checks.
pub const R_OK: u32 = 4;
pub const W_OK: u32 = 2;
pub const X_OK: u32 = 1;

/// POSIX DAC permission check: does `cred` have `requested` access to an inode?
/// Root (euid 0) bypasses all checks. Checks owner/group/other mode bits.
#[inline]
pub fn check_perm(stat: &InodeStat, cred: &Credentials, requested: u32) -> Result<(), VfsError> {
    if cred.euid == 0 { return Ok(()); }
    let bits = if cred.euid == stat.uid {
        (stat.mode >> 6) & 7
    } else if cred.egid == stat.gid {
        (stat.mode >> 3) & 7
    } else {
        stat.mode & 7
    };
    if requested & !bits == 0 { Ok(()) } else { Err(VfsError::PermissionDenied) }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VfsError {
    NotFound,          // ENOENT (2)
    PermissionDenied,  // EACCES (13)
    NotADirectory,     // ENOTDIR (20)
    NotAFile,          // (custom)
    IsADirectory,      // EISDIR (21)
    AlreadyExists,     // EEXIST (17)
    DirectoryNotEmpty, // ENOTEMPTY (39)
    ReadOnly,          // EROFS (30)
    NoSpace,           // ENOSPC (28)
    InvalidPath,       // EINVAL (22)
    TooManySymlinks,   // ELOOP (40)
    IoError,           // EIO (5)
    NameTooLong,       // ENAMETOOLONG (36)
    TooManyOpenFiles,  // EMFILE (24)
    NotSupported,      // ENOTSUP (95)
    Busy,              // EBUSY (16)
    CrossDevice,       // EXDEV (18)
    NoDevice,          // ENODEV (19)
}

impl VfsError {
    #[inline(always)]
    pub const fn as_errno(self) -> i32 {
        match self {
            Self::NotFound => 2,
            Self::PermissionDenied => 13,
            Self::NotADirectory => 20,
            Self::NotAFile => 22,
            Self::IsADirectory => 21,
            Self::AlreadyExists => 17,
            Self::DirectoryNotEmpty => 39,
            Self::ReadOnly => 30,
            Self::NoSpace => 28,
            Self::InvalidPath => 22,
            Self::TooManySymlinks => 40,
            Self::IoError => 5,
            Self::NameTooLong => 36,
            Self::TooManyOpenFiles => 24,
            Self::NotSupported => 95,
            Self::Busy => 16,
            Self::CrossDevice => 18,
            Self::NoDevice => 19,
        }
    }
}

// ── Inode ID ───────────────────────────────────────────��────────────────

pub type InodeId = u64;

// ── FileName — validated name, checked once at syscall boundary ─────────

/// A validated file name component (no '/', no '\0', length ≤ NAME_MAX).
/// Created once at the syscall boundary, then passed through the VFS
/// without re-validation. Zero-cost: just a &[u8] with an invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileName<'a> {
    bytes: &'a [u8],
}

impl<'a> FileName<'a> {
    /// Validate and create a FileName. Returns NameTooLong or InvalidPath on failure.
    #[inline]
    pub fn new(name: &'a [u8]) -> Result<Self, VfsError> {
        if name.is_empty() || name.len() > NAME_MAX {
            return Err(VfsError::NameTooLong);
        }
        if name.contains(&b'/') || name.contains(&0) {
            return Err(VfsError::InvalidPath);
        }
        Ok(Self { bytes: name })
    }

    /// Access the raw bytes. No re-validation needed.
    #[inline(always)]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    #[inline(always)]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }
}

// ── InodeStat (POSIX struct stat) — written in place, not returned ──────

/// File status — matches POSIX `struct stat` semantics.
/// `mode` encodes both file type (S_IFMT) and permission bits (rwxrwxrwx).
///
/// All `stat` methods take `&mut InodeStat` to write in place rather than
/// returning by value — avoids 80-byte copies on the hot path.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct InodeStat {
    pub ino: InodeId,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub blocks: u64,
    pub blksize: u32,
    pub _pad0: u32,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub dev: u32,
    pub rdev: u32,
}

const _: () = assert!(core::mem::size_of::<InodeStat>() == 80);

// ── DirEntry (readdir) — written in place, not returned ─────────────────

/// Directory entry for readdir. Written in place via `&mut DirEntry`.
/// Name buffer matches NAME_MAX (255) + 1 null = 256 bytes.
#[repr(C)]
pub struct DirEntry {
    pub ino: InodeId,
    pub kind: InodeType,
    pub name_len: u8,
    pub _pad: [u8; 6],
    pub name: [u8; 256],
}

const _: () = assert!(core::mem::size_of::<DirEntry>() == 272);

// ── FileSystem trait ────────────────────────────────────────────────────

/// Inode-based filesystem interface. Concrete filesystems (ramfs, ext2, etc.)
/// implement this trait. Path resolution lives above this layer in `path.rs`.
///
/// ## Contract
///
/// All name parameters use `FileName` — validated once at the syscall boundary,
/// no length/slash/null checks needed inside implementations.
///
/// `stat` and `readdir` write into caller-provided buffers to avoid copies.
///
/// Read-only filesystems (procfs, devfs) return `ReadOnly` for all mutating
/// operations. Permission checks (DAC) are enforced by the `Vfs` layer's
/// `checked_*` methods — individual `FileSystem` implementations do not
/// check permissions. This matches the Linux VFS architecture where
/// `may_create()`/`may_delete()`/`inode_permission()` run before the
/// filesystem's `inode_operations` methods are called.
///
/// ## Error semantics
///
/// Methods return `Result<T, VfsError>`. The documented errors below are
/// **required** — implementations must check these conditions. Additional
/// errors (e.g., `IoError` for disk failures) are always permitted.
pub trait FileSystem {
    /// Return the root directory inode ID for this filesystem.
    fn root_inode(&self) -> InodeId;

    /// Write inode metadata into `buf`.
    /// Errors: `NotFound` if inode doesn't exist.
    fn stat(&self, ino: InodeId, buf: &mut InodeStat) -> Result<(), VfsError>;

    // ── File I/O ────────────────────────────────────────────────────

    /// Read up to `buf.len()` bytes from file at `offset`. Returns bytes read.
    /// Returns 0 at EOF. Errors: `IsADirectory` if inode is a directory.
    fn read(&self, ino: InodeId, offset: u64, buf: &mut [u8]) -> Result<usize, VfsError>;

    /// Write `buf` to file at `offset`. Returns bytes written.
    /// Extends the file if writing past EOF.
    /// Errors: `IsADirectory`, `ReadOnly`, `NoSpace`.
    fn write(&mut self, ino: InodeId, offset: u64, buf: &[u8]) -> Result<usize, VfsError>;

    /// Set file size. If shrinking, free excess data. If growing, extend with zeros.
    /// Errors: `IsADirectory`, `ReadOnly`.
    fn truncate(&mut self, ino: InodeId, size: u64) -> Result<(), VfsError>;

    // ── Directory operations ────────────────────────────────────────

    /// Look up `name` in directory `dir`. Returns the child inode ID.
    /// Errors: `NotFound` if absent, `NotADirectory` if `dir` is not a directory.
    fn lookup(&self, dir: InodeId, name: FileName<'_>) -> Result<InodeId, VfsError>;

    /// Create a regular file named `name` in directory `dir`. Returns new inode ID.
    /// Errors: `AlreadyExists` if name taken, `NoSpace`, `ReadOnly`.
    fn create(&mut self, dir: InodeId, name: FileName<'_>, mode: u32) -> Result<InodeId, VfsError>;

    /// Create a subdirectory named `name` in directory `dir`. Returns new inode ID.
    /// Initializes `.` and `..` entries. Increments parent link count.
    /// Errors: `AlreadyExists` if name taken, `NoSpace`, `ReadOnly`.
    fn mkdir(&mut self, dir: InodeId, name: FileName<'_>, mode: u32) -> Result<InodeId, VfsError>;

    /// Remove directory entry `name` from `dir`. Decrements target link count;
    /// frees inode + data when link count reaches zero.
    /// Errors: `NotFound`, `IsADirectory` (use `rmdir` for directories), `ReadOnly`.
    fn unlink(&mut self, dir: InodeId, name: FileName<'_>) -> Result<(), VfsError>;

    /// Remove empty subdirectory `name` from `dir`. Decrements parent link count.
    /// Errors: `NotFound`, `DirectoryNotEmpty`, `ReadOnly`.
    fn rmdir(&mut self, dir: InodeId, name: FileName<'_>) -> Result<(), VfsError>;

    /// Create hard link: add `name` in `dir` pointing to existing `target` inode.
    /// Errors: `AlreadyExists`, `IsADirectory` (cannot hardlink dirs), `ReadOnly`.
    fn link(&mut self, dir: InodeId, name: FileName<'_>, target: InodeId) -> Result<(), VfsError>;

    /// Create symbolic link `name` in `dir` pointing to `target` path bytes.
    /// Returns the new symlink inode ID.
    /// Errors: `AlreadyExists`, `NoSpace`, `ReadOnly`.
    fn symlink(
        &mut self,
        dir: InodeId,
        name: FileName<'_>,
        target: &[u8],
    ) -> Result<InodeId, VfsError>;

    /// Read symlink target into `buf`. Returns bytes written to buf.
    /// Errors: `InvalidPath` if inode is not a symlink.
    fn readlink(&self, ino: InodeId, buf: &mut [u8]) -> Result<usize, VfsError>;

    /// Write next directory entry at `offset` into `buf`. Returns `Ok(true)` if
    /// an entry was written, `Ok(false)` when no more entries.
    /// `offset` is an opaque position cookie (0 for first entry).
    /// Errors: `NotADirectory`.
    fn readdir(
        &self,
        dir: InodeId,
        offset: usize,
        buf: &mut DirEntry,
    ) -> Result<bool, VfsError>;

    /// Move/rename: remove `old_name` from `old_dir`, add `new_name` in `new_dir`
    /// pointing to the same inode. If `new_name` already exists, atomically replace it.
    /// Errors: `NotFound` (old doesn't exist), `ReadOnly`.
    fn rename(
        &mut self,
        old_dir: InodeId,
        old_name: FileName<'_>,
        new_dir: InodeId,
        new_name: FileName<'_>,
    ) -> Result<(), VfsError>;

    // ── Attribute operations ────────────────────────────────────────

    /// Change permission bits (preserves file type bits in mode).
    /// Errors: `NotFound`, `ReadOnly`.
    fn chmod(&mut self, ino: InodeId, mode: u32) -> Result<(), VfsError>;

    /// Change owner/group. Errors: `NotFound`, `ReadOnly`.
    fn chown(&mut self, ino: InodeId, uid: u32, gid: u32) -> Result<(), VfsError>;

    /// Set access and modification times. Errors: `NotFound`, `ReadOnly`.
    fn utimes(&mut self, ino: InodeId, atime: u64, mtime: u64) -> Result<(), VfsError>;
}

// ── Contract tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inode_type_to_mode_roundtrip() {
        let types = [
            InodeType::File,
            InodeType::Directory,
            InodeType::Symlink,
            InodeType::CharDevice,
            InodeType::BlockDevice,
            InodeType::Pipe,
            InodeType::Socket,
        ];
        for &t in &types {
            let mode = t.to_mode();
            let back = InodeType::from_mode(mode).unwrap();
            assert_eq!(back, t);
        }
    }

    #[test]
    fn inode_type_from_mode_invalid() {
        assert!(InodeType::from_mode(0).is_none());
        assert!(InodeType::from_mode(0o170000).is_none()); // exact S_IFMT mask
    }

    #[test]
    fn open_flags_or_and_contains() {
        let flags = OpenFlags::CREAT.or(OpenFlags::RDWR);
        assert!(flags.contains(OpenFlags::CREAT));
        assert!(flags.contains(OpenFlags::RDWR));
        assert!(!flags.contains(OpenFlags::TRUNC));
        let masked = flags.and(OpenFlags::CREAT);
        assert!(masked.contains(OpenFlags::CREAT));
    }

    #[test]
    fn open_flags_access_mode() {
        assert!(OpenFlags::RDONLY.is_read());
        assert!(!OpenFlags::RDONLY.is_write());
        assert!(!OpenFlags::WRONLY.is_read());
        assert!(OpenFlags::WRONLY.is_write());
        assert!(OpenFlags::RDWR.is_read());
        assert!(OpenFlags::RDWR.is_write());
    }

    #[test]
    fn filename_valid() {
        assert!(FileName::new(b"hello.txt").is_ok());
        assert!(FileName::new(b".").is_ok());
        assert!(FileName::new(b"..").is_ok());
    }

    #[test]
    fn filename_empty_rejected() {
        assert_eq!(FileName::new(b""), Err(VfsError::NameTooLong));
    }

    #[test]
    fn filename_slash_rejected() {
        assert_eq!(FileName::new(b"a/b"), Err(VfsError::InvalidPath));
    }

    #[test]
    fn filename_null_rejected() {
        assert_eq!(FileName::new(b"a\0b"), Err(VfsError::InvalidPath));
    }

    #[test]
    fn filename_too_long_rejected() {
        let long = [b'a'; NAME_MAX + 1];
        assert_eq!(FileName::new(&long), Err(VfsError::NameTooLong));
    }

    #[test]
    fn vfs_error_as_errno_coverage() {
        // Ensure every variant has a non-zero errno.
        let errors = [
            VfsError::NotFound,
            VfsError::PermissionDenied,
            VfsError::NotADirectory,
            VfsError::NotAFile,
            VfsError::IsADirectory,
            VfsError::AlreadyExists,
            VfsError::DirectoryNotEmpty,
            VfsError::ReadOnly,
            VfsError::NoSpace,
            VfsError::InvalidPath,
            VfsError::TooManySymlinks,
            VfsError::IoError,
            VfsError::NameTooLong,
            VfsError::TooManyOpenFiles,
            VfsError::NotSupported,
            VfsError::Busy,
            VfsError::CrossDevice,
            VfsError::NoDevice,
        ];
        for e in &errors {
            assert!(e.as_errno() > 0, "{:?} has non-positive errno", e);
        }
        // Spot-check known values.
        assert_eq!(VfsError::NotFound.as_errno(), 2);
        assert_eq!(VfsError::PermissionDenied.as_errno(), 13);
        assert_eq!(VfsError::NoSpace.as_errno(), 28);
    }

    #[test]
    fn inode_stat_size() {
        assert_eq!(core::mem::size_of::<InodeStat>(), 80);
    }

    #[test]
    fn dir_entry_size() {
        assert_eq!(core::mem::size_of::<DirEntry>(), 272);
    }
}
