#![no_std]

pub mod ramfs;
pub mod path;
pub mod fdtable;
pub mod cpio;
pub mod vfs;

// ── POSIX constants ─────────────────────────────────────────────────────

pub const PATH_MAX: usize = 4096;
pub const NAME_MAX: usize = 255;
pub const SYMLOOP_MAX: usize = 8;

// ── File type constants (S_IFMT) ────────────────────────────────────────

pub const S_IFMT: u32   = 0o170000;
pub const S_IFREG: u32  = 0o100000;
pub const S_IFDIR: u32  = 0o040000;
pub const S_IFLNK: u32  = 0o120000;
pub const S_IFCHR: u32  = 0o020000;
pub const S_IFBLK: u32  = 0o060000;
pub const S_IFIFO: u32  = 0o010000;
pub const S_IFSOCK: u32 = 0o140000;

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

// ── Inode traits ────────────────────────────────────────────────────────

/// Core inode identity and metadata.
pub trait Inode {
    fn id(&self) -> InodeId;
    fn kind(&self) -> InodeType;
    /// Write inode status into `buf`. Avoids 80-byte return-by-value copy.
    fn stat(&self, buf: &mut InodeStat) -> Result<(), VfsError>;
}

/// File data operations (regular files, char/block devices).
pub trait FileOps {
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<usize, VfsError>;
    fn write(&mut self, offset: u64, buf: &[u8]) -> Result<usize, VfsError>;
    fn truncate(&mut self, size: u64) -> Result<(), VfsError>;
}

/// Directory operations. Names are pre-validated `FileName` — no length
/// checks inside the filesystem, validated once at the syscall boundary.
pub trait DirOps {
    fn lookup(&self, name: FileName<'_>) -> Result<InodeId, VfsError>;
    fn create(&mut self, name: FileName<'_>, mode: u32) -> Result<InodeId, VfsError>;
    fn mkdir(&mut self, name: FileName<'_>, mode: u32) -> Result<InodeId, VfsError>;
    fn unlink(&mut self, name: FileName<'_>) -> Result<(), VfsError>;
    fn rmdir(&mut self, name: FileName<'_>) -> Result<(), VfsError>;
    fn rename(
        &mut self,
        old_name: FileName<'_>,
        new_dir: InodeId,
        new_name: FileName<'_>,
    ) -> Result<(), VfsError>;
    fn link(&mut self, name: FileName<'_>, target: InodeId) -> Result<(), VfsError>;
    fn symlink(&mut self, name: FileName<'_>, target: &[u8]) -> Result<InodeId, VfsError>;
    /// Write next directory entry into `buf`. Returns false when no more entries.
    fn readdir(&self, offset: usize, buf: &mut DirEntry) -> Result<bool, VfsError>;
}

/// Inode attribute operations.
pub trait InodeAttrOps {
    fn chmod(&mut self, mode: u32) -> Result<(), VfsError>;
    fn chown(&mut self, uid: u32, gid: u32) -> Result<(), VfsError>;
    fn utimes(&mut self, atime: u64, mtime: u64) -> Result<(), VfsError>;
}

/// Symlink operations.
pub trait SymlinkOps {
    fn readlink(&self, buf: &mut [u8]) -> Result<usize, VfsError>;
}

// ── FileSystem trait ────────────────────────────────────────────────────

/// Inode-based filesystem interface. Concrete filesystems (ramfs, ext4, etc.)
/// implement this trait. Path resolution lives above this layer.
///
/// All name parameters use `FileName` — validated once, no re-checking.
/// `stat` and `readdir` write into caller-provided buffers — no copies.
pub trait FileSystem {
    fn root_inode(&self) -> InodeId;

    /// Write inode status into `buf`.
    fn stat(&self, ino: InodeId, buf: &mut InodeStat) -> Result<(), VfsError>;

    // ── File I/O ────────────────────────────────────────────────────
    fn read(&self, ino: InodeId, offset: u64, buf: &mut [u8]) -> Result<usize, VfsError>;
    fn write(&mut self, ino: InodeId, offset: u64, buf: &[u8]) -> Result<usize, VfsError>;
    fn truncate(&mut self, ino: InodeId, size: u64) -> Result<(), VfsError>;

    // ── Directory operations ────────────────────────────────────────
    fn lookup(&self, dir: InodeId, name: FileName<'_>) -> Result<InodeId, VfsError>;
    fn create(&mut self, dir: InodeId, name: FileName<'_>, mode: u32) -> Result<InodeId, VfsError>;
    fn mkdir(&mut self, dir: InodeId, name: FileName<'_>, mode: u32) -> Result<InodeId, VfsError>;
    fn unlink(&mut self, dir: InodeId, name: FileName<'_>) -> Result<(), VfsError>;
    fn rmdir(&mut self, dir: InodeId, name: FileName<'_>) -> Result<(), VfsError>;
    fn link(&mut self, dir: InodeId, name: FileName<'_>, target: InodeId) -> Result<(), VfsError>;
    fn symlink(
        &mut self,
        dir: InodeId,
        name: FileName<'_>,
        target: &[u8],
    ) -> Result<InodeId, VfsError>;
    fn readlink(&self, ino: InodeId, buf: &mut [u8]) -> Result<usize, VfsError>;
    /// Write next directory entry into `buf`. Returns false when no more entries.
    fn readdir(
        &self,
        dir: InodeId,
        offset: usize,
        buf: &mut DirEntry,
    ) -> Result<bool, VfsError>;
    fn rename(
        &mut self,
        old_dir: InodeId,
        old_name: FileName<'_>,
        new_dir: InodeId,
        new_name: FileName<'_>,
    ) -> Result<(), VfsError>;

    // ── Attribute operations ────────────────────────────────────────
    fn chmod(&mut self, ino: InodeId, mode: u32) -> Result<(), VfsError>;
    fn chown(&mut self, ino: InodeId, uid: u32, gid: u32) -> Result<(), VfsError>;
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
