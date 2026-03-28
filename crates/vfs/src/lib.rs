#![no_std]

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
    /// Convert to S_IFMT mode bits.
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

    /// Convert from S_IFMT mode bits.
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
    /// Access mode bits: O_RDONLY(0), O_WRONLY(1), O_RDWR(2).
    #[inline(always)]
    pub const fn access_mode(self) -> u32 { self.0 & 3 }
    #[inline(always)]
    pub const fn is_read(self) -> bool { self.access_mode() != 1 }
    #[inline(always)]
    pub const fn is_write(self) -> bool { self.access_mode() != 0 }
}

// ── VFS errors ──────────────────────────────────────────────────────────

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

// ── Inode ID ────────────────────────────────────────────────────────────

pub type InodeId = u64;

// ── InodeStat (POSIX struct stat) ───────────────────────────────────────

/// File status — matches POSIX `struct stat` semantics.
/// `mode` encodes both file type (S_IFMT) and permission bits (rwxrwxrwx).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct InodeStat {
    pub ino: InodeId,
    pub mode: u32,       // S_IFMT | permission bits
    pub nlink: u32,      // hard link count
    pub uid: u32,
    pub gid: u32,
    pub size: u64,       // total size in bytes
    pub blocks: u64,     // 512-byte blocks allocated
    pub blksize: u32,    // preferred I/O block size
    pub _pad0: u32,
    pub atime: u64,      // last access (nanoseconds since epoch)
    pub mtime: u64,      // last modification
    pub ctime: u64,      // last status change
    pub dev: u32,        // device ID
    pub rdev: u32,       // device ID (special files)
}

const _: () = assert!(core::mem::size_of::<InodeStat>() == 80);

// ── DirEntry (readdir) ──────────────────────────────────────────────────

/// Directory entry returned by readdir.
#[repr(C)]
pub struct DirEntry {
    pub ino: InodeId,
    pub kind: InodeType,
    pub name_len: u8,
    pub _pad: [u8; 6],
    pub name: [u8; 256],
}

// ── Inode traits ────────────────────────────────────────────────────────

/// Core inode identity and metadata.
pub trait Inode {
    fn id(&self) -> InodeId;
    fn kind(&self) -> InodeType;
    fn stat(&self) -> Result<InodeStat, VfsError>;
}

/// File data operations (regular files, char/block devices).
pub trait FileOps {
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<usize, VfsError>;
    fn write(&mut self, offset: u64, buf: &[u8]) -> Result<usize, VfsError>;
    fn truncate(&mut self, size: u64) -> Result<(), VfsError>;
}

/// Directory operations.
pub trait DirOps {
    fn lookup(&self, name: &[u8]) -> Result<InodeId, VfsError>;
    fn create(&mut self, name: &[u8], mode: u32) -> Result<InodeId, VfsError>;
    fn mkdir(&mut self, name: &[u8], mode: u32) -> Result<InodeId, VfsError>;
    fn unlink(&mut self, name: &[u8]) -> Result<(), VfsError>;
    fn rmdir(&mut self, name: &[u8]) -> Result<(), VfsError>;
    fn rename(
        &mut self,
        old_name: &[u8],
        new_dir: InodeId,
        new_name: &[u8],
    ) -> Result<(), VfsError>;
    fn link(&mut self, name: &[u8], target: InodeId) -> Result<(), VfsError>;
    fn symlink(&mut self, name: &[u8], target: &[u8]) -> Result<InodeId, VfsError>;
    fn readdir(&self, offset: usize) -> Result<Option<DirEntry>, VfsError>;
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
pub trait FileSystem {
    /// Root directory inode.
    fn root_inode(&self) -> InodeId;

    /// Get inode status.
    fn stat(&self, ino: InodeId) -> Result<InodeStat, VfsError>;

    // ── File I/O ────────────────────────────────────────────────────
    fn read(&self, ino: InodeId, offset: u64, buf: &mut [u8]) -> Result<usize, VfsError>;
    fn write(&mut self, ino: InodeId, offset: u64, buf: &[u8]) -> Result<usize, VfsError>;
    fn truncate(&mut self, ino: InodeId, size: u64) -> Result<(), VfsError>;

    // ── Directory operations ────────────────────────────────────────
    fn lookup(&self, dir: InodeId, name: &[u8]) -> Result<InodeId, VfsError>;
    fn create(&mut self, dir: InodeId, name: &[u8], mode: u32) -> Result<InodeId, VfsError>;
    fn mkdir(&mut self, dir: InodeId, name: &[u8], mode: u32) -> Result<InodeId, VfsError>;
    fn unlink(&mut self, dir: InodeId, name: &[u8]) -> Result<(), VfsError>;
    fn rmdir(&mut self, dir: InodeId, name: &[u8]) -> Result<(), VfsError>;
    fn link(&mut self, dir: InodeId, name: &[u8], target: InodeId) -> Result<(), VfsError>;
    fn symlink(
        &mut self,
        dir: InodeId,
        name: &[u8],
        target: &[u8],
    ) -> Result<InodeId, VfsError>;
    fn readlink(&self, ino: InodeId, buf: &mut [u8]) -> Result<usize, VfsError>;
    fn readdir(
        &self,
        dir: InodeId,
        offset: usize,
    ) -> Result<Option<DirEntry>, VfsError>;
    fn rename(
        &mut self,
        old_dir: InodeId,
        old_name: &[u8],
        new_dir: InodeId,
        new_name: &[u8],
    ) -> Result<(), VfsError>;

    // ── Attribute operations ────────────────────────────────────────
    fn chmod(&mut self, ino: InodeId, mode: u32) -> Result<(), VfsError>;
    fn chown(&mut self, ino: InodeId, uid: u32, gid: u32) -> Result<(), VfsError>;
}
