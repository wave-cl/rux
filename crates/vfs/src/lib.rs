#![no_std]

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeekFrom {
    Start(u64),
    Current(i64),
    End(i64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VfsError {
    NotFound,
    PermissionDenied,
    NotADirectory,
    NotAFile,
    IsADirectory,
    AlreadyExists,
    DirectoryNotEmpty,
    ReadOnly,
    NoSpace,
    InvalidPath,
    TooManySymlinks,
    IoError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum OpenFlags {
    Read = 1 << 0,
    Write = 1 << 1,
    Create = 1 << 2,
    Truncate = 1 << 3,
    Append = 1 << 4,
    Exclusive = 1 << 5,
}

pub type InodeId = u64;

pub trait FileSystem {
    type InodeHandle: Inode;

    fn root(&self) -> Result<Self::InodeHandle, VfsError>;
    fn stat(&self, inode: &Self::InodeHandle) -> Result<InodeStat, VfsError>;
}

pub trait Inode {
    fn id(&self) -> InodeId;
    fn kind(&self) -> InodeType;
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<usize, VfsError>;
    fn write(&mut self, offset: u64, buf: &[u8]) -> Result<usize, VfsError>;
    fn lookup(&self, name: &str) -> Result<InodeId, VfsError>;
}

#[repr(C)]
pub struct InodeStat {
    pub id: InodeId,        // 0  (u64)
    pub size: u64,          // 8
    pub blocks: u64,        // 16
    pub uid: u32,           // 24
    pub gid: u32,           // 28
    pub permissions: u16,   // 32
    pub kind: InodeType,    // 34 (u8, repr(u8))
    pub _pad: [u8; 5],      // 35–39 — repr(C) rounds to align(8), 40 bytes total
}

const _: () = assert!(core::mem::size_of::<InodeStat>() == 40);
