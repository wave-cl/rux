/// Per-process filesystem context.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct FsContext {
    /// Current working directory inode.
    pub cwd: u64,
    /// Root directory inode (for chroot).
    pub root: u64,
    /// File creation mask (umask).
    pub umask: u16,
    pub _pad: [u8; 6],
}

const _: () = assert!(core::mem::size_of::<FsContext>() == 24);

impl FsContext {
    pub const DEFAULT: Self = Self {
        cwd: 0,
        root: 0,
        umask: 0o022,
        _pad: [0; 6],
    };
}

impl Default for FsContext {
    fn default() -> Self { Self::DEFAULT }
}
