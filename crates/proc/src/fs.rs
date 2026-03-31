/// Per-process filesystem context: CWD inode, path cache, root, umask.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct FsContext {
    /// Current working directory inode.
    pub cwd: u64,
    /// Root directory inode (for chroot).
    pub root: u64,
    /// Cached CWD path for getcwd() (null-terminated).
    pub cwd_path: [u8; 256],
    /// Length of the CWD path (excluding null terminator).
    pub cwd_path_len: usize,
    /// File creation mask (umask).
    pub umask: u16,
    pub _pad: [u8; 6],
}

impl FsContext {
    pub const fn new() -> Self {
        Self {
            cwd: 0,
            root: 0,
            cwd_path: {
                let mut buf = [0u8; 256];
                buf[0] = b'/';
                buf
            },
            cwd_path_len: 1,
            umask: 0o022,
            _pad: [0; 6],
        }
    }

    pub const DEFAULT: Self = Self::new();
}

impl Default for FsContext {
    fn default() -> Self { Self::DEFAULT }
}
