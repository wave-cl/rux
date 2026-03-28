/// Process ID — unique per schedulable entity (process or thread).
/// Userspace `getpid()` returns `tgid`, not `pid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Pid(pub u32);

/// Thread Group ID — equals the leader's Pid. All threads in a
/// process share the same Tgid. Single-threaded: `tgid == pid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Tgid(pub u32);

/// Process Group ID — set by `setpgid()`. Used for job control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Pgid(pub u32);

/// Session ID — set by `setsid()`. Groups process groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Sid(pub u32);

/// User ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Uid(pub u32);

/// Group ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Gid(pub u32);

macro_rules! impl_id {
    ($ty:ident) => {
        impl $ty {
            #[inline(always)]
            pub const fn new(v: u32) -> Self { Self(v) }
            #[inline(always)]
            pub const fn as_u32(self) -> u32 { self.0 }
        }
    };
}

impl_id!(Pid);
impl_id!(Tgid);
impl_id!(Pgid);
impl_id!(Sid);
impl_id!(Uid);
impl_id!(Gid);
