use crate::id::{Pgid, Sid};

/// Process group — a set of processes for job control.
#[repr(C)]
pub struct ProcessGroup {
    /// Process group ID.
    pub pgid: Pgid,
    /// Session this group belongs to.
    pub session: Sid,
}

const _: () = assert!(core::mem::size_of::<ProcessGroup>() == 8);

/// Session — groups process groups under a login session.
#[repr(C)]
pub struct Session {
    /// Session ID.
    pub sid: Sid,
    pub _pad0: [u8; 4],
    /// Controlling terminal inode (0 = no controlling terminal).
    pub ctty: u64,
    /// Foreground process group.
    pub foreground: Pgid,
    pub _pad1: [u8; 4],
}

const _: () = assert!(core::mem::size_of::<Session>() == 24);

impl Default for ProcessGroup {
    fn default() -> Self {
        Self { pgid: Pgid(0), session: Sid(0) }
    }
}

impl Default for Session {
    fn default() -> Self {
        Self { sid: Sid(0), _pad0: [0; 4], ctty: 0, foreground: Pgid(0), _pad1: [0; 4] }
    }
}
