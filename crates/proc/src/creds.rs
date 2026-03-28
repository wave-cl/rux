use crate::id::{Uid, Gid};

/// Maximum supplementary groups per process.
pub const MAX_SUPPLEMENTARY_GROUPS: usize = 32;

/// Process credentials — real, effective, saved, and filesystem UID/GID,
/// supplementary groups, and POSIX capabilities.
#[repr(C)]
pub struct Credentials {
    /// Real user ID (set at creation, changed by setuid).
    pub uid: Uid,
    /// Real group ID.
    pub gid: Gid,
    /// Effective user ID (used for permission checks).
    pub euid: Uid,
    /// Effective group ID.
    pub egid: Gid,
    /// Saved set-user-ID (preserved across exec for setuid binaries).
    pub suid: Uid,
    /// Saved set-group-ID.
    pub sgid: Gid,
    /// Filesystem UID (used for filesystem access checks, usually == euid).
    pub fsuid: Uid,
    /// Filesystem GID.
    pub fsgid: Gid,
    /// Number of valid entries in `supplementary`.
    pub ngroups: u8,
    pub _pad0: [u8; 3],
    /// Supplementary group IDs.
    pub supplementary: [Gid; MAX_SUPPLEMENTARY_GROUPS],
    pub _pad1: [u8; 4],
    /// Effective capability bitmask (capabilities currently in effect).
    pub cap_effective: u64,
    /// Permitted capability bitmask (upper bound of effective + inheritable).
    pub cap_permitted: u64,
    /// Inheritable capability bitmask (preserved across execve).
    pub cap_inheritable: u64,
}

const _: () = assert!(core::mem::size_of::<Credentials>() == 192);

impl Credentials {
    /// Root credentials: uid 0, gid 0, all capabilities.
    pub const ROOT: Self = Self {
        uid: Uid(0), gid: Gid(0),
        euid: Uid(0), egid: Gid(0),
        suid: Uid(0), sgid: Gid(0),
        fsuid: Uid(0), fsgid: Gid(0),
        ngroups: 0, _pad0: [0; 3],
        supplementary: [Gid(0); MAX_SUPPLEMENTARY_GROUPS],
        _pad1: [0; 4],
        cap_effective: u64::MAX,
        cap_permitted: u64::MAX,
        cap_inheritable: 0,
    };

    /// Check if this credential set has a specific capability.
    #[inline(always)]
    pub const fn has_cap(&self, cap: u8) -> bool {
        (self.cap_effective >> cap) & 1 != 0
    }

    /// Check if effective UID is root (0).
    #[inline(always)]
    pub const fn is_root(&self) -> bool {
        self.euid.0 == 0
    }

    /// Create unprivileged credentials for a user.
    pub const fn user(uid: Uid, gid: Gid) -> Self {
        Self {
            uid, gid,
            euid: uid, egid: gid,
            suid: uid, sgid: gid,
            fsuid: uid, fsgid: gid,
            ngroups: 0, _pad0: [0; 3],
            supplementary: [Gid(0); MAX_SUPPLEMENTARY_GROUPS],
            _pad1: [0; 4],
            cap_effective: 0,
            cap_permitted: 0,
            cap_inheritable: 0,
        }
    }

    /// POSIX kill(2) permission: can this credential send a signal to target?
    /// Root can signal anyone. Non-root: real or effective UID must match
    /// target's real or saved UID.
    #[inline(always)]
    pub fn can_signal(&self, target: &Credentials) -> bool {
        if self.is_root() { return true; }
        self.uid == target.uid || self.uid == target.suid
            || self.euid == target.uid || self.euid == target.suid
    }

    /// POSIX DAC file access check.
    /// `mode`: file permission bits (rwxrwxrwx as 9-bit octal).
    /// `access`: requested access (4=read, 2=write, 1=execute, OR'd).
    #[inline]
    pub fn can_access(&self, file_uid: Uid, file_gid: Gid, mode: u16, access: u8) -> bool {
        // Root bypasses DAC for read/write (but not execute unless any x bit set)
        if self.is_root() {
            if access & 1 == 0 { return true; } // not checking execute
            return (mode & 0o111) != 0; // root needs at least one x bit
        }

        let bits = if self.fsuid == file_uid {
            (mode >> 6) & 7 // owner bits
        } else if self.fsgid == file_gid || self.in_group(file_gid) {
            (mode >> 3) & 7 // group bits
        } else {
            mode & 7 // other bits
        } as u8;

        (bits & access) == access
    }

    /// Set effective UID. Non-root can only set to real uid or saved uid.
    pub fn set_euid(&mut self, uid: Uid) -> Result<Uid, crate::error::ProcError> {
        if !self.is_root() && uid != self.uid && uid != self.suid {
            return Err(crate::error::ProcError::NotPermitted);
        }
        let old = self.euid;
        self.euid = uid;
        self.fsuid = uid;
        Ok(old)
    }

    /// Set effective GID. Non-root can only set to real gid or saved gid.
    pub fn set_egid(&mut self, gid: Gid) -> Result<Gid, crate::error::ProcError> {
        if !self.is_root() && gid != self.gid && gid != self.sgid {
            return Err(crate::error::ProcError::NotPermitted);
        }
        let old = self.egid;
        self.egid = gid;
        self.fsgid = gid;
        Ok(old)
    }

    /// Add a supplementary group. Returns error if table is full.
    pub fn add_group(&mut self, gid: Gid) -> Result<(), crate::error::ProcError> {
        if self.ngroups as usize >= MAX_SUPPLEMENTARY_GROUPS {
            return Err(crate::error::ProcError::ResourceLimit);
        }
        self.supplementary[self.ngroups as usize] = gid;
        self.ngroups += 1;
        Ok(())
    }

    /// Check if a GID is in the supplementary group list.
    #[inline(always)]
    pub fn in_group(&self, gid: Gid) -> bool {
        let n = self.ngroups as usize;
        let mut i = 0;
        while i < n {
            if self.supplementary[i] == gid {
                return true;
            }
            i += 1;
        }
        false
    }
}

impl Default for Credentials {
    fn default() -> Self { Self::ROOT }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_signal_root_signals_anyone() {
        let root = Credentials::ROOT;
        let user = Credentials::user(Uid(1000), Gid(1000));
        assert!(root.can_signal(&user), "root should be able to signal any process");
    }

    #[test]
    fn can_signal_same_uid() {
        let a = Credentials::user(Uid(1000), Gid(1000));
        let b = Credentials::user(Uid(1000), Gid(2000));
        assert!(a.can_signal(&b), "same real uid should allow signaling");
    }

    #[test]
    fn can_signal_euid_matches_target_suid() {
        let mut sender = Credentials::user(Uid(500), Gid(500));
        // Simulate setuid: sender euid differs from uid
        sender.euid = Uid(1000);
        sender.fsuid = Uid(1000);
        let mut target = Credentials::user(Uid(999), Gid(999));
        target.suid = Uid(1000);
        assert!(sender.can_signal(&target), "sender euid matching target suid should allow");
    }

    #[test]
    fn can_signal_denied_between_different_users() {
        let a = Credentials::user(Uid(1000), Gid(1000));
        let b = Credentials::user(Uid(2000), Gid(2000));
        assert!(!a.can_signal(&b), "different uid/euid should deny signaling");
    }

    #[test]
    fn can_access_root_read_write() {
        let root = Credentials::ROOT;
        // Root bypasses DAC for read/write
        assert!(root.can_access(Uid(1000), Gid(1000), 0o000, 4), "root can read anything");
        assert!(root.can_access(Uid(1000), Gid(1000), 0o000, 2), "root can write anything");
    }

    #[test]
    fn can_access_root_execute_needs_x_bit() {
        let root = Credentials::ROOT;
        assert!(!root.can_access(Uid(1000), Gid(1000), 0o000, 1), "root cannot execute without any x bit");
        assert!(root.can_access(Uid(1000), Gid(1000), 0o100, 1), "root can execute with owner x bit");
        assert!(root.can_access(Uid(1000), Gid(1000), 0o010, 1), "root can execute with group x bit");
        assert!(root.can_access(Uid(1000), Gid(1000), 0o001, 1), "root can execute with other x bit");
    }

    #[test]
    fn can_access_owner_bits() {
        let user = Credentials::user(Uid(1000), Gid(1000));
        // File owned by user with rwx------
        assert!(user.can_access(Uid(1000), Gid(9999), 0o700, 4), "owner should read");
        assert!(user.can_access(Uid(1000), Gid(9999), 0o700, 2), "owner should write");
        assert!(user.can_access(Uid(1000), Gid(9999), 0o700, 1), "owner should execute");
        assert!(!user.can_access(Uid(1000), Gid(9999), 0o000, 4), "owner no perms should deny read");
    }

    #[test]
    fn can_access_group_bits() {
        let user = Credentials::user(Uid(1000), Gid(50));
        // File owned by different user, same group, ---rwx---
        assert!(user.can_access(Uid(9999), Gid(50), 0o070, 4), "group should read");
        assert!(!user.can_access(Uid(9999), Gid(50), 0o050, 2), "group without w should deny write");
    }

    #[test]
    fn can_access_supplementary_group() {
        let mut user = Credentials::user(Uid(1000), Gid(1000));
        user.add_group(Gid(50)).unwrap();
        // File group is supplementary group
        assert!(user.can_access(Uid(9999), Gid(50), 0o070, 4), "supplementary group should grant access");
    }

    #[test]
    fn can_access_other_bits() {
        let user = Credentials::user(Uid(1000), Gid(1000));
        // File owned by different user/group, ------rwx
        assert!(user.can_access(Uid(9999), Gid(9999), 0o007, 4), "other should read");
        assert!(!user.can_access(Uid(9999), Gid(9999), 0o005, 2), "other without w should deny write");
    }

    #[test]
    fn set_euid_root_can_set_any() {
        let mut root = Credentials::ROOT;
        let old = root.set_euid(Uid(1000)).expect("root should set euid to anything");
        assert_eq!(old, Uid(0), "old euid should be 0");
        assert_eq!(root.euid, Uid(1000), "euid should be updated");
        assert_eq!(root.fsuid, Uid(1000), "fsuid should track euid");
    }

    #[test]
    fn set_euid_nonroot_allowed_values() {
        let mut user = Credentials::user(Uid(1000), Gid(1000));
        user.suid = Uid(2000);
        // Can set to real uid
        user.set_euid(Uid(1000)).expect("non-root can set euid to real uid");
        // Can set to saved uid
        user.set_euid(Uid(2000)).expect("non-root can set euid to saved uid");
        // Cannot set to arbitrary uid
        let err = user.set_euid(Uid(9999)).unwrap_err();
        assert_eq!(err, crate::error::ProcError::NotPermitted, "non-root cannot set arbitrary euid");
    }

    #[test]
    fn add_group_and_in_group() {
        let mut user = Credentials::user(Uid(1000), Gid(1000));
        assert!(!user.in_group(Gid(50)), "should not be in group 50 initially");
        user.add_group(Gid(50)).expect("add_group should succeed");
        assert!(user.in_group(Gid(50)), "should be in group 50 after adding");
        assert!(!user.in_group(Gid(51)), "should not be in unrelated group");
    }

    #[test]
    fn add_group_full() {
        let mut user = Credentials::user(Uid(1000), Gid(1000));
        for i in 0..MAX_SUPPLEMENTARY_GROUPS {
            user.add_group(Gid(i as u32 + 100)).expect("add_group should succeed");
        }
        let err = user.add_group(Gid(9999)).unwrap_err();
        assert_eq!(err, crate::error::ProcError::ResourceLimit, "should fail when supplementary groups full");
    }

    #[test]
    fn has_cap() {
        let root = Credentials::ROOT;
        assert!(root.has_cap(0), "root should have cap 0");
        assert!(root.has_cap(63), "root should have cap 63");
        let user = Credentials::user(Uid(1000), Gid(1000));
        assert!(!user.has_cap(0), "unprivileged user should not have any caps");
    }

    #[test]
    fn is_root() {
        let root = Credentials::ROOT;
        assert!(root.is_root(), "ROOT should be root");
        let user = Credentials::user(Uid(1000), Gid(1000));
        assert!(!user.is_root(), "unprivileged user should not be root");
        let mut setuid = Credentials::user(Uid(1000), Gid(1000));
        setuid.euid = Uid(0);
        assert!(setuid.is_root(), "euid 0 should be root");
    }
}
