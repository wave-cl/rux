//! File permission checks (DAC — Discretionary Access Control).
//!
//! Checks Unix file mode bits against the calling process's
//! effective UID/GID.

/// Permission bits requested by open/access.
pub const R_OK: u32 = 4;
pub const W_OK: u32 = 2;
pub const X_OK: u32 = 1;

/// Check if the current process can access a file with the given mode.
///
/// `file_mode` — the inode's mode (includes S_IFMT + permission bits)
/// `file_uid` — the inode's owner UID
/// `file_gid` — the inode's owner GID
/// `requested` — combination of R_OK, W_OK, X_OK
///
/// Returns true if access is allowed.
pub fn check_access(
    file_mode: u32,
    file_uid: u32,
    file_gid: u32,
    requested: u32,
) -> bool {
    let (euid, egid) = unsafe {
        (crate::syscall::PROCESS.euid, crate::syscall::PROCESS.egid)
    };

    // Root (euid 0) can do anything
    if euid == 0 { return true; }

    let perm_bits = if euid == file_uid {
        (file_mode >> 6) & 7 // owner bits
    } else if egid == file_gid {
        (file_mode >> 3) & 7 // group bits
    } else {
        file_mode & 7         // other bits
    };

    (requested & !perm_bits) == 0
}
