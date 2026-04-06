//! POSIX error codes (negated) and signal constants.
//!
//! Syscall handlers return negative errno values on failure.
//! Using named constants instead of magic numbers improves readability.

// ── Error codes (negated POSIX errno) ───────────────────────────────

pub const EPERM: isize = -1;       // Operation not permitted
pub const ENOENT: isize = -2;      // No such file or directory
pub const ESRCH: isize = -3;       // No such process
pub const EINTR: isize = -4;       // Interrupted system call
pub const EIO: isize = -5;         // Input/output error
pub const EBADF: isize = -9;       // Bad file descriptor
pub const ECHILD: isize = -10;     // No child processes
pub const EAGAIN: isize = -11;     // Resource temporarily unavailable
pub const EACCES: isize = -13;     // Permission denied
pub const EFAULT: isize = -14;     // Bad address
pub const EEXIST: isize = -17;     // File exists
pub const ENOTDIR: isize = -20;    // Not a directory
pub const EINVAL: isize = -22;     // Invalid argument
pub const ELOOP: isize = -40;      // Too many levels of symbolic links
pub const ESPIPE: isize = -29;     // Illegal seek (pipe)
pub const EPIPE: isize = -32;      // Broken pipe
pub const ERANGE: isize = -34;     // Numerical result out of range
pub const ENOMEM: isize = -12;     // Cannot allocate memory
pub const ENOSYS: isize = -38;     // Function not implemented
pub const EAFNOSUPPORT: isize = -97;  // Address family not supported
pub const EPROTONOSUPPORT: isize = -93; // Protocol not supported
pub const ECONNREFUSED: isize = -111;  // Connection refused
pub const EINPROGRESS: isize = -115;   // Operation now in progress
pub const ETIMEDOUT: isize = -110;     // Connection timed out
pub const ENETUNREACH: isize = -101;   // Network is unreachable
pub const EADDRINUSE: isize = -98;     // Address already in use
pub const EOPNOTSUPP: isize = -95;     // Operation not supported on socket
pub const ENOTCONN: isize = -107;     // Transport endpoint is not connected

// ── Signal numbers (POSIX) ──────────────────────────────────────────

pub const SIGKILL: u8 = 9;
pub const SIGCHLD: u8 = 17;
#[allow(dead_code)]
pub const SIGCONT: u8 = 18;
#[allow(dead_code)]
pub const SIGSTOP: u8 = 19;
#[allow(dead_code)]
pub const SIGTSTP: u8 = 20;

// ── Clone flags (Linux) ─────────────────────────────────────────────

pub const CLONE_VM: usize = 0x100;
#[allow(dead_code)]
pub const CLONE_FS: usize = 0x200;
#[allow(dead_code)]
pub const CLONE_FILES: usize = 0x400;
#[allow(dead_code)]
pub const CLONE_SIGHAND: usize = 0x800;
pub const CLONE_THREAD: usize = 0x10000;
pub const CLONE_CHILD_CLEARTID: usize = 0x200000;
