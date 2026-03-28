use crate::id::{Pid, Pgid, Sid};
use crate::signal::Signal;

/// Process exit status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    /// Normal exit with status code.
    Code(i32),
    /// Terminated by signal.
    Signaled(Signal),
}

/// Clone flags — control resource sharing between parent and child.
/// Used by fork/clone to determine what is shared vs. copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CloneFlags {
    /// Share virtual memory (threads).
    Vm       = 1 << 8,
    /// Share filesystem context (cwd, root, umask).
    Fs       = 1 << 9,
    /// Share file descriptor table.
    Files    = 1 << 10,
    /// Share signal handlers.
    Sighand  = 1 << 11,
    /// Use vfork semantics (parent blocks until child execs/exits).
    Vfork    = 1 << 14,
    /// Set parent to caller's parent (for init adoption).
    Parent   = 1 << 15,
    /// Same thread group (POSIX threads).
    Thread   = 1 << 16,
    /// Create in a new PID namespace.
    NewPid   = 1 << 29,
}

/// Wait options for waitpid/wait4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum WaitOptions {
    /// Return immediately if no child has exited.
    NoHang     = 1,
    /// Also report stopped children.
    Untraced   = 2,
    /// Also report continued children.
    Continued  = 8,
}

/// Process lifecycle operations.
///
/// # Safety
/// Implementations manipulate raw task pointers, kernel stacks, and page tables.
/// All methods assume the caller holds appropriate locks.
pub unsafe trait ProcessOps {
    type Error;

    /// Create a new process/thread. `flags` is a bitmask of `CloneFlags` values.
    /// Returns the new child's Pid.
    fn fork(&mut self, flags: u32) -> Result<Pid, Self::Error>;

    /// Replace the current process image with a new program.
    fn exec(&mut self, path: &[u8], argv: &[&[u8]], envp: &[&[u8]]) -> Result<(), Self::Error>;

    /// Terminate the current process with the given status code.
    fn exit(&mut self, status: i32) -> !;

    /// Wait for a child process to change state.
    /// `pid`: -1 = any child, 0 = any in same pgrp, >0 = specific pid.
    /// `options`: bitmask of `WaitOptions` values.
    fn wait(&mut self, pid: i32, options: u32) -> Result<(Pid, ExitStatus), Self::Error>;

    /// Send a signal to a process or process group.
    /// `pid`: >0 = specific process, 0 = caller's pgrp, -1 = all, <-1 = pgrp abs(pid).
    fn kill(&mut self, pid: i32, sig: Signal) -> Result<(), Self::Error>;

    /// Get the caller's thread group ID (what userspace sees as PID).
    fn getpid(&self) -> Pid;

    /// Get the parent's thread group ID.
    fn getppid(&self) -> Pid;

    /// Set the process group of `pid` to `pgid`.
    fn setpgid(&mut self, pid: Pid, pgid: Pgid) -> Result<(), Self::Error>;

    /// Create a new session, becoming the session leader.
    fn setsid(&mut self) -> Result<Sid, Self::Error>;
}
