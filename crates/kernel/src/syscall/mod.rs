/// Shared syscall implementations — architecture-independent.
///
/// Split into POSIX-standardized syscalls and Linux-specific extensions.
/// Architecture-specific entry/exit asm stays in each arch module.

pub mod posix;
pub mod linux;
mod file;
mod fs_ops;
mod process;
pub(crate) mod signal;
mod memory;
pub(crate) mod socket;
mod mount;

// ── Shared process state ────────────────────────────────────────────

/// Per-process state, consolidated into a single struct for clean vfork save/restore.
#[repr(C)]
pub struct ProcessState {
    /// Program break for brk().
    pub program_brk: usize,
    /// Next anonymous mmap virtual address.
    pub mmap_base: usize,
    /// Filesystem context: CWD inode + path cache.
    pub fs_ctx: rux_proc::fs::FsContext,
    /// Child exit status for wait4.
    pub last_child_exit: i32,
    /// Whether there's a child to collect.
    pub child_available: bool,
    /// Whether we're in a vfork child context (skip pipe ref counting in close).
    /// Signal pending/blocked bitmasks (hot path — checked every syscall return).
    pub signal_hot: rux_proc::signal::SignalHot,
    /// Signal handler table and RT queue (cold path).
    pub signal_cold: rux_proc::signal::SignalCold,
    /// Per-signal sa_restorer address (x86_64 only — musl sets this for sigreturn trampoline).
    pub signal_restorer: [usize; 32],
    /// Real user ID.
    pub uid: u32,
    /// Effective user ID (used for permission checks).
    pub euid: u32,
    /// Saved set-user-ID (preserved across exec).
    pub suid: u32,
    /// Real group ID.
    pub gid: u32,
    /// Effective group ID.
    pub egid: u32,
    /// Saved set-group-ID (preserved across exec).
    pub sgid: u32,
    /// Syscall filter bitmask (seccomp-lite infrastructure).
    pub syscall_filter: u64,
}

impl ProcessState {
    pub const fn new() -> Self {
        Self {
            program_brk: 0,
            mmap_base: 0x10000000,
            fs_ctx: rux_proc::fs::FsContext::new(),
            last_child_exit: 0,
            child_available: false,
            signal_hot: rux_proc::signal::SignalHot::new(),
            signal_cold: rux_proc::signal::SignalCold::new(),
            signal_restorer: [0; 32],
            uid: 0, euid: 0, suid: 0, gid: 0, egid: 0, sgid: 0,
            syscall_filter: 0,
        }
    }
}

pub static mut PROCESS: ProcessState = ProcessState::new();

// ── Page table helper (arch-dispatched) ─────────────────────────────

/// Get a handle to the current user-space page table.
pub unsafe fn current_user_page_table() -> crate::arch::PageTable {
    use rux_arch::PageTableRootOps;
    crate::arch::PageTable::from_root(
        rux_klib::PhysAddr::new(crate::arch::Arch::read() as usize))
}

/// Map zeroed pages into the current user page table.
/// Used by brk() and mmap() to add pages to the user address space.
/// Returns true if all pages were mapped, false on OOM (partial map may exist).
pub unsafe fn map_user_pages(
    start_va: usize,
    end_va: usize,
    flags: rux_mm::MappingFlags,
) -> bool {
    let alloc = crate::kstate::alloc();
    let mut upt = current_user_page_table();

    for pa in (start_va as u64..end_va as u64).step_by(4096) {
        use rux_mm::FrameAllocator;
        let frame = match alloc.alloc(rux_mm::PageSize::FourK) {
            Ok(f) => f,
            Err(_) => return false, // OOM
        };
        core::ptr::write_bytes(frame.as_usize() as *mut u8, 0, 4096);
        let va = rux_klib::VirtAddr::new(pa as usize);
        let _ = upt.unmap_4k(va);
        let _ = upt.map_4k(va, frame, flags, alloc);
    }
    true
}

// ── Credentials helper ──────────────────────────────────────────────

/// Build credentials from the current process state.
#[inline(always)]
pub unsafe fn current_cred() -> rux_fs::Credentials {
    rux_fs::Credentials { euid: PROCESS.euid, egid: PROCESS.egid }
}

// ── Path resolution helper (used by both POSIX and Linux) ──────���────

/// Get current time in seconds (for timestamp updates on file operations).
pub fn current_time_secs() -> u64 {
    use rux_arch::TimerOps;
    crate::arch::Arch::ticks() / 1000
}

/// Resolve a path using CWD, with execute checks on every intermediate directory.
pub unsafe fn resolve_with_cwd(path: &[u8]) -> Result<rux_fs::InodeId, isize> {
    let fs = crate::kstate::fs();
    let cred = current_cred();
    rux_fs::path::resolve_path_at_checked(fs, PROCESS.fs_ctx.cwd, path, &cred)
        .map_err(|e| -(e.as_errno() as isize))
}

/// Resolve a path relative to a directory FD, with execute checks.
pub unsafe fn resolve_at(dirfd: usize, path: &[u8]) -> Result<rux_fs::InodeId, isize> {
    let at_fdcwd = (-100isize) as usize;
    if path.first() == Some(&b'/') || dirfd == at_fdcwd {
        return resolve_with_cwd(path);
    }
    if dirfd < rux_fs::fdtable::MAX_FDS {
        if let Some(dir_ino) = rux_fs::fdtable::get_fd_inode(dirfd) {
            let fs = crate::kstate::fs();
            let cred = current_cred();
            return rux_fs::path::resolve_path_at_checked(fs, dir_ino, path, &cred)
                .map_err(|e| -(e.as_errno() as isize));
        }
    }
    resolve_with_cwd(path)
}

/// Resolve (dirfd, path_ptr) to a parent inode + basename, with execute checks.
pub unsafe fn resolve_parent_at(dirfd: usize, path_ptr: usize) -> Result<(rux_fs::InodeId, &'static [u8]), isize> {
    let path = crate::uaccess::read_user_cstr(path_ptr);
    let at_fdcwd = (-100isize) as usize;
    if path.first() == Some(&b'/') || dirfd == at_fdcwd {
        return resolve_parent_and_name(path_ptr);
    }
    if dirfd < rux_fs::fdtable::MAX_FDS {
        if let Some(dir_ino) = rux_fs::fdtable::get_fd_inode(dirfd) {
            let fs = crate::kstate::fs();
            let cred = current_cred();
            if let Some(slash) = path.iter().rposition(|&b| b == b'/') {
                let parent = rux_fs::path::resolve_path_at_checked(fs, dir_ino, &path[..slash], &cred)
                    .map_err(|e| -(e.as_errno() as isize))?;
                Ok((parent, &path[slash + 1..]))
            } else {
                Ok((dir_ino, path))
            }
        } else {
            Err(crate::errno::EBADF)
        }
    } else {
        resolve_parent_and_name(path_ptr)
    }
}

/// Resolve a user path pointer to (parent_inode, basename), with execute checks.
pub unsafe fn resolve_parent_and_name(path_ptr: usize) -> Result<(rux_fs::InodeId, &'static [u8]), isize> {
    let path = crate::uaccess::read_user_cstr(path_ptr);
    let fs = crate::kstate::fs();
    let cred = current_cred();
    rux_fs::path::resolve_parent_checked(fs, PROCESS.fs_ctx.cwd, path, &cred)
}

/// Resolve a user path to (parent_inode, validated FileName) — combines
/// resolve_parent_and_name + FileName::new into one call.
pub unsafe fn resolve_parent_fname(path_ptr: usize) -> Result<(rux_fs::InodeId, rux_fs::FileName<'static>), isize> {
    let (dir_ino, name) = resolve_parent_and_name(path_ptr)?;
    let fname = rux_fs::FileName::new(name).map_err(|_| crate::errno::EINVAL)?;
    Ok((dir_ino, fname))
}

/// Like resolve_parent_fname but with *at() dirfd semantics.
pub unsafe fn resolve_parent_fname_at(dirfd: usize, path_ptr: usize) -> Result<(rux_fs::InodeId, rux_fs::FileName<'static>), isize> {
    let (dir_ino, name) = resolve_parent_at(dirfd, path_ptr)?;
    let fname = rux_fs::FileName::new(name).map_err(|_| crate::errno::EINVAL)?;
    Ok((dir_ino, fname))
}

// ── Generic syscall dispatch ───────────────────────────────────────────

/// Architecture-independent syscall identifiers.
/// Each arch maps its own syscall numbers to this enum via `translate()`.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syscall {
    // File I/O
    Read, Write, Open, OpenAt, Close, Lseek, Dup, Dup2, Fcntl,
    Readv, Writev, Sendfile, Ioctl, Pipe2,
    // File metadata
    Stat, Lstat, Fstat, FstatAt, Faccessat, Readlink, Readlinkat,
    // Directory / path ops
    Getcwd, Creat, Mknodat, Mkdir, Mkdirat, Unlink, Unlinkat, Chdir, Fchdir,
    Rename, Renameat, Renameat2, Symlink, Symlinkat,
    // Permissions
    Chmod, Fchmod, Fchmodat, Chown, Fchown, Fchownat, Utimensat,
    // Memory
    Mmap, Munmap, Mprotect, Brk, Pread64,
    // Process
    Getpid, Getppid, Exit, ExitGroup, Kill,
    Vfork, Execve, Wait4,
    Uname, ClockGettime,
    // Signals
    Sigaction, Sigprocmask, Sigaltstack,
    // Terminal / scheduling
    SchedYield, Nanosleep,
    // User/group IDs
    Getuid, Geteuid, Getgid, Getegid, Getgroups,
    Setuid, Setgid, Setreuid, Setregid,
    // Process groups / sessions
    Setpgid, Getpgid, Setsid,
    // Linux extensions
    Getdents64, SetTidAddress, Gettid,
    SetRobustList, Futex, Tgkill, Tkill,
    SchedGetaffinity, Getrlimit,
    Poll, Gettimeofday,
    Prctl, Alarm, Access, Link, Linkat, Sysinfo, Statfs,
    // Signals (additional)
    Sigreturn,
    // Filesystem mounting
    Mount, Umount,
    // Sockets
    Socket, Bind, Sendto, Recvfrom, Setsockopt, Getsockopt, Connect,
    Getsockname, Getpeername, Sendmsg, Recvmsg, Shutdown, Sendmmsg, Recvmmsg,
    // Additional syscalls for musl/Alpine
    Getrandom, ClockGetres, Dup3, Sysctl, Flock, SetItimer, Pselect6, ClockNanosleep,
    Fstatfs,
    // Phase 1 stubs
    Getrusage, GetPriority, SetPriority, Umask, SetGroups,
    Fsync, Fdatasync, Sync, Syncfs, Fallocate,
    Getxattr, Setxattr, Fgetxattr, Fsetxattr, Lgetxattr, Lsetxattr,
    Listxattr, Flistxattr, Llistxattr,
    Removexattr, Fremovexattr, Lremovexattr,
    Capget, Capset, Personality, Seccomp,
    RestartSyscall, Membarrier,
    // Phase 2 wrappers
    Pwrite64, Ftruncate, Truncate, Rmdir, Pipe, Getsid,
    // Phase 3 epoll
    EpollCreate, EpollCreate1, EpollCtl, EpollWait, EpollPwait,
    // Phase 4 server sockets
    Listen, Accept, Accept4,
    // Phase 5 event/timer fds
    Eventfd2, TimerfdCreate, TimerfdSettime, TimerfdGettime,
    // Batch 2: memory management
    Madvise, Mincore, Mremap, Msync,
    Mlock, Munlock, Mlockall, Munlockall,
    // Batch 2: signal extensions
    SigPending, SigTimedwait, SigQueueinfo, TgSigQueueinfo, Signalfd4,
    // Batch 2: splice / zero-copy I/O
    Splice, Vmsplice, Tee,
    // Batch 2: process misc
    Setsid2, Getresuid, Getresgid, Setresuid, Setresgid,
    SchedSetaffinity, SchedGetparam, SchedSetparam,
    SchedGetscheduler, SchedSetscheduler,
    // Batch 2: filesystem misc
    Chroot, PivotRoot, Fadvise,
    Inotify, InotifyAddWatch, InotifyRmWatch,
    // Batch 2: misc
    Syslog, Reboot, Setdomainname, Sethostname,
    Pause, Getitimer,
    Lchown, Setfsuid, Setfsgid,
    MemfdCreate, CopyFileRange, Statx,
    // Batch 3: POSIX IPC
    Semget, Semop, Semctl, Shmget, Shmat, Shmdt, Shmctl,
    Msgget, Msgsnd, Msgrcv, Msgctl,
    // Batch 3: process extensions
    Clone3, Waitid, Execveat,
    ProcessVmReadv, ProcessVmWritev,
    Ptrace, SetSid, GetSid2,
    // Batch 3: resource limits
    Getrlimit2, Setrlimit,
    // Batch 3: timer/clock
    ClockSettime, ClockGettime2, TimerCreate, TimerSettime, TimerGettime, TimerGetoverrun, TimerDelete,
    // Batch 3: filesystem extended
    Readahead, FallocateRange, Quotactl,
    OpenByHandleAt, NameToHandleAt,
    // Batch 3: misc Linux
    Kcmp, Getrandom2, Pidfd, PidfdSendSignal,
    IoUringSetup, IoUringEnter, IoUringRegister,
    Close2, Dup3_2,
    Ppoll2,
    RecvFrom2, SendTo2,
    Socketpair, Gethostname,
    // Stubs that return specific values
    Prlimit64, Rseq,
    // Architecture-specific (handled by ArchSpecificOps)
    ArchSpecific(usize),
    // Unknown
    Unknown(usize),
}

impl Syscall {
    #[allow(dead_code)]
    pub fn name(&self) -> &'static str {
        match self {
            Syscall::Read => "read", Syscall::Write => "write",
            Syscall::Open | Syscall::OpenAt => "open",
            Syscall::Close => "close", Syscall::Poll => "poll",
            Syscall::Mmap => "mmap", Syscall::Brk => "brk",
            Syscall::Futex => "futex", Syscall::Nanosleep => "nanosleep",
            Syscall::ClockNanosleep => "clock_nanosleep",
            Syscall::EpollPwait | Syscall::EpollWait => "epoll_wait",
            Syscall::Pselect6 => "pselect6",
            Syscall::Connect => "connect", Syscall::Recvfrom => "recvfrom",
            Syscall::Sendto => "sendto", Syscall::Socket => "socket",
            Syscall::Clone3 => "clone3", Syscall::Execveat => "execveat",
            Syscall::Exit | Syscall::ExitGroup => "exit",
            Syscall::Wait4 => "wait4",
            Syscall::Sigaction => "sigaction", Syscall::Sigprocmask => "sigprocmask",
            Syscall::Getrandom => "getrandom",
            Syscall::Ioctl => "ioctl", Syscall::Fcntl => "fcntl",
            Syscall::Fstat | Syscall::FstatAt | Syscall::Stat => "stat",
            Syscall::Statx => "statx",
            Syscall::Getdents64 => "getdents64",
            Syscall::Unknown(_) => "unknown",
            _ => "other",
        }
    }
}

/// Dispatch a syscall by its architecture-independent identifier.
/// All arguments are native-width (usize). The arch entry point casts
/// from register-width to usize before calling.
///
/// SMAP: stac/clac brackets the entire syscall so handlers can access
/// user memory via raw pointers. Individual uaccess helpers (get_user,
/// put_user, etc.) are idempotent when SMAP is already enabled.
#[inline]
pub fn dispatch(sc: Syscall, a0: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> isize {
    unsafe { crate::uaccess::stac(); }
    let result = dispatch_inner(sc, a0, a1, a2, a3, a4);
    unsafe { crate::uaccess::clac(); }
    result
}

fn dispatch_inner(sc: Syscall, a0: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> isize {
    match sc {
        // ── POSIX.1 File I/O ───────────────────────────────────────
        Syscall::Read => posix::read(a0, a1, a2),
        Syscall::Readv => posix::readv(a0, a1, a2),
        Syscall::Pread64 => posix::pread64(a0, a1, a2, a3),
        Syscall::Write => posix::write(a0, a1, a2),
        Syscall::Open => posix::open(a0, a1, a2),
        Syscall::OpenAt => posix::openat(a0, a1, a2, a3),
        Syscall::Close => posix::close(a0),
        Syscall::Lseek => posix::lseek(a0, a1 as i64, a2),
        Syscall::Dup => posix::dup(a0),
        Syscall::Dup2 => posix::dup2(a0, a1),
        Syscall::Fcntl => posix::fcntl(a0, a1, a2),
        Syscall::Writev => posix::writev(a0, a1, a2),
        Syscall::Sendfile => posix::sendfile(a0, a1, a2, a3),
        Syscall::Ioctl => posix::ioctl(a0, a1, a2),
        Syscall::Pipe2 => linux::pipe2(a0, a1),

        // ── File metadata ──────────────────────────────────────────
        Syscall::Stat => posix::stat(a0, a1),
        Syscall::Lstat => posix::lstat(a0, a1),
        Syscall::Fstat => posix::fstat(a0, a1),
        Syscall::FstatAt => posix::fstatat(a0, a1, a2, a3),
        Syscall::Faccessat => posix::faccessat(a0, a1, a2),
        Syscall::Readlink => posix::readlink(a0, a1, a2),
        Syscall::Readlinkat => posix::readlink_at(a0, a1, a2, a3),

        // ── Directory / path ops ──────────────────────────────────
        Syscall::Getcwd => posix::getcwd(a0, a1),
        Syscall::Creat => posix::creat(a0),
        Syscall::Mknodat => posix::creat_at(a0, a1),
        Syscall::Mkdir => posix::mkdir(a0, a1),
        Syscall::Mkdirat => posix::mkdir_at(a0, a1, a2),
        Syscall::Unlink => posix::unlink(a0),
        Syscall::Unlinkat => posix::unlink_at(a0, a1),
        Syscall::Chdir => posix::chdir(a0),
        Syscall::Fchdir => posix::fchdir(a0),
        Syscall::Rename => posix::rename(a0, a1),
        Syscall::Renameat => posix::rename_at2(a0, a1, a2, a3, 0),
        Syscall::Renameat2 => posix::rename_at2(a0, a1, a2, a3, a4),
        Syscall::Symlink => posix::symlink(a0, a1),
        Syscall::Symlinkat => posix::symlink_at(a0, a1, a2),

        // ── Permissions ───────────────────────────────────────────
        Syscall::Link => posix::link(a0, a1),
        Syscall::Linkat => posix::link_at(a0, a1, a2, a3),
        Syscall::Chmod => posix::chmod(a0, a1),
        Syscall::Fchmodat => posix::chmod_at(a0, a1, a2),
        Syscall::Fchmod => posix::fchmod(a0, a1),       // fchmod(fd, mode)
        Syscall::Chown => posix::chown(a0, a1, a2),     // chown(path, uid, gid)
        Syscall::Fchownat => posix::fchownat(a0, a1, a2, a3),
        Syscall::Fchown => posix::fchown(a0, a1, a2),
        Syscall::Utimensat => posix::utimensat(a0, a1, a2, a3),

        // ── Memory ─────────────────────────────────────────────────
        Syscall::Mmap => {
            // mmap has 6 args. The 6th (offset) is saved by arch entry code.
            use rux_arch::SyscallArgOps;
            let a5 = crate::arch::Arch::saved_syscall_arg5();
            posix::mmap(a0, a1, a2, a3, a4, a5)
        }
        Syscall::Munmap => posix::munmap(a0, a1),
        Syscall::Brk => linux::brk(a0),

        // ── Process ────────────────────────────────────────────────
        Syscall::Getpid => unsafe { crate::task_table::TASK_TABLE[crate::task_table::current_task_idx()].tgid as isize },
        Syscall::Getppid => crate::task_table::current_ppid() as isize,
        Syscall::Exit => posix::exit(a0 as i32),
        Syscall::ExitGroup => linux::exit_group(a0 as i32),
        Syscall::Kill => posix::kill(a0 as isize, a1),
        Syscall::Wait4 => linux::wait4(a0, a1, a2, a3),
        Syscall::Uname => posix::uname(a0),
        Syscall::ClockGettime => posix::clock_gettime(a0, a1),
        Syscall::Nanosleep => posix::nanosleep(a0),

        // ── Signals ────────────────────────────────────────────────
        Syscall::Sigaction => posix::sigaction(a0, a1, a2),
        Syscall::Sigprocmask => posix::sigprocmask(a0, a1, a2, a3),

        // ── User/group IDs (single user: always root) ─────────────
        Syscall::Getuid => unsafe { PROCESS.uid as isize },
        Syscall::Geteuid => unsafe { PROCESS.euid as isize },
        Syscall::Getgid => unsafe { PROCESS.gid as isize },
        Syscall::Getegid => unsafe { PROCESS.egid as isize },
        Syscall::Setuid => unsafe { posix::setuid(a0 as u32) },
        Syscall::Setgid => unsafe { posix::setgid(a0 as u32) },
        Syscall::Setreuid => unsafe { posix::setreuid(a0 as u32, a1 as u32) },
        Syscall::Setregid => unsafe { posix::setregid(a0 as u32, a1 as u32) },
        Syscall::Gettid => unsafe { crate::task_table::TASK_TABLE[crate::task_table::current_task_idx()].pid as isize },

        // ── Process groups ────────────────────────────────────────
        Syscall::Setpgid => posix::setpgid(a0, a1),
        Syscall::Getpgid => posix::getpgid(a0),
        Syscall::Setsid  => posix::setsid(),

        // ── Linux extensions ───────────────────────────────────────
        Syscall::Getdents64 => linux::getdents64(a0, a1, a2),
        Syscall::SetTidAddress => linux::set_tid_address(a0),
        Syscall::Poll => posix::ppoll(a0, a1, a2, a3),
        Syscall::Gettimeofday => unsafe {
            use rux_arch::TimerOps;
            let ticks = crate::arch::Arch::ticks();
            if a0 != 0 {
                if crate::uaccess::validate_user_ptr(a0, 16).is_err() { return crate::errno::EFAULT; }
                *(a0 as *mut u64) = ticks / 1000;                // tv_sec
                *((a0 + 8) as *mut u64) = (ticks % 1000) * 1000; // tv_usec
            }
            if a1 != 0 {
                if crate::uaccess::validate_user_ptr(a1, 8).is_err() { return crate::errno::EFAULT; }
                *(a1 as *mut i32) = 0;   // tz_minuteswest
                *((a1 + 4) as *mut i32) = 0; // tz_dsttime
            }
            0
        }
        Syscall::Sysinfo => linux::sysinfo(a0),
        Syscall::Statfs => linux::statfs(a0, a1),
        Syscall::Fstatfs => linux::fstatfs(a0, a1),
        Syscall::Prlimit64 => posix::prlimit64(a0, a1, a2, a3),

        // ── Stubs: accepted but no-op ─────────────────────────────
        Syscall::Mprotect => posix::mprotect(a0, a1, a2),
        Syscall::Access => posix::faccessat((-100isize) as usize, a0, a1), // AT_FDCWD
        Syscall::Futex => posix::futex(a0, a1, a2),
        Syscall::Sigaltstack => unsafe {
            // sigaltstack(ss, old_ss) — set/get alternate signal stack
            let cold = &mut (*(&raw mut PROCESS)).signal_cold;
            if a1 != 0 { // old_ss: write current state
                if crate::uaccess::validate_user_ptr(a1, 24).is_err() { return crate::errno::EFAULT as isize; }
                crate::uaccess::put_user(a1, cold.alt_stack_base);
                crate::uaccess::put_user(a1 + core::mem::size_of::<usize>(), cold.alt_stack_flags as usize);
                crate::uaccess::put_user(a1 + 2 * core::mem::size_of::<usize>(), cold.alt_stack_size);
            }
            if a0 != 0 { // ss: set new state
                if crate::uaccess::validate_user_ptr(a0, 24).is_err() { return crate::errno::EFAULT as isize; }
                cold.alt_stack_base = crate::uaccess::get_user(a0);
                cold.alt_stack_flags = crate::uaccess::get_user::<usize>(a0 + core::mem::size_of::<usize>()) as u32;
                cold.alt_stack_size = crate::uaccess::get_user(a0 + 2 * core::mem::size_of::<usize>());
            }
            0
        },
        Syscall::SchedYield |
        Syscall::SetRobustList | Syscall::SchedGetaffinity => 0,
        Syscall::Alarm => unsafe {
            // alarm(seconds): set one-shot ITIMER_REAL, return previous remaining seconds
            use rux_arch::TimerOps;
            let now = crate::arch::Arch::ticks();
            let idx = crate::task_table::current_task_idx();
            let t = &mut crate::task_table::TASK_TABLE[idx];
            let old_remaining = if t.itimer_real_deadline > 0 && t.itimer_real_deadline > now {
                ((t.itimer_real_deadline - now) / 1000 + 1) as isize // round up to seconds
            } else { 0 };
            if a0 == 0 {
                // alarm(0): cancel timer
                t.itimer_real_deadline = 0;
                t.itimer_real_interval = 0;
            } else {
                // alarm(N): set one-shot timer for N seconds
                t.itimer_real_deadline = now + (a0 as u64) * 1000;
                t.itimer_real_interval = 0;
            }
            old_remaining
        },
        Syscall::Getrlimit => {
            // getrlimit(resource, rlim) — return RLIM_INFINITY
            if a1 != 0 {
                if crate::uaccess::validate_user_ptr(a1, 16).is_err() { return crate::errno::EFAULT; }
                unsafe {
                    *(a1 as *mut u64) = u64::MAX;
                    *((a1 + 8) as *mut u64) = u64::MAX;
                }
            }
            0
        }
        Syscall::Prctl => match a0 {
            3 => 1,  // PR_GET_DUMPABLE → dumpable
            4 => 0,  // PR_SET_DUMPABLE → accept
            _ => 0,
        }
        Syscall::Getgroups => {
            if a0 == 0 { 1 }
            else {
                if crate::uaccess::validate_user_ptr(a1, 4).is_err() { return crate::errno::EFAULT; }
                unsafe { *(a1 as *mut u32) = 0; }
                1
            }
        }

        // tgkill(tgid, tid, sig) / tkill(tid, sig) — route to kill()
        Syscall::Tgkill => posix::kill(a1 as isize, a2),
        Syscall::Tkill => posix::kill(a0 as isize, a1),

        // Dispatched by arch entry point, never reaches generic dispatch
        Syscall::Vfork | Syscall::Execve | Syscall::Sigreturn => 0,

        // ── Filesystem mounting ─────────────────────────────────────
        Syscall::Mount => mount::sys_mount(a0, a1, a2, a3, a4),
        Syscall::Umount => mount::sys_umount(a0, a1),

        // ── Sockets ────────────────────────────────────────────────
        Syscall::Socket => socket::sys_socket(a0, a1, a2),
        Syscall::Bind => socket::sys_bind(a0, a1, a2),
        Syscall::Sendto => socket::sys_sendto(a0, a1, a2, a3, a4, 0),
        Syscall::Recvfrom => socket::sys_recvfrom(a0, a1, a2, a3, a4, 0),
        Syscall::Setsockopt => socket::sys_setsockopt(a0, a1, a2, a3, a4),
        Syscall::Getsockopt => socket::sys_getsockopt(a0, a1, a2, a3, a4),
        Syscall::Connect => socket::sys_connect(a0, a1, a2),
        Syscall::Getsockname => socket::sys_getsockname(a0, a1, a2),
        Syscall::Getpeername => socket::sys_getpeername(a0, a1, a2),
        Syscall::Sendmsg => socket::sys_sendmsg(a0, a1),
        Syscall::Recvmsg => socket::sys_recvmsg(a0, a1),
        Syscall::Shutdown => socket::sys_shutdown(a0, a1),
        Syscall::Sendmmsg => socket::sys_sendmmsg(a0, a1, a2),
        Syscall::Recvmmsg => socket::sys_recvmmsg(a0, a1, a2),

        // ── Additional syscalls ────────────────────────────────────
        Syscall::Getrandom => posix::getrandom(a0, a1, a2),
        Syscall::ClockGetres => {
            // clock_getres(clockid, res) — return 1ns resolution
            if a1 != 0 {
                if crate::uaccess::validate_user_ptr(a1, 16).is_ok() {
                    unsafe { *(a1 as *mut u64) = 0; *((a1 + 8) as *mut u64) = 1; } // 0s + 1ns
                }
            }
            0
        }
        Syscall::Dup3 => posix::dup3(a0, a1, a2),
        Syscall::Sysctl => 0, // stub — OpenRC queries kernel params
        Syscall::Flock => 0, // stub — single-process, locking is a no-op
        Syscall::SetItimer => unsafe {
            // setitimer(which, new_value, old_value)
            // Only ITIMER_REAL (which=0) is implemented — sends SIGALRM on wall clock expiry
            if a0 != 0 { return 0; } // ITIMER_VIRTUAL/PROF: stub
            use rux_arch::TimerOps;
            let now = crate::arch::Arch::ticks();
            let idx = crate::task_table::current_task_idx();
            let t = &mut crate::task_table::TASK_TABLE[idx];
            // Write old value if requested
            if a2 != 0 && crate::uaccess::validate_user_ptr(a2, 32).is_ok() {
                // struct itimerval: { it_interval: timeval, it_value: timeval }
                // timeval: { tv_sec: i64, tv_usec: i64 } (on 64-bit)
                let remaining = if t.itimer_real_deadline > 0 && t.itimer_real_deadline > now {
                    t.itimer_real_deadline - now
                } else { 0 };
                let int_ms = t.itimer_real_interval;
                crate::uaccess::put_user(a2, int_ms / 1000);        // it_interval.tv_sec
                crate::uaccess::put_user(a2 + 8, (int_ms % 1000) * 1000); // it_interval.tv_usec
                crate::uaccess::put_user(a2 + 16, remaining / 1000);  // it_value.tv_sec
                crate::uaccess::put_user(a2 + 24, (remaining % 1000) * 1000); // it_value.tv_usec
            }
            // Read new value
            if a1 != 0 && crate::uaccess::validate_user_ptr(a1, 32).is_ok() {
                let int_sec: u64 = crate::uaccess::get_user(a1);
                let int_usec: u64 = crate::uaccess::get_user(a1 + 8);
                let val_sec: u64 = crate::uaccess::get_user(a1 + 16);
                let val_usec: u64 = crate::uaccess::get_user(a1 + 24);
                let interval_ms = int_sec * 1000 + int_usec / 1000;
                let value_ms = val_sec * 1000 + val_usec / 1000;
                t.itimer_real_interval = interval_ms;
                if value_ms > 0 {
                    t.itimer_real_deadline = now + value_ms;
                } else {
                    t.itimer_real_deadline = 0; // disarm
                }
            }
            0
        }
        Syscall::Pselect6 => memory::pselect6(a0, a1, a2, a3, a4),
        Syscall::ClockNanosleep => {
            // clock_nanosleep(clockid, flags, request, remain)
            // flags & 1 = TIMER_ABSTIME: request is absolute time (not supported, return 0)
            if a1 & 1 != 0 { 0 } else { posix::nanosleep(a2) }
        }

        // ── Phase 1 stubs ─────────────────────────────────────────
        Syscall::Getrusage => {
            // Zero the rusage struct (144 bytes)
            if a1 != 0 && crate::uaccess::validate_user_ptr(a1, 144).is_ok() {
                unsafe { core::ptr::write_bytes(a1 as *mut u8, 0, 144); }
            }
            0
        }
        Syscall::Umask => {
            let old = unsafe { PROCESS.fs_ctx.umask } as isize;
            unsafe { PROCESS.fs_ctx.umask = (a0 & 0o777) as u16; }
            old
        }
        // No-op stubs: safe to accept silently (single-process, no swap, etc.)
        Syscall::GetPriority | Syscall::SetPriority | Syscall::SetGroups |
        Syscall::Fsync | Syscall::Fdatasync | Syscall::Sync | Syscall::Syncfs |
        Syscall::Fallocate | Syscall::RestartSyscall | Syscall::Membarrier => 0,
        // Unsupported: return ENOSYS
        Syscall::Getxattr | Syscall::Setxattr | Syscall::Fgetxattr | Syscall::Fsetxattr |
        Syscall::Lgetxattr | Syscall::Lsetxattr | Syscall::Listxattr | Syscall::Flistxattr |
        Syscall::Llistxattr | Syscall::Removexattr | Syscall::Fremovexattr |
        Syscall::Lremovexattr |
        Syscall::Capget | Syscall::Capset | Syscall::Personality | Syscall::Seccomp => crate::errno::ENOSYS,

        // ── Phase 2 wrappers ─────────────────────────────────────
        Syscall::Pwrite64 => posix::pwrite64(a0, a1, a2, a3),
        Syscall::Ftruncate => posix::ftruncate(a0, a1),
        Syscall::Truncate => posix::truncate(a0, a1),
        Syscall::Rmdir => posix::rmdir(a0),
        Syscall::Pipe => linux::pipe2(a0, 0),
        Syscall::Getsid => unsafe {
            // getsid(pid): pid==0 means self
            let target_pid = if a0 == 0 { crate::task_table::current_pid() } else { a0 as u32 };
            match crate::task_table::find_task_by_pid(target_pid) {
                Some(i) => crate::task_table::TASK_TABLE[i].sid as isize,
                None => crate::errno::ESRCH,
            }
        }

        // ── Phase 3 epoll ─────────────────────────────────────────
        Syscall::EpollCreate => memory::epoll_create(0),
        Syscall::EpollCreate1 => memory::epoll_create(a0),
        Syscall::EpollCtl => memory::epoll_ctl(a0, a1, a2, a3),
        Syscall::EpollWait => memory::epoll_wait(a0, a1, a2, a3),
        Syscall::EpollPwait => memory::epoll_wait(a0, a1, a2, a3), // ignore sigmask

        // ── Phase 4 server sockets ────────────────────────────────
        Syscall::Listen => socket::sys_listen(a0, a1),
        Syscall::Accept => socket::sys_accept(a0, a1, a2),
        Syscall::Accept4 => {
            let fd = socket::sys_accept(a0, a1, a2);
            // Apply flags (a3): SOCK_NONBLOCK (0x800), SOCK_CLOEXEC (0x80000)
            if fd >= 0 {
                unsafe {
                    if let Some(f) = rux_fs::fdtable::get_fd_mut(fd as usize) {
                        if a3 & 0x800 != 0 { f.flags |= 0x800; } // SOCK_NONBLOCK
                        if a3 & 0x80000 != 0 { f.fd_flags |= rux_fs::fdtable::FD_CLOEXEC; }
                    }
                }
            }
            fd
        }

        // ── Phase 5 event/timer fds ───────────────────────────────
        Syscall::Eventfd2 => memory::eventfd2(a0, a1),
        Syscall::TimerfdCreate => memory::timerfd_create(a0, a1),
        Syscall::TimerfdSettime => memory::timerfd_settime(a0, a1, a2, a3),
        Syscall::TimerfdGettime => memory::timerfd_gettime(a0, a1),

        // ── Batch 2: memory management ─────────────────────────────
        Syscall::Madvise => 0, // hints are advisory — safe to ignore
        Syscall::Mincore => memory::mincore(a0, a1, a2),
        Syscall::Mremap => memory::mremap(a0, a1, a2, a3, a4),
        Syscall::Msync => { unsafe { memory::msync(a0, a1, a2); } 0 }
        Syscall::Mlock | Syscall::Munlock |
        Syscall::Mlockall | Syscall::Munlockall => 0, // all pages are locked (no swap)

        // ── Batch 2: signal extensions ────────────────────────────
        Syscall::SigPending => {
            // rt_sigpending(set, sigsetsize) — return pending signals
            if a0 != 0 {
                if crate::uaccess::validate_user_ptr(a0, 8).is_err() { return crate::errno::EFAULT; }
                unsafe { *(a0 as *mut u64) = PROCESS.signal_hot.pending.0; }
            }
            0
        }
        Syscall::SigTimedwait => {
            // rt_sigtimedwait(set, info, timeout, sigsetsize)
            // Wait for a signal from `set`. For now: sleep for the timeout duration
            // then return EAGAIN (no signal pending). This prevents busy-wait loops.
            if a2 != 0 && crate::uaccess::validate_user_ptr(a2, 16).is_ok() {
                unsafe {
                    let sec: u64 = crate::uaccess::get_user(a2);
                    let nsec: u64 = crate::uaccess::get_user(a2 + 8);
                    let ms = (sec * 1000 + nsec / 1_000_000).min(5000);
                    for _ in 0..ms {
                        use rux_arch::HaltOps;
                        crate::arch::Arch::halt_until_interrupt();
                    }
                }
            }
            crate::errno::EAGAIN
        },
        Syscall::SigQueueinfo | Syscall::TgSigQueueinfo => crate::errno::ENOSYS,
        Syscall::Signalfd4 => memory::signalfd4(a0, a1, a2),

        // ── Batch 2: splice / zero-copy I/O ───────────────────────
        Syscall::Splice => linux::splice(a0, a1, a2, a3, a4, 0),
        Syscall::Tee => linux::tee(a0, a2, a3, 0), // tee(fd_in, fd_out, len, flags)
        Syscall::Vmsplice => crate::errno::ENOSYS, // userspace→pipe not yet implemented

        // ── Batch 2: process misc ─────────────────────────────────
        Syscall::Setsid2 => posix::setsid(), // alias
        Syscall::Getresuid => unsafe {
            if a0 != 0 { crate::uaccess::put_user(a0, PROCESS.uid); }
            if a1 != 0 { crate::uaccess::put_user(a1, PROCESS.euid); }
            if a2 != 0 { crate::uaccess::put_user(a2, PROCESS.suid); }
            0
        }
        Syscall::Getresgid => unsafe {
            if a0 != 0 { crate::uaccess::put_user(a0, PROCESS.gid); }
            if a1 != 0 { crate::uaccess::put_user(a1, PROCESS.egid); }
            if a2 != 0 { crate::uaccess::put_user(a2, PROCESS.sgid); }
            0
        }
        Syscall::Setresuid => unsafe {
            PROCESS.uid = a0 as u32; PROCESS.euid = a1 as u32; PROCESS.suid = a2 as u32; 0
        }
        Syscall::Setresgid => unsafe {
            PROCESS.gid = a0 as u32; PROCESS.egid = a1 as u32; PROCESS.sgid = a2 as u32; 0
        }
        Syscall::SchedSetaffinity | Syscall::SchedGetparam | Syscall::SchedSetparam |
        Syscall::SchedGetscheduler | Syscall::SchedSetscheduler => 0, // single-CPU stubs

        // ── Batch 2: filesystem misc ──────────────────────────────
        Syscall::Chroot | Syscall::PivotRoot => crate::errno::ENOSYS, // no namespace support
        Syscall::Fadvise => 0, // advisory — safe to ignore
        Syscall::Inotify => {
            // inotify_init1(flags) → fd
            // Return a valid fd that never becomes readable. Programs fall back
            // to polling when inotify doesn't fire events.
            unsafe {
                let fd_table = &mut *rux_fs::fdtable::FD_TABLE;
                match (rux_fs::fdtable::FIRST_FILE_FD..rux_fs::fdtable::MAX_FDS)
                    .find(|&f| !fd_table[f].active)
                {
                    Some(fd) => {
                        fd_table[fd] = rux_fs::fdtable::EMPTY_FD;
                        fd_table[fd].active = true;
                        fd as isize
                    }
                    None => crate::errno::ENOMEM,
                }
            }
        },
        Syscall::InotifyAddWatch => 1, // return fake watch descriptor
        Syscall::InotifyRmWatch => 0,

        // ── Batch 2: misc ─────────────────────────────────────────
        Syscall::Syslog => crate::errno::ENOSYS,
        Syscall::Reboot => crate::errno::ENOSYS,
        Syscall::Setdomainname | Syscall::Sethostname => 0, // stubs
        Syscall::Pause => {
            // Suspend until signal — use nanosleep(very long)
            unsafe { use rux_arch::HaltOps; crate::arch::Arch::halt_until_interrupt(); }
            crate::errno::EINTR
        }
        Syscall::Getitimer => unsafe {
            // getitimer(which, value) — return current timer state
            if a0 != 0 || a1 == 0 { return 0; } // Only ITIMER_REAL; null ptr = no-op
            if crate::uaccess::validate_user_ptr(a1, 32).is_err() { return crate::errno::EFAULT; }
            use rux_arch::TimerOps;
            let now = crate::arch::Arch::ticks();
            let idx = crate::task_table::current_task_idx();
            let t = &crate::task_table::TASK_TABLE[idx];
            let remaining = if t.itimer_real_deadline > 0 && t.itimer_real_deadline > now {
                t.itimer_real_deadline - now
            } else { 0 };
            let int_ms = t.itimer_real_interval;
            crate::uaccess::put_user(a1, int_ms / 1000);
            crate::uaccess::put_user(a1 + 8, (int_ms % 1000) * 1000);
            crate::uaccess::put_user(a1 + 16, remaining / 1000);
            crate::uaccess::put_user(a1 + 24, (remaining % 1000) * 1000);
            0
        }
        Syscall::Lchown => posix::chown(a0, a1, a2), // same as chown for now
        Syscall::Setfsuid => 0,
        Syscall::Setfsgid => 0,
        Syscall::MemfdCreate => {
            // memfd_create(name, flags) → fd
            // Return an anonymous fd. mmap on it works via MAP_ANONYMOUS fallback.
            // read/write return 0 (empty). ftruncate is a no-op.
            unsafe {
                let fd_table = &mut *rux_fs::fdtable::FD_TABLE;
                match (rux_fs::fdtable::FIRST_FILE_FD..rux_fs::fdtable::MAX_FDS)
                    .find(|&f| !fd_table[f].active)
                {
                    Some(fd) => {
                        fd_table[fd] = rux_fs::fdtable::EMPTY_FD;
                        fd_table[fd].active = true;
                        fd as isize
                    }
                    None => crate::errno::ENOMEM,
                }
            }
        },
        Syscall::CopyFileRange => file::copy_file_range(a0, a1, a2, a3, a4),
        Syscall::Statx => fs_ops::statx(a0, a1, a2, a3, a4),

        // ── Batch 3: POSIX IPC ─────────────────────────────────────
        Syscall::Semget | Syscall::Semop | Syscall::Semctl => crate::errno::ENOSYS,
        Syscall::Shmget | Syscall::Shmat | Syscall::Shmdt | Syscall::Shmctl => crate::errno::ENOSYS,
        Syscall::Msgget | Syscall::Msgsnd | Syscall::Msgrcv | Syscall::Msgctl => crate::errno::ENOSYS,

        // ── Batch 3: process extensions ───────────────────────────
        Syscall::Clone3 => crate::errno::ENOSYS, // musl falls back to clone
        Syscall::Waitid => crate::errno::ENOSYS, // musl uses wait4
        Syscall::Execveat => crate::errno::ENOSYS, // musl uses execve
        Syscall::ProcessVmReadv | Syscall::ProcessVmWritev => crate::errno::ENOSYS,
        Syscall::Ptrace => crate::errno::ENOSYS,
        Syscall::SetSid => posix::setsid(),
        Syscall::GetSid2 => unsafe {
            let target_pid = if a0 == 0 { crate::task_table::current_pid() } else { a0 as u32 };
            match crate::task_table::find_task_by_pid(target_pid) {
                Some(i) => crate::task_table::TASK_TABLE[i].sid as isize,
                None => crate::errno::ESRCH,
            }
        }

        // ── Batch 3: resource limits ──────────────────────────────
        Syscall::Getrlimit2 => {
            // getrlimit(resource, rlim) — return infinity for all resources
            if a1 != 0 {
                if crate::uaccess::validate_user_ptr(a1, 16).is_err() { return crate::errno::EFAULT; }
                unsafe {
                    *(a1 as *mut u64) = u64::MAX; // rlim_cur = RLIM_INFINITY
                    *((a1 + 8) as *mut u64) = u64::MAX; // rlim_max = RLIM_INFINITY
                }
            }
            0
        }
        Syscall::Setrlimit => 0, // accept but ignore

        // ── Batch 3: timer/clock ──────────────────────────────────
        Syscall::ClockSettime => crate::errno::EPERM, // not allowed
        Syscall::ClockGettime2 => posix::clock_gettime(a0, a1), // alias
        Syscall::TimerCreate | Syscall::TimerSettime | Syscall::TimerGettime |
        Syscall::TimerGetoverrun | Syscall::TimerDelete => crate::errno::ENOSYS,

        // ── Batch 3: filesystem extended ──────────────────────────
        Syscall::Readahead => 0, // advisory — no-op
        Syscall::FallocateRange => 0, // same as fallocate
        Syscall::Quotactl => crate::errno::ENOSYS,
        Syscall::OpenByHandleAt | Syscall::NameToHandleAt => crate::errno::ENOSYS,

        // ── Batch 3: misc Linux ───────────────────────────────────
        Syscall::Kcmp => crate::errno::ENOSYS,
        Syscall::Getrandom2 => posix::getrandom(a0, a1, a2), // alias
        Syscall::Pidfd | Syscall::PidfdSendSignal => crate::errno::ENOSYS,
        Syscall::IoUringSetup | Syscall::IoUringEnter | Syscall::IoUringRegister => crate::errno::ENOSYS,
        Syscall::Close2 => posix::close(a0), // alias
        Syscall::Dup3_2 => posix::dup3(a0, a1, a2), // alias
        Syscall::Ppoll2 => posix::ppoll(a0, a1, a2, a3), // alias
        Syscall::RecvFrom2 => socket::sys_recvfrom(a0, a1, a2, a3, a4, 0),
        Syscall::SendTo2 => socket::sys_sendto(a0, a1, a2, a3, a4, 0),
        Syscall::Socketpair => {
            // socketpair(domain, type, protocol, sv[2])
            // Implement as two unidirectional pipes.
            // sv[0] reads from pipe1, writes to pipe2
            // sv[1] reads from pipe2, writes to pipe1
            // For simplicity: just create a single pipe (covers most real use cases
            // where only one direction is used, e.g. signaling, subprocess comms).
            if a3 == 0 { return crate::errno::EFAULT; }
            if crate::uaccess::validate_user_ptr(a3, 8).is_err() { return crate::errno::EFAULT; }
            match crate::pipe::create() {
                Ok((_pid, read_fd, write_fd)) => unsafe {
                    // sv[0] = read end, sv[1] = write end (like pipe)
                    crate::uaccess::put_user(a3, read_fd as i32);
                    crate::uaccess::put_user(a3 + 4, write_fd as i32);
                    0
                },
                Err(e) => e,
            }
        },
        Syscall::Gethostname => {
            // gethostname(buf, len) — write hostname to user buffer
            if crate::uaccess::validate_user_ptr(a0, a1.min(256)).is_err() { return crate::errno::EFAULT; }
            unsafe {
                let hostname = b"rux";
                let len = hostname.len().min(a1);
                core::ptr::copy_nonoverlapping(hostname.as_ptr(), a0 as *mut u8, len);
                if len < a1 { *(a0 as *mut u8).add(len) = 0; }
            }
            0
        }

        Syscall::Rseq => crate::errno::ENOSYS,

        // ── Architecture-specific ──────────────────────────────────
        Syscall::ArchSpecific(nr) => {
            use rux_arch::ArchSpecificOps;
            crate::arch::Arch::arch_syscall(nr as usize, a0, a1)
                .unwrap_or(crate::errno::ENOSYS)
        }

        // ── Unknown ────────────────────────────────────────────────
        Syscall::Unknown(_) => crate::errno::ENOSYS,
    }
}

/// Trait for arch-specific syscall number translation.
/// Each architecture maps its Linux syscall numbers to the common Syscall enum.
#[allow(dead_code)]
pub trait SyscallTranslate {
    fn translate(nr: usize) -> Syscall;
}

// ── Generic exec ──────────────────────────────────────────────────────

/// Generic exec implementation.
///
/// # Safety
/// Replaces the current process image.
#[cfg(feature = "native")]
pub unsafe fn generic_exec<V: rux_arch::VforkContext>(_path_ptr: usize, _argv_ptr: usize) -> ! {
    panic!("exec not supported in native mode")
}

#[cfg(not(feature = "native"))]
pub unsafe fn generic_exec<V: rux_arch::VforkContext>(path_ptr: usize, argv_ptr: usize, envp_ptr: usize) -> ! {
    use rux_arch::ConsoleOps;

    let fs = crate::kstate::fs();
    let alloc = crate::kstate::alloc();

    let path = crate::uaccess::read_user_cstr(path_ptr);

    crate::uaccess::stac();
    rux_proc::execargs::set_from_user(path, argv_ptr, envp_ptr);
    crate::uaccess::clac();

    let ino = match rux_fs::path::resolve_path(fs, path) {
        Ok(ino) => ino,
        Err(_) => { crate::arch::Arch::write_str("rux: exec: not found\n"); loop {} }
    };

    // Task slot 0 is the init process. For real fork children (slot > 0),
    // we must NOT call begin_child because that would free the parent's exec frames.
    // Instead: directly switch CR3 to kernel PT, free the forked PT, skip CHILD_PAGES.
    // Fork children use free_user_address_space in waitpid for cleanup.
    let is_fork_child = crate::task_table::current_task_idx() != 0;

    if is_fork_child {
        let idx = crate::task_table::current_task_idx();
        let is_clone_vm = crate::task_table::TASK_TABLE[idx].clone_flags & crate::errno::CLONE_VM as u32 != 0;

        // Switch CR3/TTBR0 to kernel PT so it's safe to work with page tables.
        let kpt = crate::pgtrack::kernel_pt_root();
        if kpt != 0 {
            use rux_arch::PageTableRootOps;
            crate::arch::Arch::write(kpt);
        }
        let old_pt_root = crate::task_table::TASK_TABLE[idx].pt_root;
        if old_pt_root != 0 && !is_clone_vm {
            let old_pt = crate::arch::PageTable::from_root(
                rux_klib::PhysAddr::new(old_pt_root as usize)
            );
            old_pt.free_user_address_space_cow(alloc, &mut |pa| crate::cow::dec_ref(pa));
            // Set pt_root to kernel PT (not 0) so if preempted before the new
            // user PT is loaded, swap_process_state switches to a valid PT.
            crate::task_table::TASK_TABLE[crate::task_table::current_task_idx()].pt_root = kpt;
        }
        // CLONE_VFORK: wake the blocked parent now that child has exec'd
        if is_clone_vm {
            let idx = crate::task_table::current_task_idx();
            let ppid = crate::task_table::TASK_TABLE[idx].ppid;
            if let Some(pi) = crate::task_table::find_task_by_pid(ppid) {
                if crate::task_table::TASK_TABLE[pi].state == crate::task_table::TaskState::Sleeping {
                    crate::task_table::TASK_TABLE[pi].state = crate::task_table::TaskState::Ready;
                    crate::scheduler::get().wake_task(pi);
                }
            }
            // Clear CLONE_VM flag — child now has its own address space
            crate::task_table::TASK_TABLE[idx].clone_flags &= !(crate::errno::CLONE_VM as u32);
        }
    } else {
        // Init/vfork path: begin_child switches CR3 and frees previous child's frames.
        crate::pgtrack::begin_child(alloc);
    }

    // Reset signal state on exec (POSIX: caught signals revert to default)
    PROCESS.signal_hot = rux_proc::signal::SignalHot::new();
    PROCESS.signal_cold = rux_proc::signal::SignalCold::new();
    *crate::task_table::signal_cold_mut(crate::task_table::current_task_idx()) = rux_proc::signal::SignalCold::new();
    PROCESS.signal_restorer = [0; 32];

    // Note: ITIMER_REAL is preserved across exec (POSIX).
    // busybox timeout sets alarm() then exec's — the timer must survive.

    // Reset arch-specific state (e.g., aarch64 signal trampoline mapping)
    V::on_exec_reset();

    crate::elf::load_elf_from_inode(ino as u64, alloc);
}

// ── Generic signal delivery ─────────────────────────────────────────────

/// Post-syscall processing: deliver pending signals and check for reschedule.
/// Called by both x86_64 and aarch64 syscall return paths.
#[inline]
pub unsafe fn post_syscall<S: rux_arch::SignalOps>(result: i64) -> i64 {
    let ret = if (*(&raw const PROCESS)).signal_hot.has_deliverable() {
        crate::uaccess::stac();
        let r = generic_deliver_signal::<S>(result);
        crate::uaccess::clac();
        // SA_RESTART: if the signal handler had SA_RESTART set (encoded in bit 32)
        // and the original syscall returned -EINTR, return -EINTR to let the
        // arch return path restart the syscall (Linux uses -ERESTARTSYS internally).
        // For now, we return the original result so the syscall restarts transparently
        // via the userspace libc retry loop (musl handles this).
        let sa_restart = r & (1 << 32) != 0;
        if sa_restart && result == -(crate::errno::EINTR as i64).abs() {
            result // return original -EINTR; musl restarts in userspace
        } else {
            r & 0xFFFFFFFF // mask off the restart flag bit
        }
    } else {
        result
    };
    let sched = crate::scheduler::get();
    if sched.need_resched { sched.schedule(); }
    ret
}

/// Deliver a pending signal to the user-space handler.
/// Thin wrapper around `rux_proc::signal::deliver_signal` that supplies kernel state.
pub unsafe fn generic_deliver_signal<S: rux_arch::SignalOps>(syscall_result: i64) -> i64 {
    // Signal delivery uses PROCESS.signal_cold (global) rather than the
    // per-task SIGNAL_COLD_BYTES slot. Copying >512 bytes on the aarch64
    // syscall return path corrupts state. Since sigaction writes to both
    // the per-task slot and PROCESS.signal_cold, and exec resets both,
    // the global is correct for the current task during delivery.
    rux_proc::signal::deliver_signal_ex::<S>(
        &mut (*(&raw mut PROCESS)).signal_hot,
        &mut (*(&raw mut PROCESS)).signal_cold,
        &(*(&raw const PROCESS)).signal_restorer,
        syscall_result,
        |status| posix::exit(status),
        |signum| {
            // Stop the current process
            let idx = crate::task_table::current_task_idx();
            crate::task_table::TASK_TABLE[idx].state = crate::task_table::TaskState::Stopped;
            crate::task_table::TASK_TABLE[idx].exit_code = 0x7F | ((signum as i32) << 8);
            crate::task_table::notify_parent_child_exit(
                crate::task_table::TASK_TABLE[idx].ppid,
                crate::task_table::TASK_TABLE[idx].exit_code,
            );
            let sched = crate::scheduler::get();
            sched.tasks[idx].entity.state = rux_sched::TaskState::Stopped;
            sched.schedule();
        },
    )
}

/// Restore pre-signal state from the signal frame on the user stack.
/// Thin wrapper around `rux_proc::signal::sigreturn` that supplies kernel state.
pub unsafe fn generic_sigreturn<S: rux_arch::SignalOps>() -> i64 {
    rux_proc::signal::sigreturn::<S>(&mut (*(&raw mut PROCESS)).signal_hot)
}
