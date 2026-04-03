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
    /// Real group ID.
    pub gid: u32,
    /// Effective group ID.
    pub egid: u32,
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
            uid: 0, euid: 0, gid: 0, egid: 0,
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
pub unsafe fn map_user_pages(
    start_va: usize,
    end_va: usize,
    flags: rux_mm::MappingFlags,
) {
    let alloc = crate::kstate::alloc();
    let mut upt = current_user_page_table();

    let upt_ptr = &mut upt as *mut crate::arch::PageTable;
    rux_mm::map_zeroed_pages(
        alloc, start_va as u64, end_va as u64, flags,
        &mut |va, phys, f, a| { let _ = (*upt_ptr).map_4k(va, phys, f, a); },
        &mut |va| { let _ = (*upt_ptr).unmap_4k(va); },
    );
}

// ── Path resolution helper (used by both POSIX and Linux) ───────────

/// Get current time in seconds (for timestamp updates on file operations).
pub fn current_time_secs() -> u64 {
    use rux_arch::TimerOps;
    crate::arch::Arch::ticks() / 1000
}

/// Resolve a path using CWD for relative paths.
pub unsafe fn resolve_with_cwd(path: &[u8]) -> Result<rux_fs::InodeId, isize> {
    let fs = crate::kstate::fs();
    rux_fs::path::resolve_with_cwd(fs, PROCESS.fs_ctx.cwd, path)
}

/// Resolve a user path pointer to (parent_inode, basename).
pub unsafe fn resolve_parent_and_name(path_ptr: usize) -> Result<(rux_fs::InodeId, &'static [u8]), isize> {
    let path = crate::uaccess::read_user_cstr(path_ptr);
    let fs = crate::kstate::fs();
    rux_fs::path::resolve_parent_and_name(fs, PROCESS.fs_ctx.cwd, path)
}

// ── Generic syscall dispatch ───────────────────────────────────────────

/// Architecture-independent syscall identifiers.
/// Each arch maps its own syscall numbers to this enum via `translate()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syscall {
    // File I/O
    Read, Write, Open, OpenAt, Close, Lseek, Dup, Dup2, Fcntl,
    Writev, Sendfile, Ioctl, Pipe2,
    // File metadata
    Stat, Lstat, Fstat, FstatAt, Faccessat, Readlink, Readlinkat,
    // Directory / path ops
    Getcwd, Creat, Mknodat, Mkdir, Mkdirat, Unlink, Unlinkat, Chdir,
    Rename, Renameat, Symlink, Symlinkat,
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
    // Sockets
    Socket, Bind, Sendto, Recvfrom, Setsockopt, Getsockopt, Connect,
    // Stubs that return specific values
    Prlimit64, Rseq,
    // Architecture-specific (handled by ArchSpecificOps)
    ArchSpecific(usize),
    // Unknown
    Unknown(usize),
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
        Syscall::Faccessat => 0,
        Syscall::Readlink => posix::readlink(a0, a1, a2),
        Syscall::Readlinkat => posix::readlinkat(a0, a1, a2, a3),

        // ── Directory / path ops ──────────────────────────────────
        Syscall::Getcwd => posix::getcwd(a0, a1),
        Syscall::Creat => posix::creat(a0),
        Syscall::Mknodat => posix::creat(a1),      // mknodat(dirfd, path, mode, dev)
        Syscall::Mkdir => posix::mkdir(a0),
        Syscall::Mkdirat => posix::mkdir(a1),       // mkdirat(dirfd, path, mode)
        Syscall::Unlink => posix::unlink(a0),
        Syscall::Unlinkat => posix::unlink(a1),     // unlinkat(dirfd, path, flags)
        Syscall::Chdir => posix::chdir(a0),
        Syscall::Rename => posix::rename(a0, a1),
        Syscall::Renameat => posix::rename(a1, a3),  // renameat(olddirfd, old, newdirfd, new)
        Syscall::Symlink => posix::symlink(a0, a1),
        Syscall::Symlinkat => posix::symlink(a0, a2), // symlinkat(target, dirfd, linkpath)

        // ── Permissions ───────────────────────────────────────────
        Syscall::Link => posix::link(a0, a1),
        Syscall::Linkat => posix::link(a1, a3),   // linkat(olddirfd, old, newdirfd, new, flags)
        Syscall::Chmod => posix::chmod(a0, a1),         // chmod(path, mode)
        Syscall::Fchmodat => posix::chmod(a1, a2),      // fchmodat(dirfd, path, mode)
        Syscall::Fchmod => posix::fchmod(a0, a1),       // fchmod(fd, mode)
        Syscall::Chown => posix::chown(a0, a1, a2),     // chown(path, uid, gid)
        Syscall::Fchownat => posix::chown(a1, a2, a3),  // fchownat(dirfd, path, uid, gid, flags)
        Syscall::Fchown => posix::fchown(a0, a1, a2),   // fchown(fd, uid, gid)
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
        Syscall::Poll => posix::poll(a0, a1, a2),
        Syscall::Gettimeofday => {
            use rux_arch::TimerOps;
            crate::arch::Arch::ticks() as isize
        }
        Syscall::Sysinfo => linux::sysinfo(a0),
        Syscall::Statfs => linux::statfs(a0, a1),
        Syscall::Prlimit64 => posix::prlimit64(a0, a1, a2, a3),

        // ── Stubs: accepted but no-op ─────────────────────────────
        Syscall::Mprotect => posix::mprotect(a0, a1, a2),
        Syscall::Access |
        Syscall::Sigaltstack | Syscall::SchedYield | Syscall::Alarm |
        Syscall::Getgroups | Syscall::Getrlimit |
        Syscall::Futex => posix::futex(a0, a1, a2),
        Syscall::SetRobustList |
        Syscall::SchedGetaffinity | Syscall::Prctl => 0,

        // tgkill(tgid, tid, sig) / tkill(tid, sig) — route to kill()
        Syscall::Tgkill => posix::kill(a1 as isize, a2),
        Syscall::Tkill => posix::kill(a0 as isize, a1),

        // Dispatched by arch entry point, never reaches generic dispatch
        Syscall::Vfork | Syscall::Execve | Syscall::Sigreturn => 0,

        // ── Sockets ────────────────────────────────────────────────
        Syscall::Socket => socket::sys_socket(a0, a1, a2),
        Syscall::Bind => socket::sys_bind(a0, a1, a2),
        Syscall::Sendto => socket::sys_sendto(a0, a1, a2, a3, a4, 0),
        Syscall::Recvfrom => socket::sys_recvfrom(a0, a1, a2, a3, a4, 0),
        Syscall::Setsockopt | Syscall::Getsockopt => 0, // stub
        Syscall::Connect => socket::sys_connect(a0, a1, a2),

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
pub unsafe fn generic_exec<V: rux_arch::VforkContext>(path_ptr: usize, argv_ptr: usize) -> ! {
    use rux_arch::ConsoleOps;

    let fs = crate::kstate::fs();
    let alloc = crate::kstate::alloc();

    let path = crate::uaccess::read_user_cstr(path_ptr);

    crate::uaccess::stac();
    rux_proc::execargs::set_from_user(path, argv_ptr, 0);
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
        // Switch CR3 to kernel PT so it's safe to free the forked PT.
        let kpt = crate::pgtrack::kernel_pt_root();
        if kpt != 0 {
            use rux_arch::PageTableRootOps;
            crate::arch::Arch::write(kpt);
        }
        // Free the forked PT (the address space we're replacing).
        // Use the COW-aware variant: shared frames are only freed when their
        // refcount reaches zero (dec_ref returns true).
        let old_pt_root = crate::task_table::TASK_TABLE[crate::task_table::current_task_idx()].pt_root;
        if old_pt_root != 0 {
            let old_pt = crate::arch::PageTable::from_root(
                rux_klib::PhysAddr::new(old_pt_root as usize)
            );
            old_pt.free_user_address_space_cow(alloc, &mut |pa| crate::cow::dec_ref(pa));
            // Set pt_root to kernel PT (not 0) so if preempted before the new
            // user PT is loaded, swap_process_state switches to a valid PT.
            crate::task_table::TASK_TABLE[crate::task_table::current_task_idx()].pt_root = kpt;
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

    // Reset arch-specific state (e.g., aarch64 signal trampoline mapping)
    V::on_exec_reset();

    crate::elf::load_elf_from_inode(ino as u64, alloc);
}

// ── Generic signal delivery ─────────────────────────────────────────────

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
