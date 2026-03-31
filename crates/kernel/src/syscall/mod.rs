/// Shared syscall implementations — architecture-independent.
///
/// Split into POSIX-standardized syscalls and Linux-specific extensions.
/// Architecture-specific entry/exit asm stays in each arch module.

pub mod posix;
pub mod linux;
mod file;
mod fs_ops;
mod process;
mod signal;
mod memory;

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
    pub in_vfork_child: bool,
    /// Signal pending/blocked bitmasks (hot path — checked every syscall return).
    pub signal_hot: rux_proc::signal::SignalHot,
    /// Signal handler table and RT queue (cold path).
    pub signal_cold: rux_proc::signal::SignalCold,
    /// Per-signal sa_restorer address (x86_64 only — musl sets this for sigreturn trampoline).
    pub signal_restorer: [usize; 32],
}

impl ProcessState {
    pub const fn new() -> Self {
        Self {
            program_brk: 0,
            mmap_base: 0x10000000,
            fs_ctx: rux_proc::fs::FsContext::new(),
            last_child_exit: 0,
            child_available: false,
            in_vfork_child: false,
            signal_hot: rux_proc::signal::SignalHot::new(),
            signal_cold: rux_proc::signal::SignalCold::new(),
            signal_restorer: [0; 32],
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
    Mmap, Munmap, Mprotect, Brk,
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
pub fn dispatch(sc: Syscall, a0: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> isize {
    match sc {
        // ── POSIX.1 File I/O ───────────────────────────────────────
        Syscall::Read => posix::read(a0, a1, a2),
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
        Syscall::Mmap => posix::mmap(a0, a1, a2, a3, a4),
        Syscall::Munmap => posix::munmap(a0, a1),
        Syscall::Brk => linux::brk(a0),

        // ── Process ────────────────────────────────────────────────
        Syscall::Getpid | Syscall::Getppid => 1, // TODO: use task_table after debugging
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
        Syscall::Getuid | Syscall::Geteuid |
        Syscall::Getgid | Syscall::Getegid => 0, // uid=0, gid=0
        Syscall::Getpgid | Syscall::Setsid |
        Syscall::Gettid => 1, // single-process: always 1

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
        Syscall::Mprotect | Syscall::Faccessat | Syscall::Access |
        Syscall::Sigaltstack | Syscall::SchedYield | Syscall::Alarm |
        Syscall::Getgroups | Syscall::Setpgid | Syscall::Getrlimit |
        Syscall::SetRobustList | Syscall::Futex |
        Syscall::Tgkill | Syscall::Tkill |
        Syscall::SchedGetaffinity | Syscall::Prctl => 0,

        // Dispatched by arch entry point, never reaches generic dispatch
        Syscall::Vfork | Syscall::Execve | Syscall::Sigreturn => 0,

        Syscall::Rseq => -38, // -ENOSYS

        // ── Architecture-specific ──────────────────────────────────
        Syscall::ArchSpecific(nr) => {
            use rux_arch::ArchSpecificOps;
            crate::arch::Arch::arch_syscall(nr as usize, a0, a1)
                .unwrap_or(-38)
        }

        // ── Unknown ────────────────────────────────────────────────
        Syscall::Unknown(nr) => {
            use rux_arch::ConsoleOps;
            crate::arch::Arch::write_str("rux: unknown syscall ");
            let mut buf = [0u8; 10];
            crate::arch::Arch::write_str(rux_klib::fmt::u32_to_str(&mut buf, nr as u32));
            crate::arch::Arch::write_str("\n");
            -38
        }
    }
}

/// Trait for arch-specific syscall number translation.
/// Each architecture maps its Linux syscall numbers to the common Syscall enum.
pub trait SyscallTranslate {
    fn translate(nr: usize) -> Syscall;
}

// ── Generic vfork/exec ─────────────────────────────────────────────────

/// Saved parent process state for vfork (architecture-independent).
static mut VFORK_SAVED: ProcessState = ProcessState::new();
static mut VFORK_PARENT_USER_SP: usize = 0;
static mut VFORK_PARENT_TLS: u64 = 0;       // register-width, set by arch VforkContext
static mut VFORK_PARENT_PT_ROOT: u64 = 0;   // register-width, set by arch VforkContext
static mut VFORK_PARENT_FDS: [rux_fs::fdtable::OpenFile; 64] = [rux_fs::fdtable::OpenFile {
    ino: 0, offset: 0, flags: 0, active: false, is_console: false,
    is_pipe: false, pipe_id: 0, pipe_write: false,
}; 64];

/// Page snapshot state for vfork (save/restore writable user pages).
static mut VFORK_SNAPSHOT: rux_mm::snapshot::PageSnapshot = rux_mm::snapshot::PageSnapshot::new();

/// Generic vfork implementation. The arch provides hardware primitives
/// via the `VforkContext` trait; this function handles the algorithm.
///
/// # Safety
/// Manipulates process state, page tables, and performs setjmp/longjmp.
#[cfg(feature = "native")]
pub unsafe fn generic_vfork<V: rux_arch::VforkContext>() -> isize {
    panic!("vfork not supported in native mode")
}

#[cfg(not(feature = "native"))]
#[inline(never)]
pub unsafe fn generic_vfork<V: rux_arch::VforkContext>() -> isize {
    use rux_arch::ConsoleOps;
    crate::arch::Arch::write_str("rux: vfork()\n");

    // 1. Save arch-specific register state
    V::save_regs();
    VFORK_PARENT_USER_SP = V::save_user_sp();
    VFORK_PARENT_TLS = V::save_tls();

    // 2. Save process state that exec resets
    core::ptr::copy_nonoverlapping(&PROCESS, &mut VFORK_SAVED, 1);
    for i in 0..64 { VFORK_PARENT_FDS[i] = rux_fs::fdtable::FD_TABLE[i]; }
    PROCESS.child_available = true;

    // 3. setjmp — returns 0 on first call, child PID on longjmp
    let val = V::setjmp();
    if val == 0 {
        // ── Child path ─────────────────────────────────────────────
        PROCESS.in_vfork_child = true;

        // Copy parent stack pages to child VA to prevent corruption
        use rux_mm::FrameAllocator;
        let alloc = crate::kstate::alloc();
        let parent_sp = VFORK_PARENT_USER_SP;
        let parent_page_base = parent_sp & !0xFFF;
        let child_stack_pages = 4usize;
        let child_va_base = V::CHILD_STACK_VA;

        let mut upt = current_user_page_table();
        let flags = rux_mm::MappingFlags::READ
            .or(rux_mm::MappingFlags::WRITE)
            .or(rux_mm::MappingFlags::USER);

        for p in 0..child_stack_pages {
            let src_va = parent_page_base - (child_stack_pages - 1 - p) * 4096;
            let dst_va = child_va_base + p * 4096;
            let frame = alloc.alloc(rux_mm::PageSize::FourK).expect("child stack");
            let src = src_va as *const u8;
            let dst = frame.as_usize() as *mut u8;
            for j in 0..4096 { *dst.add(j) = *src.add(j); }
            let _ = upt.unmap_4k(rux_klib::VirtAddr::new(dst_va as usize));
            let _ = upt.map_4k(rux_klib::VirtAddr::new(dst_va as usize), frame, flags, alloc);
        }

        // Adjust SP to child stack
        let offset_in_page = parent_sp - parent_page_base;
        let child_top_va = child_va_base + (child_stack_pages - 1) * 4096;
        V::set_user_sp(child_top_va + offset_in_page);

        // Snapshot parent's writable user pages so forkchild() modifications
        // can be undone when the parent resumes.
        let stack_page = parent_sp & !0xFFF;
        VFORK_SNAPSHOT.snapshot_ranges(
            &mut upt, alloc,
            VFORK_SAVED.program_brk, VFORK_SAVED.mmap_base,
            stack_page, child_stack_pages,
        );

        return 0; // child gets fork return 0
    } else {
        // ── Parent resume ──────────────────────────────────────────

        // Restore page table root (exec replaced it)
        if VFORK_PARENT_PT_ROOT != 0 {
            V::write_pt_root(VFORK_PARENT_PT_ROOT);
        }

        crate::arch::Arch::write_str("rux: vfork parent resumed\n");
        V::clear_jmp();
        PROCESS.in_vfork_child = false;

        // Restore parent's snapshotted pages and free snapshot copies.
        VFORK_SNAPSHOT.restore_and_free(crate::kstate::alloc());

        // Restore process state
        core::ptr::copy_nonoverlapping(&VFORK_SAVED, &mut PROCESS, 1);
        for i in 0..64 { rux_fs::fdtable::FD_TABLE[i] = VFORK_PARENT_FDS[i]; }

        // Fix fd 0-2: in real Linux, fork() gives each process its own fd
        // table, so shell redirects (dup2(file, 0)) before fork only affect
        // the child.  In our single-process vfork model the redirect is
        // captured in VFORK_PARENT_FDS.  After restore, fd 0-2 may still
        // point to a file instead of the console.  Reset any non-pipe
        // file-backed fd 0-2 to console so the parent shell works correctly.
        // Pipe redirects are left alone — the shell manages pipe lifecycle.
        for i in 0..3 {
            let f = &rux_fs::fdtable::FD_TABLE[i];
            if f.active && !f.is_console && !f.is_pipe {
                rux_fs::fdtable::FD_TABLE[i] = rux_fs::fdtable::OpenFile {
                    ino: 0, offset: 0, flags: 0, active: true, is_console: true,
                    is_pipe: false, pipe_id: 0, pipe_write: false,
                };
            }
        }

        // Restore TLS
        V::restore_tls(VFORK_PARENT_TLS);

        // Restore registers and return to user mode
        V::restore_and_return_to_user(val, VFORK_PARENT_USER_SP);
    }
}

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
    use rux_fs::FileSystem;

    let fs = crate::kstate::fs();
    let alloc = crate::kstate::alloc();

    let path = crate::uaccess::read_user_cstr(path_ptr);

    rux_proc::execargs::set_from_user(path, argv_ptr, 0);

    crate::arch::Arch::write_str("rux: exec(\"");
    crate::arch::Arch::write_bytes(path);
    crate::arch::Arch::write_str("\")\n");

    let ino = match rux_fs::path::resolve_path(fs, path) {
        Ok(ino) => ino,
        Err(_) => { crate::arch::Arch::write_str("rux: exec: not found\n"); loop {} }
    };

    // Save page table root so parent can restore on vfork resume.
    // The exec will create a new page table, replacing the current one.
    VFORK_PARENT_PT_ROOT = V::read_pt_root();

    crate::pgtrack::begin_child(alloc);

    // Reset signal state on exec (POSIX: caught signals revert to default)
    PROCESS.signal_hot = rux_proc::signal::SignalHot::new();
    PROCESS.signal_cold = rux_proc::signal::SignalCold::new();
    PROCESS.signal_restorer = [0; 32];

    // Reset arch-specific signal trampoline state
    #[cfg(all(target_arch = "aarch64", not(feature = "native")))]
    crate::arch::aarch64::syscall::reset_trampoline();

    crate::arch::Arch::write_str("rux: entering user mode...\n");
    crate::elf::load_elf_from_inode(ino as u64, alloc);
}

// ── Generic signal delivery ─────────────────────────────────────────────

/// Deliver a pending signal to the user-space handler.
/// Thin wrapper around `rux_proc::signal::deliver_signal` that supplies kernel state.
pub unsafe fn generic_deliver_signal<S: rux_arch::SignalOps>(syscall_result: i64) -> i64 {
    rux_proc::signal::deliver_signal::<S>(
        &mut PROCESS.signal_hot,
        &mut PROCESS.signal_cold,
        &PROCESS.signal_restorer,
        syscall_result,
        |status| { posix::exit(status); loop {} },
    )
}

/// Restore pre-signal state from the signal frame on the user stack.
/// Thin wrapper around `rux_proc::signal::sigreturn` that supplies kernel state.
pub unsafe fn generic_sigreturn<S: rux_arch::SignalOps>() -> i64 {
    rux_proc::signal::sigreturn::<S>(&mut PROCESS.signal_hot)
}
