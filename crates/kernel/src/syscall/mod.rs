/// Shared syscall implementations — architecture-independent.
///
/// Split into POSIX-standardized syscalls and Linux-specific extensions.
/// Architecture-specific entry/exit asm stays in each arch module.

pub mod posix;
pub mod linux;

// ── Shared process state ────────────────────────────────────────────

/// Program break for brk().
pub static mut PROGRAM_BRK: usize = 0;

/// Next anonymous mmap virtual address.
pub static mut MMAP_BASE: usize = 0x10000000;

/// Current working directory inode (0 = root).
pub static mut CWD_INODE: u64 = 0;

/// Current working directory path (for getcwd). Null-terminated.
pub static mut CWD_PATH: [u8; 256] = {
    let mut buf = [0u8; 256];
    buf[0] = b'/';
    buf
};
pub static mut CWD_PATH_LEN: usize = 1;

/// Child exit status for wait4.
pub static mut LAST_CHILD_EXIT: i32 = 0;

/// Whether there's a child to collect.
pub static mut CHILD_AVAILABLE: bool = false;

/// Whether we're in a vfork child context (skip pipe ref counting in close).
pub static mut IN_VFORK_CHILD: bool = false;

// ── Signal state (single-process) ──────────────────────────────────
pub static mut SIGNAL_HOT: rux_proc::signal::SignalHot = rux_proc::signal::SignalHot::new();
pub static mut SIGNAL_COLD: rux_proc::signal::SignalCold = rux_proc::signal::SignalCold::new();
/// Per-signal sa_restorer address (x86_64 only — musl sets this for sigreturn trampoline).
pub static mut SIGNAL_RESTORER: [usize; 32] = [0; 32];

// ── Page table helper (arch-dispatched) ─────────────────────────────

/// Map zeroed pages into the current user page table.
/// Used by brk() and mmap() to add pages to the user address space.
pub unsafe fn map_user_pages(
    start_va: usize,
    end_va: usize,
    flags: rux_mm::MappingFlags,
) {
    use rux_arch::PageTableRootOps;
    let alloc = crate::kstate::alloc();
    let root = crate::arch::Arch::read();
    let mut upt = crate::arch::PageTable::from_root(
        rux_klib::PhysAddr::new(root as usize));

    let upt_ptr = &mut upt as *mut crate::arch::PageTable;
    rux_mm::map_zeroed_pages(
        alloc, start_va as u64, end_va as u64, flags,
        &mut |va, phys, f, a| { let _ = (*upt_ptr).map_4k(va, phys, f, a); },
        &mut |va| { let _ = (*upt_ptr).unmap_4k(va); },
    );
}

// ── Path resolution helper (used by both POSIX and Linux) ───────────

/// Read a C string from user memory into a path slice.
pub unsafe fn read_user_path(path_ptr: usize) -> &'static [u8] {
    let cstr = path_ptr as *const u8;
    let mut len = 0usize;
    while *cstr.add(len) != 0 && len < 256 { len += 1; }
    core::slice::from_raw_parts(cstr, len)
}

/// Resolve a path using CWD for relative paths.
pub unsafe fn resolve_with_cwd(path: &[u8]) -> Result<rux_fs::InodeId, isize> {
    let fs = crate::kstate::fs();
    rux_fs::path::resolve_with_cwd(fs, CWD_INODE, path)
}

/// Resolve a path to (parent_inode, basename).
pub unsafe fn resolve_parent_and_name(path_ptr: usize) -> Result<(rux_fs::InodeId, &'static [u8]), isize> {
    let path = read_user_path(path_ptr);
    let fs = crate::kstate::fs();
    rux_fs::path::resolve_parent_and_name(fs, CWD_INODE, path)
}

/// Fill a Linux struct stat from VFS InodeStat.
/// Uses the architecture's StatLayout constants for field offsets/widths.
pub unsafe fn fill_linux_stat(buf: usize, vfs_stat: &rux_fs::InodeStat) {
    crate::arch::fill_linux_stat::<crate::arch::Arch>(buf, vfs_stat);
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
        Syscall::Utimensat => 0,

        // ── Memory ─────────────────────────────────────────────────
        Syscall::Mmap => posix::mmap(a0, a1, a2, a3, a4),
        Syscall::Munmap => posix::munmap(a0, a1),
        Syscall::Mprotect => 0,
        Syscall::Brk => linux::brk(a0),

        // ── Process ────────────────────────────────────────────────
        Syscall::Getpid => 1,
        Syscall::Getppid => 1,
        Syscall::Exit => posix::exit(a0 as i32),
        Syscall::ExitGroup => linux::exit_group(a0 as i32),
        Syscall::Kill => posix::kill(a0 as isize, a1),
        Syscall::Vfork => 0,   // dispatched by arch entry, never reaches here
        Syscall::Execve => 0,
        Syscall::Wait4 => linux::wait4(a0, a1, a2, a3),
        Syscall::Uname => posix::uname(a0),
        Syscall::ClockGettime => posix::clock_gettime(a0, a1),

        // ── Signals ────────────────────────────────────────────────
        Syscall::Sigaction => posix::sigaction(a0, a1, a2),
        Syscall::Sigprocmask => posix::sigprocmask(a0, a1, a2, a3),
        Syscall::Sigaltstack => 0, // accept and ignore
        Syscall::Sigreturn => 0,   // handled by arch entry, never reaches here

        // ── Terminal / scheduling ──────────────────────────────────
        Syscall::SchedYield | Syscall::Alarm => 0,
        Syscall::Nanosleep => posix::nanosleep(a0),

        // ── User/group IDs ─────────────────────────────────────────
        Syscall::Getuid | Syscall::Geteuid |
        Syscall::Getgid | Syscall::Getegid => 0,
        Syscall::Getgroups => 0, // no supplementary groups

        // ── Process groups ─────────────────────────────────────────
        Syscall::Setpgid => 0,
        Syscall::Getpgid => 1,
        Syscall::Setsid => 1,

        // ── Linux extensions ───────────────────────────────────────
        Syscall::Getdents64 => linux::getdents64(a0, a1, a2),
        Syscall::SetTidAddress => linux::set_tid_address(a0),
        Syscall::Gettid => 1,
        Syscall::SetRobustList | Syscall::Futex |
        Syscall::Tgkill | Syscall::Tkill |
        Syscall::SchedGetaffinity | Syscall::Prctl => 0,
        Syscall::Getrlimit => 0,
        Syscall::Poll => posix::poll(a0, a1, a2),
        Syscall::Gettimeofday => {
            use rux_arch::TimerOps;
            crate::arch::Arch::ticks() as isize
        }
        Syscall::Access => 0,
        Syscall::Sysinfo => linux::sysinfo(a0),
        Syscall::Statfs => linux::statfs(a0, a1),
        Syscall::Prlimit64 => posix::prlimit64(a0, a1, a2, a3),
        Syscall::Rseq => -38,

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
static mut VFORK_PARENT_MMAP_BASE: usize = 0;
static mut VFORK_PARENT_PROGRAM_BRK: usize = 0;
static mut VFORK_PARENT_CWD_INODE: u64 = 0; // inode IDs are genuinely u64
static mut VFORK_PARENT_CWD_PATH: [u8; 256] = [0u8; 256];
static mut VFORK_PARENT_CWD_PATH_LEN: usize = 1;
static mut VFORK_PARENT_USER_SP: usize = 0;
static mut VFORK_PARENT_TLS: u64 = 0;       // register-width, set by arch VforkContext
static mut VFORK_PARENT_PT_ROOT: u64 = 0;   // register-width, set by arch VforkContext
static mut VFORK_PARENT_FDS: [rux_fs::fdtable::OpenFile; 64] = [rux_fs::fdtable::OpenFile {
    ino: 0, offset: 0, flags: 0, active: false, is_console: false,
    is_pipe: false, pipe_id: 0, pipe_write: false,
}; 64];

/// Maximum number of user data pages to snapshot around vfork.
const VFORK_SNAP_MAX: usize = 1024;

/// Virtual addresses of snapshotted pages (4KB aligned).
static mut VFORK_SNAP_VA: [usize; VFORK_SNAP_MAX] = [0; VFORK_SNAP_MAX];
/// Physical addresses of the original frames.
static mut VFORK_SNAP_ORIG_PHYS: [usize; VFORK_SNAP_MAX] = [0; VFORK_SNAP_MAX];
/// Physical addresses of snapshot copies (freed after parent restore).
static mut VFORK_SNAP_COPY_PHYS: [usize; VFORK_SNAP_MAX] = [0; VFORK_SNAP_MAX];
/// Number of valid entries in the snapshot arrays.
static mut VFORK_SNAP_COUNT: usize = 0;

/// Generic vfork implementation. The arch provides hardware primitives
/// via the `VforkContext` trait; this function handles the algorithm.
///
/// # Safety
/// Manipulates process state, page tables, and performs setjmp/longjmp.
#[inline(never)]
pub unsafe fn generic_vfork<V: rux_arch::VforkContext>() -> isize {
    use rux_arch::ConsoleOps;
    crate::arch::Arch::write_str("rux: vfork()\n");

    // 1. Save arch-specific register state
    V::save_regs();
    VFORK_PARENT_USER_SP = V::save_user_sp();
    VFORK_PARENT_TLS = V::save_tls();

    // 2. Save process state that exec resets
    VFORK_PARENT_MMAP_BASE = MMAP_BASE;
    VFORK_PARENT_PROGRAM_BRK = PROGRAM_BRK;
    VFORK_PARENT_CWD_INODE = CWD_INODE;
    for i in 0..CWD_PATH_LEN { VFORK_PARENT_CWD_PATH[i] = CWD_PATH[i]; }
    VFORK_PARENT_CWD_PATH_LEN = CWD_PATH_LEN;
    for i in 0..64 { VFORK_PARENT_FDS[i] = rux_fs::fdtable::FD_TABLE[i]; }
    CHILD_AVAILABLE = true;

    // 3. setjmp — returns 0 on first call, child PID on longjmp
    let val = V::setjmp();
    if val == 0 {
        // ── Child path ─────────────────────────────────────────────
        IN_VFORK_CHILD = true;

        // Copy parent stack pages to child VA to prevent corruption
        use rux_mm::FrameAllocator;
        let alloc = crate::kstate::alloc();
        let parent_sp = VFORK_PARENT_USER_SP;
        let parent_page_base = parent_sp & !0xFFF;
        let child_stack_pages = 4usize;
        let child_va_base = V::CHILD_STACK_VA;

        let pt_root = V::read_pt_root();
        let mut upt = crate::arch::PageTable::from_root(
            rux_klib::PhysAddr::new(pt_root as usize));
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

        // Snapshot parent's user data/BSS pages and mmap'd heap/TLS pages
        // so that forkchild() modifications can be undone when the parent
        // resumes.  We scan two ranges:
        //   1. 0x1000..PROGRAM_BRK  — ELF data/BSS
        //   2. 0x10000000..MMAP_BASE — musl heap and TLS (mmap'd anonymous pages)
        // Only writable pages with PA >= allocator base are snapshotted (skips
        // read-only .text and kernel identity-mapped pages).
        VFORK_SNAP_COUNT = 0;
        let alloc_base = crate::kstate::alloc().base.as_usize();

        // Helper closure: snapshot one page.
        macro_rules! snap_page {
            ($snap_va:expr) => {{
                if let Ok(orig_pa) = upt.translate_writable(
                    rux_klib::VirtAddr::new($snap_va)) {
                    let orig_page = orig_pa.as_usize() & !0xFFF;
                    if orig_page >= alloc_base && VFORK_SNAP_COUNT < VFORK_SNAP_MAX {
                        if let Ok(snap_pa) = alloc.alloc(rux_mm::PageSize::FourK) {
                            let op = orig_page as *const u8;
                            let sp = snap_pa.as_usize() as *mut u8;
                            core::ptr::copy_nonoverlapping(op, sp, 4096);
                            VFORK_SNAP_VA[VFORK_SNAP_COUNT] = $snap_va;
                            VFORK_SNAP_ORIG_PHYS[VFORK_SNAP_COUNT] = orig_page;
                            VFORK_SNAP_COPY_PHYS[VFORK_SNAP_COUNT] = snap_pa.as_usize();
                            VFORK_SNAP_COUNT += 1;
                        }
                    }
                }
            }};
        }

        // Range 1: ELF data / BSS
        let mut va = 0x1000usize;
        while va < VFORK_PARENT_PROGRAM_BRK {
            snap_page!(va);
            va += 4096;
        }

        // Range 2: mmap'd heap / TLS (musl allocates these with mmap)
        va = 0x10000000usize;
        while va < VFORK_PARENT_MMAP_BASE {
            snap_page!(va);
            va += 4096;
        }

        // Range 3: user stack area (contains stack canary, local vars)
        // The parent's stack frame holds the GCC stack-protector canary
        // at sp+offset; without snapshotting these pages the canary can
        // appear corrupted after child exec replaces the address space.
        let stack_page = parent_sp & !0xFFF;
        va = stack_page.saturating_sub(child_stack_pages * 4096);
        while va <= stack_page {
            snap_page!(va);
            va += 4096;
        }

        return 0; // child gets fork return 0
    } else {
        // ── Parent resume ──────────────────────────────────────────

        // Restore page table root (exec replaced it)
        if VFORK_PARENT_PT_ROOT != 0 {
            V::write_pt_root(VFORK_PARENT_PT_ROOT);
        }

        crate::arch::Arch::write_str("rux: vfork parent resumed\n");
        V::clear_jmp();
        IN_VFORK_CHILD = false;

        // Restore parent's data pages: undo any writes forkchild() made
        // (e.g. g_parsefile state zeroed by closescript()).
        use rux_mm::FrameAllocator;
        let restore_alloc = crate::kstate::alloc();
        for i in 0..VFORK_SNAP_COUNT {
            let orig_phys = VFORK_SNAP_ORIG_PHYS[i];
            let snap_phys = VFORK_SNAP_COPY_PHYS[i];
            let orig = orig_phys as *mut u8;
            let snap = snap_phys as *const u8;
            core::ptr::copy_nonoverlapping(snap, orig, 4096);
            restore_alloc.dealloc(
                rux_klib::PhysAddr::new(snap_phys),
                rux_mm::PageSize::FourK,
            );
        }
        VFORK_SNAP_COUNT = 0;

        // Restore process state
        MMAP_BASE = VFORK_PARENT_MMAP_BASE;
        PROGRAM_BRK = VFORK_PARENT_PROGRAM_BRK;
        CWD_INODE = VFORK_PARENT_CWD_INODE;
        for i in 0..VFORK_PARENT_CWD_PATH_LEN { CWD_PATH[i] = VFORK_PARENT_CWD_PATH[i]; }
        CWD_PATH[VFORK_PARENT_CWD_PATH_LEN] = 0;
        CWD_PATH_LEN = VFORK_PARENT_CWD_PATH_LEN;
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
pub unsafe fn generic_exec<V: rux_arch::VforkContext>(path_ptr: usize, argv_ptr: usize) -> ! {
    use rux_arch::ConsoleOps;
    use rux_fs::FileSystem;

    let fs = crate::kstate::fs();
    let alloc = crate::kstate::alloc();

    let path_cstr = path_ptr as *const u8;
    let mut path_len = 0usize;
    while *path_cstr.add(path_len) != 0 && path_len < 256 { path_len += 1; }
    let path = core::slice::from_raw_parts(path_cstr, path_len);

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
    SIGNAL_HOT = rux_proc::signal::SignalHot::new();
    SIGNAL_COLD = rux_proc::signal::SignalCold::new();
    SIGNAL_RESTORER = [0; 32];

    // Reset arch-specific signal trampoline state
    #[cfg(target_arch = "aarch64")]
    crate::arch::aarch64::syscall::reset_trampoline();

    crate::arch::Arch::write_str("rux: entering user mode...\n");
    crate::elf::load_elf_from_inode(ino as u64, alloc);
}
