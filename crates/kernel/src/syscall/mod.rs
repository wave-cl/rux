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
    Stat, Fstat, FstatAt, Faccessat, Readlink,
    // Directory / path ops
    Getcwd, Creat, Mkdir, Unlink, Chdir, Rename, Symlink,
    // Permissions (stubs)
    Chmod, Chown, Utimensat,
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
    Getuid, Geteuid, Getgid, Getegid,
    // Process groups / sessions
    Setpgid, Getpgid, Setsid,
    // Linux extensions
    Getdents64, SetTidAddress, Gettid,
    SetRobustList, Futex, Tgkill, Tkill,
    SchedGetaffinity, Getrlimit,
    Poll, Gettimeofday,
    Prctl, Alarm, Access, Link,
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
        Syscall::Fstat => posix::fstat(a0, a1),
        Syscall::FstatAt => posix::fstatat(a0, a1, a2),
        Syscall::Faccessat => 0,
        Syscall::Readlink => posix::readlink(a0, a1, a2),

        // ── Directory / path ops ──────────────────────────────────
        Syscall::Getcwd => posix::getcwd(a0, a1),
        Syscall::Creat => posix::creat(a0),
        Syscall::Mkdir => posix::mkdir(a0),
        Syscall::Unlink => posix::unlink(a0),
        Syscall::Chdir => posix::chdir(a0),
        Syscall::Rename => posix::rename(a0, a1),
        Syscall::Symlink => posix::symlink(a0, a1),

        // ── Permissions (stubs) ───────────────────────────────────
        Syscall::Chmod | Syscall::Chown | Syscall::Utimensat | Syscall::Link => 0,

        // ── Memory ─────────────────────────────────────────────────
        Syscall::Mmap => posix::mmap(a0, a1, a2, a3, a4),
        Syscall::Munmap => 0,
        Syscall::Mprotect => 0,
        Syscall::Brk => linux::brk(a0),

        // ── Process ────────────────────────────────────────────────
        Syscall::Getpid => 1,
        Syscall::Getppid => 1,
        Syscall::Exit => posix::exit(a0 as i32),
        Syscall::ExitGroup => linux::exit_group(a0 as i32),
        Syscall::Kill => 0,
        Syscall::Vfork => 0,   // dispatched by arch entry, never reaches here
        Syscall::Execve => 0,
        Syscall::Wait4 => linux::wait4(a0, a1, a2, a3),
        Syscall::Uname => posix::uname(a0),
        Syscall::ClockGettime => posix::clock_gettime(a0, a1),

        // ── Signals ────────────────────────────────────────────────
        Syscall::Sigaction => posix::sigaction(a0, a1, a2),
        Syscall::Sigprocmask => posix::sigprocmask(a0, a1, a2, a3),
        Syscall::Sigaltstack => 0, // accept and ignore

        // ── Terminal / scheduling ──────────────────────────────────
        Syscall::SchedYield | Syscall::Alarm => 0,
        Syscall::Nanosleep => posix::nanosleep(a0),

        // ── User/group IDs ─────────────────────────────────────────
        Syscall::Getuid | Syscall::Geteuid |
        Syscall::Getgid | Syscall::Getegid => 0,

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
        Syscall::Poll => 1,
        Syscall::Gettimeofday => {
            use rux_arch::TimerOps;
            crate::arch::Arch::ticks() as isize
        }
        Syscall::Access => 0,
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
static mut VFORK_PARENT_USER_SP: usize = 0;
static mut VFORK_PARENT_TLS: u64 = 0;       // register-width, set by arch VforkContext
static mut VFORK_PARENT_PT_ROOT: u64 = 0;   // register-width, set by arch VforkContext
static mut VFORK_PARENT_FDS: [rux_fs::fdtable::OpenFile; 64] = [rux_fs::fdtable::OpenFile {
    ino: 0, offset: 0, flags: 0, active: false, is_console: false,
    is_pipe: false, pipe_id: 0, pipe_write: false,
}; 64];

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

        // Restore process state
        MMAP_BASE = VFORK_PARENT_MMAP_BASE;
        PROGRAM_BRK = VFORK_PARENT_PROGRAM_BRK;
        CWD_INODE = VFORK_PARENT_CWD_INODE;
        for i in 0..64 { rux_fs::fdtable::FD_TABLE[i] = VFORK_PARENT_FDS[i]; }

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

    crate::arch::Arch::write_str("rux: entering user mode...\n");
    crate::elf::load_elf_from_inode(ino as u64, alloc);
}
