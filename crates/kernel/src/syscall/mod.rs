/// Shared syscall implementations — architecture-independent.
///
/// Split into POSIX-standardized syscalls and Linux-specific extensions.
/// Architecture-specific entry/exit asm stays in each arch module.

pub mod posix;
pub mod linux;

// ── Shared process state ────────────────────────────────────────────

/// Program break for brk().
pub static mut PROGRAM_BRK: u64 = 0;

/// Next anonymous mmap virtual address.
pub static mut MMAP_BASE: u64 = 0x10000000;

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
    start_va: u64,
    end_va: u64,
    flags: rux_mm::MappingFlags,
) {
    use rux_arch::PageTableRootOps;
    let alloc = crate::kstate::alloc();
    let root = crate::arch::Arch::read();
    let mut upt = crate::arch::PageTable::from_root(
        rux_klib::PhysAddr::new(root as usize));

    let upt_ptr = &mut upt as *mut crate::arch::PageTable;
    rux_mm::map_zeroed_pages(
        alloc, start_va, end_va, flags,
        &mut |va, phys, f, a| { let _ = (*upt_ptr).map_4k(va, phys, f, a); },
        &mut |va| { let _ = (*upt_ptr).unmap_4k(va); },
    );
}

// ── Path resolution helper (used by both POSIX and Linux) ───────────

/// Read a C string from user memory into a path slice.
pub unsafe fn read_user_path(path_ptr: u64) -> &'static [u8] {
    let cstr = path_ptr as *const u8;
    let mut len = 0usize;
    while *cstr.add(len) != 0 && len < 256 { len += 1; }
    core::slice::from_raw_parts(cstr, len)
}

/// Resolve a path using CWD for relative paths.
pub unsafe fn resolve_with_cwd(path: &[u8]) -> Result<rux_vfs::InodeId, i64> {
    let fs = crate::kstate::fs();
    rux_vfs::path::resolve_with_cwd(fs, CWD_INODE, path)
}

/// Resolve a path to (parent_inode, basename).
pub unsafe fn resolve_parent_and_name(path_ptr: u64) -> Result<(rux_vfs::InodeId, &'static [u8]), i64> {
    let path = read_user_path(path_ptr);
    let fs = crate::kstate::fs();
    rux_vfs::path::resolve_parent_and_name(fs, CWD_INODE, path)
}

/// Fill a Linux struct stat from VFS InodeStat.
/// Uses the architecture's StatLayout constants for field offsets/widths.
pub unsafe fn fill_linux_stat(buf: u64, vfs_stat: &rux_vfs::InodeStat) {
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
    Stat, Fstat, FstatAt, Faccessat,
    // Directory ops
    Getcwd, Creat, Mkdir, Unlink, Chdir,
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
    Prctl, Alarm, Access,
    // Stubs that return specific values
    Prlimit64, Rseq,
    // Architecture-specific (handled by ArchSpecificOps)
    ArchSpecific(u64),
    // Unknown
    Unknown(u64),
}

/// Dispatch a syscall by its architecture-independent identifier.
/// Called from the arch-specific entry point after translating the number.
pub fn dispatch(sc: Syscall, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> i64 {
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

        // ── Directory ops ──────────────────────────────────────────
        Syscall::Getcwd => posix::getcwd(a0, a1),
        Syscall::Creat => posix::creat(a0),
        Syscall::Mkdir => posix::mkdir(a0),
        Syscall::Unlink => posix::unlink(a0),
        Syscall::Chdir => posix::chdir(a0),

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
        // Vfork/Execve are dispatched by the arch entry — they never reach here
        Syscall::Vfork => 0,   // unreachable in practice
        Syscall::Execve => 0,  // unreachable in practice
        Syscall::Wait4 => linux::wait4(a0, a1, a2, a3),
        Syscall::Uname => posix::uname(a0),
        Syscall::ClockGettime => posix::clock_gettime(a0, a1),

        // ── Signals ────────────────────────────────────────────────
        Syscall::Sigaction => posix::sigaction(a0, a1, a2),
        Syscall::Sigprocmask => posix::sigprocmask(a0, a1, a2, a3),
        Syscall::Sigaltstack => -38,

        // ── Terminal / scheduling ──────────────────────────────────
        Syscall::SchedYield | Syscall::Nanosleep | Syscall::Alarm => 0,

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
            crate::arch::Arch::ticks() as i64
        }
        Syscall::Access => 0,
        Syscall::Prlimit64 | Syscall::Rseq => -38,

        // ── Architecture-specific ──────────────────────────────────
        Syscall::ArchSpecific(nr) => {
            use rux_arch::ArchSpecificOps;
            crate::arch::Arch::arch_syscall(nr, a0, a1).unwrap_or(-38)
        }

        // ── Unknown ────────────────────────────────────────────────
        Syscall::Unknown(nr) => {
            use rux_arch::SerialOps;
            crate::arch::Arch::write_str("rux: unknown syscall ");
            let mut buf = [0u8; 10];
            crate::arch::Arch::write_str(crate::write_u32(&mut buf, nr as u32));
            crate::arch::Arch::write_str("\n");
            -38
        }
    }
}

/// Trait for arch-specific syscall number translation.
/// Each architecture maps its Linux syscall numbers to the common Syscall enum.
pub trait SyscallTranslate {
    fn translate(nr: u64) -> Syscall;
}
