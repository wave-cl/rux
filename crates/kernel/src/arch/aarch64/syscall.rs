/// SVC syscall handler for aarch64.
/// User code does `svc #0` which traps to EL1.
/// Uses aarch64 Linux syscall numbers.


/// Exception frame layout from exception.S save_context:
///   regs[0..30] = x0..x29  (each 8 bytes)
///   regs[30] = x30 (lr)
///   regs[31] = elr_el1 (user return address)
///   regs[32] = spsr_el1
/// Total: 34 u64s (272 bytes)
const FRAME_REGS: usize = 34;

/// Sigreturn trampoline virtual address (user-accessible page).
/// Must not conflict with user stack (0x7FFE0000..0x80000000) or code (near 0x400000).
const SIGRETURN_TRAMPOLINE_VA: usize = 0x7FFD_F000;

/// Whether the trampoline page has been mapped in the current page table.
static mut TRAMPOLINE_MAPPED: bool = false;
/// 6th syscall argument (x5) — saved for mmap offset.
pub static mut SAVED_SYSCALL_A5: u64 = 0;

/// Reset trampoline state on exec (new page table invalidates old mapping).
pub fn reset_trampoline() { unsafe { TRAMPOLINE_MAPPED = false; } }

/// Handle SVC from user mode. Called from exception_dispatch.
pub fn handle_syscall(frame: *mut u8) {
    unsafe {
        let regs = frame as *mut u64;
        CURRENT_REGS_PTR = regs; // Set for SignalOps + VforkContext

        // aarch64 syscall convention: x8 = number, x0-x5 = args
        let nr = *regs.add(8);   // x8
        let a0 = *regs.add(0);   // x0
        let a1 = *regs.add(1);   // x1
        let a2 = *regs.add(2);   // x2
        let a3 = *regs.add(3);   // x3
        let a4 = *regs.add(4);   // x4
        let a5 = *regs.add(5);   // x5 (6th arg, used by mmap for offset)
        SAVED_SYSCALL_A5 = a5;

        // Process creation + sigreturn (handled before generic dispatch)
        let result: i64 = match nr {
            // nr=220 is clone(flags, stack, ptid, tls, ctid)
            220 => {
                let flags = a0 as usize;
                if flags & crate::errno::CLONE_VM != 0
                    && flags & crate::errno::CLONE_VFORK == 0
                {
                    // Thread: shared address space (CLONE_VM without CLONE_VFORK)
                    crate::fork::sys_clone(flags, a1 as usize, a4 as usize) as i64
                } else {
                    // Fork or vfork: COW (vfork uses COW to avoid shared-state corruption)
                    crate::fork::sys_fork() as i64
                }
            }
            221 => { crate::syscall::generic_exec::<super::Aarch64>(a0 as usize, a1 as usize, a2 as usize) }
            139 => {
                // rt_sigreturn — restore pre-signal state (reads signal frame from user stack)
                crate::uaccess::stac();
                let _ = crate::syscall::generic_sigreturn::<super::Aarch64>();
                crate::uaccess::clac();
                return; // exception frame already has restored x0, skip writing it
            }
            _ => {
                let sc = translate_aarch64(nr as usize);
                crate::syscall::dispatch(sc, a0 as usize, a1 as usize, a2 as usize, a3 as usize, a4 as usize) as i64
            }
        };


        // Re-sync CURRENT_REGS_PTR: after any syscall that blocked (schedule()),
        // other tasks may have overwritten this global with their own frame pointer.
        // Signal delivery in post_syscall uses CURRENT_REGS_PTR to modify ELR/x30,
        // so it must point to THIS task's exception frame.
        CURRENT_REGS_PTR = regs;


        // Return value in x0 + signal delivery + reschedule check
        *regs.add(0) = crate::syscall::post_syscall::<super::Aarch64>(result) as u64;
    }
}

/// Signal frame layout on user stack (aarch64).
///
/// Must save ALL general-purpose registers (x0-x30) because the signal handler
/// may clobber any caller-saved register (x0-x18, x30). After sigreturn, the
/// interrupted code expects all registers to be exactly as they were before the
/// signal was delivered. Without this, registers like x1 get clobbered by the
/// handler and the interrupted code sees garbage values.
#[repr(C)]
struct SignalFrameAarch64 {
    saved_regs: [u64; 31],  // x0-x30 (full GPR state)
    saved_elr: u64,         // original ELR_EL1 (user return PC)
    saved_spsr: u64,        // original SPSR_EL1
    saved_mask: u64,        // blocked signal mask before handler
    orig_user_sp: u64,      // original sp_el0 for exact restoration
}

/// Map the sigreturn trampoline page if not already mapped.
unsafe fn ensure_trampoline() {
    if TRAMPOLINE_MAPPED { return; }
    use rux_arch::PageTableRootOps;
    let alloc = crate::kstate::alloc();
    let root = crate::arch::Arch::read();
    let mut upt = crate::arch::PageTable::from_root(
        rux_klib::PhysAddr::new(root as usize));

    use rux_mm::FrameAllocator;
    let frame = alloc.alloc(rux_mm::PageSize::FourK)
        .expect("trampoline alloc");
    let pa = frame.as_usize();

    // Write trampoline code: mov x8, #139; svc #0; brk #0
    let code = pa as *mut u32;
    *code.add(0) = 0xD2801168; // mov x8, #139
    *code.add(1) = 0xD4000001; // svc #0
    *code.add(2) = 0xD4200000; // brk #0

    let flags = rux_mm::MappingFlags::USER
        .or(rux_mm::MappingFlags::READ)
        .or(rux_mm::MappingFlags::EXECUTE);
    let _ = upt.map_4k(
        rux_klib::VirtAddr::new(SIGRETURN_TRAMPOLINE_VA),
        rux_klib::PhysAddr::new(pa),
        flags,
        alloc,
    );
    // Flush TLB for the trampoline page to ensure the new mapping is visible.
    core::arch::asm!(
        "dsb ishst",
        "tlbi vale1is, {va}",
        "dsb ish",
        "isb",
        va = in(reg) (SIGRETURN_TRAMPOLINE_VA >> 12) as u64,
        options(nostack),
    );
    TRAMPOLINE_MAPPED = true;
}

// ── SignalOps implementation ──────────────────────────────────────────

unsafe impl rux_arch::SignalOps for super::Aarch64 {
    const SIGNAL_FRAME_SIZE: usize = core::mem::size_of::<SignalFrameAarch64>();

    unsafe fn sig_read_user_sp() -> usize {
        let sp: u64;
        core::arch::asm!("mrs {}, sp_el0", out(reg) sp, options(nostack));
        sp as usize
    }

    unsafe fn sig_write_user_sp(sp: usize) {
        core::arch::asm!("msr sp_el0, {}", in(reg) sp as u64, options(nostack));
    }

    unsafe fn sig_write_frame(
        frame_addr: usize, syscall_result: i64,
        blocked_mask: u64, _restorer: usize, _signum: u8,
    ) {
        let regs = CURRENT_REGS_PTR;
        let sp: u64;
        core::arch::asm!("mrs {}, sp_el0", out(reg) sp, options(nostack));
        let frame = frame_addr as *mut SignalFrameAarch64;
        // Save all GPRs (x0-x30) — handler will clobber caller-saved registers
        for i in 0..31 {
            (*frame).saved_regs[i] = *regs.add(i);
        }
        // x0 in the frame gets the syscall result (not the pre-syscall x0)
        (*frame).saved_regs[0] = syscall_result as u64;
        (*frame).saved_elr = *regs.add(31);
        (*frame).saved_spsr = *regs.add(32);
        (*frame).saved_mask = blocked_mask;
        (*frame).orig_user_sp = sp;
    }

    unsafe fn sig_redirect_to_handler(handler: usize, signum: u8) {
        let regs = CURRENT_REGS_PTR;
        *regs.add(31) = handler as u64;                    // ELR_EL1 = handler
        *regs.add(0) = signum as u64;                      // x0 = signal number
        *regs.add(30) = SIGRETURN_TRAMPOLINE_VA as u64;    // x30 (LR) = sigreturn trampoline
    }

    unsafe fn sig_redirect_to_handler_siginfo(handler: usize, signum: u8, siginfo_ptr: usize) {
        let regs = CURRENT_REGS_PTR;
        *regs.add(31) = handler as u64;                    // ELR_EL1 = handler
        *regs.add(0) = signum as u64;                      // x0 = signal number
        *regs.add(1) = siginfo_ptr as u64;                 // x1 = siginfo_t*
        *regs.add(2) = 0u64;                               // x2 = ucontext* (NULL)
        *regs.add(30) = SIGRETURN_TRAMPOLINE_VA as u64;    // x30 (LR) = sigreturn trampoline
    }

    unsafe fn sig_restore_frame(frame_addr: usize) -> (i64, u64) {
        let frame = frame_addr as *const SignalFrameAarch64;
        let saved_mask = (*frame).saved_mask;
        let orig_user_sp = (*frame).orig_user_sp;

        // Restore ALL GPRs (x0-x30) — undoes handler's register clobbering
        let regs = CURRENT_REGS_PTR;
        for i in 0..31 {
            *regs.add(i) = (*frame).saved_regs[i];
        }
        // Restore ELR + SPSR
        *regs.add(31) = (*frame).saved_elr;
        *regs.add(32) = (*frame).saved_spsr;

        // Restore user stack pointer
        core::arch::asm!("msr sp_el0, {}", in(reg) orig_user_sp, options(nostack));

        ((*frame).saved_regs[0] as i64, saved_mask)
    }

    unsafe fn sig_pre_deliver() {
        ensure_trampoline();
    }
}

/// aarch64 Linux syscall number → generic Syscall enum.
///
/// Const lookup table: O(1) bounds check + index.
#[inline]
fn translate_aarch64(nr: usize) -> crate::syscall::Syscall {
    use crate::syscall::Syscall;
    match SYSCALL_TABLE_AA64.get(nr).copied() {
        Some(Syscall::Unknown(_)) | None => Syscall::Unknown(nr),
        Some(sc) => sc,
    }
}

/// Compile-time syscall number → Syscall enum table for aarch64 Linux.
const SYSCALL_TABLE_AA64: [crate::syscall::Syscall; 437] = {
    use crate::syscall::Syscall;
    let u = Syscall::Unknown(9999); // sentinel — overwritten for valid entries
    let mut t = [u; 437];
    // File I/O
    t[56] = Syscall::OpenAt;     t[57] = Syscall::Close;
    t[63] = Syscall::Read;       t[64] = Syscall::Write;
    t[65] = Syscall::Readv;
    t[66] = Syscall::Writev;     t[67] = Syscall::Pread64;
    t[71] = Syscall::Sendfile;   t[23] = Syscall::Dup;
    t[24] = Syscall::Dup2;       t[25] = Syscall::Fcntl;
    t[29] = Syscall::Ioctl;      t[62] = Syscall::Lseek;
    t[59] = Syscall::Pipe2;      t[73] = Syscall::Poll;
    // File metadata
    t[79] = Syscall::FstatAt;    t[80] = Syscall::Fstat;
    t[78] = Syscall::Readlinkat; t[48] = Syscall::Faccessat;
    // Directory / path ops
    t[17] = Syscall::Getcwd;     t[33] = Syscall::Mknodat;
    t[34] = Syscall::Mkdirat;    t[35] = Syscall::Unlinkat;
    t[36] = Syscall::Symlinkat;  t[37] = Syscall::Linkat;
    t[38] = Syscall::Renameat;   t[49] = Syscall::Chdir;
    // Permissions
    t[52] = Syscall::Fchmodat;   t[53] = Syscall::Fchmod;
    t[54] = Syscall::Fchownat;   t[55] = Syscall::Fchown;
    t[88] = Syscall::Utimensat;
    // Memory
    t[222] = Syscall::Mmap;      t[215] = Syscall::Munmap;
    t[226] = Syscall::Mprotect;  t[214] = Syscall::Brk;
    // Process
    t[172] = Syscall::Getpid;    t[173] = Syscall::Getppid;
    t[93] = Syscall::Exit;       t[94] = Syscall::ExitGroup;
    t[129] = Syscall::Kill;      t[160] = Syscall::Uname;
    t[260] = Syscall::Wait4;
    // User/group IDs
    t[158] = Syscall::Getgroups; t[159] = Syscall::Getgroups;
    t[174] = Syscall::Getuid;    t[175] = Syscall::Geteuid;
    t[176] = Syscall::Getgid;    t[177] = Syscall::Getegid;
    t[146] = Syscall::Setuid;    t[144] = Syscall::Setgid;
    t[145] = Syscall::Setreuid;  t[143] = Syscall::Setregid;
    // Process groups
    t[154] = Syscall::Setpgid;   t[155] = Syscall::Getpgid;
    t[157] = Syscall::Setsid;
    // Signals
    t[134] = Syscall::Sigaction; t[135] = Syscall::Sigprocmask;
    t[132] = Syscall::Sigaltstack; t[139] = Syscall::Sigreturn;
    // Time / scheduling
    t[113] = Syscall::ClockGettime; t[101] = Syscall::Nanosleep;
    t[124] = Syscall::SchedYield;   t[169] = Syscall::Gettimeofday;
    t[163] = Syscall::Getrlimit;
    // Filesystem mounting
    t[40] = Syscall::Mount;      t[39] = Syscall::Umount;
    // Additional
    t[278] = Syscall::Getrandom; t[114] = Syscall::ClockGetres;
    t[24] = Syscall::Dup3;       t[156] = Syscall::Sysctl;
    t[32] = Syscall::Flock;
    t[103] = Syscall::SetItimer;
    t[72] = Syscall::Pselect6;
    t[115] = Syscall::ClockNanosleep;
    t[276] = Syscall::Renameat2;
    t[50] = Syscall::Fchdir;
    t[46] = Syscall::Flock; // ftruncate → stub as no-op (same as flock)
    // Sockets
    t[198] = Syscall::Socket;    t[200] = Syscall::Bind;
    t[203] = Syscall::Connect;   t[206] = Syscall::Sendto;
    t[207] = Syscall::Recvfrom;  t[208] = Syscall::Setsockopt;
    t[209] = Syscall::Getsockopt;
    t[204] = Syscall::Getsockname; t[205] = Syscall::Getpeername;
    t[211] = Syscall::Sendmsg;     t[212] = Syscall::Recvmsg;
    t[210] = Syscall::Shutdown;
    t[269] = Syscall::Sendmmsg;  t[243] = Syscall::Recvmmsg;
    // Linux extensions
    t[61] = Syscall::Getdents64; t[43] = Syscall::Statfs;
    t[44] = Syscall::Fstatfs;    t[179] = Syscall::Sysinfo;
    t[96] = Syscall::SetTidAddress; t[178] = Syscall::Gettid;
    t[167] = Syscall::Prctl;     t[99] = Syscall::SetRobustList;
    t[98] = Syscall::Futex;      t[131] = Syscall::Tgkill;
    t[130] = Syscall::Tkill;     t[123] = Syscall::SchedGetaffinity;
    t[261] = Syscall::Prlimit64; t[293] = Syscall::Rseq;
    // Phase 1 stubs
    t[165] = Syscall::Getrusage; t[141] = Syscall::GetPriority;
    t[140] = Syscall::SetPriority; t[166] = Syscall::Umask;
    t[159] = Syscall::SetGroups;
    t[82] = Syscall::Fsync;      t[83] = Syscall::Fdatasync;
    t[81] = Syscall::Sync;       t[267] = Syscall::Syncfs;
    t[47] = Syscall::Fallocate;
    t[8] = Syscall::Getxattr;    t[5] = Syscall::Setxattr;
    t[10] = Syscall::Fgetxattr;  t[7] = Syscall::Fsetxattr;
    t[9] = Syscall::Lgetxattr;   t[6] = Syscall::Lsetxattr;
    t[11] = Syscall::Listxattr;  t[13] = Syscall::Flistxattr;
    t[12] = Syscall::Llistxattr;
    t[14] = Syscall::Removexattr; t[16] = Syscall::Fremovexattr;
    t[15] = Syscall::Lremovexattr;
    t[90] = Syscall::Capget;     t[91] = Syscall::Capset;
    t[92] = Syscall::Personality; t[277] = Syscall::Seccomp;
    t[128] = Syscall::RestartSyscall; t[283] = Syscall::Membarrier;
    // Phase 2 wrappers
    t[68] = Syscall::Pwrite64;   t[46] = Syscall::Ftruncate;
    t[45] = Syscall::Truncate;   t[156] = Syscall::Getsid;
    // Phase 3 epoll
    t[20] = Syscall::EpollCreate1; t[21] = Syscall::EpollCtl;
    t[22] = Syscall::EpollPwait;
    // Phase 4 server sockets
    t[201] = Syscall::Listen;    t[202] = Syscall::Accept;
    t[242] = Syscall::Accept4;
    // Phase 5 event/timer fds + signalfd
    t[74] = Syscall::Signalfd4;
    t[19] = Syscall::Eventfd2;
    t[85] = Syscall::TimerfdCreate; t[86] = Syscall::TimerfdSettime;
    t[87] = Syscall::TimerfdGettime;
    // Batch 2: memory
    t[233] = Syscall::Madvise;   t[232] = Syscall::Mincore;
    t[216] = Syscall::Mremap;    t[227] = Syscall::Msync;
    t[228] = Syscall::Mlock;     t[229] = Syscall::Munlock;
    t[230] = Syscall::Mlockall;  t[231] = Syscall::Munlockall;
    // Batch 2: signals
    t[136] = Syscall::SigPending; t[137] = Syscall::SigTimedwait;
    t[138] = Syscall::SigQueueinfo; t[240] = Syscall::TgSigQueueinfo;
    // Batch 2: splice
    t[76] = Syscall::Splice;     t[75] = Syscall::Vmsplice;
    t[77] = Syscall::Tee;
    // Batch 2: process
    t[122] = Syscall::SchedGetparam; t[118] = Syscall::SchedSetparam;
    t[121] = Syscall::SchedGetscheduler; t[119] = Syscall::SchedSetscheduler;
    t[122] = Syscall::SchedSetaffinity;
    t[148] = Syscall::Getresuid; t[150] = Syscall::Getresgid;
    t[147] = Syscall::Setresuid; t[149] = Syscall::Setresgid;
    // Batch 2: filesystem
    t[51] = Syscall::Chroot;     t[41] = Syscall::PivotRoot;
    t[223] = Syscall::Fadvise;
    t[26] = Syscall::Inotify;    t[27] = Syscall::InotifyAddWatch;
    t[28] = Syscall::InotifyRmWatch;
    // Batch 2: misc
    t[116] = Syscall::Syslog;    t[142] = Syscall::Reboot;
    t[162] = Syscall::Setdomainname; t[161] = Syscall::Sethostname;
    t[102] = Syscall::Getitimer;
    // t[53] = Syscall::Fchmod (already set above; lchown uses fchownat on aarch64)
    t[152] = Syscall::Setfsuid;  t[153] = Syscall::Setfsgid;
    t[279] = Syscall::MemfdCreate; t[285] = Syscall::CopyFileRange;
    t[291] = Syscall::Statx;
    // Batch 3: POSIX IPC
    t[190] = Syscall::Semget;    t[193] = Syscall::Semop;
    t[191] = Syscall::Semctl;    t[194] = Syscall::Shmget;
    t[196] = Syscall::Shmat;     t[197] = Syscall::Shmdt;
    t[195] = Syscall::Shmctl;    t[186] = Syscall::Msgget;
    t[189] = Syscall::Msgsnd;    t[188] = Syscall::Msgrcv;
    t[187] = Syscall::Msgctl;
    // Batch 3: process
    t[435] = Syscall::Clone3;    t[95] = Syscall::Waitid;
    t[281] = Syscall::Execveat;  t[270] = Syscall::ProcessVmReadv;
    t[271] = Syscall::ProcessVmWritev; t[117] = Syscall::Ptrace;
    // Batch 3: timer/clock
    t[112] = Syscall::ClockSettime; t[107] = Syscall::TimerCreate;
    t[110] = Syscall::TimerSettime; t[108] = Syscall::TimerGettime;
    t[109] = Syscall::TimerGetoverrun; t[111] = Syscall::TimerDelete;
    // Batch 3: filesystem
    t[213] = Syscall::Readahead; t[60] = Syscall::Quotactl;
    t[264] = Syscall::NameToHandleAt; t[265] = Syscall::OpenByHandleAt;
    // Batch 3: misc
    t[272] = Syscall::Kcmp;
    t[434] = Syscall::Pidfd;     t[424] = Syscall::PidfdSendSignal;
    t[425] = Syscall::IoUringSetup; t[426] = Syscall::IoUringEnter;
    t[427] = Syscall::IoUringRegister;
    t[436] = Syscall::Close2;    // close_range
    t[199] = Syscall::Socketpair;
    t[73] = Syscall::Ppoll2;     // ppoll (alias to ppoll handler)
    t
};

// ── VforkContext implementation ─────────────────────────────────────────

/// Stash the exception frame pointer so VforkContext methods can access it.
/// Set by handle_syscall before calling generic_vfork.
pub static mut CURRENT_REGS_PTR: *mut u64 = core::ptr::null_mut();

/// Saved parent exception frame for VforkContext (34 u64s).
static mut SAVED_PARENT_FRAME: [u64; FRAME_REGS] = [0; FRAME_REGS];
/// Saved regs pointer for restore_and_return_to_user.
static mut SAVED_REGS_PTR: *mut u64 = core::ptr::null_mut();

unsafe impl rux_arch::VforkContext for super::Aarch64 {
    const CHILD_STACK_VA: usize = 0x7FFD_0000;

    unsafe fn save_regs() {
        let regs = CURRENT_REGS_PTR;
        for i in 0..FRAME_REGS {
            SAVED_PARENT_FRAME[i] = *regs.add(i);
        }
        SAVED_REGS_PTR = regs;
    }

    unsafe fn save_user_sp() -> usize {
        let sp: u64;
        core::arch::asm!("mrs {}, sp_el0", out(reg) sp, options(nostack));
        sp as usize
    }

    unsafe fn set_user_sp(sp: usize) {
        core::arch::asm!("msr sp_el0, {}", in(reg) sp, options(nostack));
    }

    unsafe fn save_tls() -> u64 {
        let tls: u64;
        core::arch::asm!("mrs {}, tpidr_el0", out(reg) tls, options(nostack));
        tls
    }

    unsafe fn restore_tls(val: u64) {
        core::arch::asm!("msr tpidr_el0, {}", in(reg) val, options(nostack));
    }

    unsafe fn read_pt_root() -> u64 {
        let ttbr0: u64;
        core::arch::asm!("mrs {}, ttbr0_el1", out(reg) ttbr0, options(nostack));
        ttbr0 & 0x0000_FFFF_FFFF_FFFF // mask out ASID bits [63:48]
    }

    unsafe fn write_pt_root(root: u64) {
        core::arch::asm!(
            "msr ttbr0_el1, {}",
            "isb",
            "tlbi vmalle1is",
            "dsb ish",
            "ic iallu",
            "dsb ish",
            "isb",
            in(reg) root,
            options(nostack)
        );
    }

    unsafe fn clear_jmp() { VFORK_JMP.sp = 0; }

    unsafe fn setjmp() -> isize { vfork_setjmp(&raw mut VFORK_JMP) as isize }

    fn jmp_active() -> bool { unsafe { VFORK_JMP.sp != 0 } }

    unsafe fn longjmp(child_pid: isize) -> ! {
        vfork_longjmp(&raw mut VFORK_JMP, child_pid as i64);
    }

    unsafe fn restore_and_return_to_user(return_val: isize, user_sp: usize) -> ! {
        // Restore parent's user stack pointer
        core::arch::asm!("msr sp_el0, {}", in(reg) user_sp, options(nostack));

        let frame = SAVED_REGS_PTR;
        for i in 0..FRAME_REGS {
            *frame.add(i) = SAVED_PARENT_FRAME[i];
        }
        *frame.add(0) = return_val as u64; // x0 = child PID

        // Match exception.S restore_context exactly
        core::arch::asm!(
            "mov sp, {frame}",
            "ldp x30, x10, [sp, #240]",
            "ldr x11, [sp, #256]",
            "msr elr_el1, x10",
            "msr spsr_el1, x11",
            "isb",
            "ldp x0,  x1,  [sp, #0]",
            "ldp x2,  x3,  [sp, #16]",
            "ldp x4,  x5,  [sp, #32]",
            "ldp x6,  x7,  [sp, #48]",
            "ldp x8,  x9,  [sp, #64]",
            "ldp x10, x11, [sp, #80]",
            "ldp x12, x13, [sp, #96]",
            "ldp x14, x15, [sp, #112]",
            "ldp x16, x17, [sp, #128]",
            "ldp x18, x19, [sp, #144]",
            "ldp x20, x21, [sp, #160]",
            "ldp x22, x23, [sp, #176]",
            "ldp x24, x25, [sp, #192]",
            "ldp x26, x27, [sp, #208]",
            "ldp x28, x29, [sp, #224]",
            "add sp, sp, #272",
            "eret",
            frame = in(reg) frame,
            options(noreturn)
        );
    }

    unsafe fn on_exec_reset() {
        reset_trampoline();
    }
}

// setjmp/longjmp buffer: callee-saved regs + SP + LR
#[repr(C)]
struct JmpBuf {
    x19: u64,
    x20: u64,
    x21: u64,
    x22: u64,
    x23: u64,
    x24: u64,
    x25: u64,
    x26: u64,
    x27: u64,
    x28: u64,
    x29: u64, // frame pointer
    lr: u64,  // x30 / return address
    sp: u64,
}

static mut VFORK_JMP: JmpBuf = JmpBuf {
    x19: 0, x20: 0, x21: 0, x22: 0, x23: 0, x24: 0,
    x25: 0, x26: 0, x27: 0, x28: 0, x29: 0, lr: 0, sp: 0,
};

// setjmp/longjmp implemented in pure assembly for correctness
core::arch::global_asm!(r#"
// vfork_setjmp: saves callee-saved regs + SP + LR into JmpBuf.
// Returns 0 on first call.
// x0 = pointer to JmpBuf
.global vfork_setjmp
vfork_setjmp:
    stp     x19, x20, [x0, #0]
    stp     x21, x22, [x0, #16]
    stp     x23, x24, [x0, #32]
    stp     x25, x26, [x0, #48]
    stp     x27, x28, [x0, #64]
    stp     x29, x30, [x0, #80]   // x29=FP, x30=LR (return address)
    mov     x2, sp
    str     x2, [x0, #96]          // SP
    mov     x0, #0                  // return 0
    ret

// vfork_longjmp: restores context from JmpBuf, makes setjmp return `val`.
// x0 = pointer to JmpBuf, x1 = return value
.global vfork_longjmp
vfork_longjmp:
    ldp     x19, x20, [x0, #0]
    ldp     x21, x22, [x0, #16]
    ldp     x23, x24, [x0, #32]
    ldp     x25, x26, [x0, #48]
    ldp     x27, x28, [x0, #64]
    ldp     x29, x30, [x0, #80]   // restore FP + LR
    ldr     x2, [x0, #96]
    mov     sp, x2                  // restore SP
    mov     x0, x1                  // return value
    ret                             // jump to saved LR
"#);

extern "C" {
    fn vfork_setjmp(buf: *mut JmpBuf) -> i64;
    fn vfork_longjmp(buf: *mut JmpBuf, val: i64) -> !;
}

/// Enter user mode (EL0) via eret.
/// Sets ELR_EL1 = entry, SP_EL0 = user_stack, SPSR_EL1 = 0 (EL0t).
/// Also resets SP_EL1 to the current task's kernel stack top so the
/// next exception from EL0 uses the correct kernel stack.
pub unsafe fn enter_user_mode(entry: usize, user_stack: usize) -> ! {
    let idx = crate::task_table::current_task_idx();
    let kstack_top = crate::task_table::TASK_TABLE[idx].kstack_top;
    core::arch::asm!(
        "msr sp_el0, {sp}",         // user stack pointer
        "msr elr_el1, {entry}",     // return-to address
        "msr spsr_el1, xzr",        // SPSR = 0 = EL0t, interrupts enabled
        "mov sp, {ksp}",            // reset kernel stack for next exception
        "isb",                       // sync ELR/SPSR before eret
        "eret",
        entry = in(reg) entry,
        sp = in(reg) user_stack,
        ksp = in(reg) kstack_top,
        options(noreturn)
    );
}

unsafe impl rux_arch::UserModeOps for super::Aarch64 {
    unsafe fn enter_user_mode(entry: usize, user_stack: usize) -> ! {
        self::enter_user_mode(entry, user_stack)
    }
}
