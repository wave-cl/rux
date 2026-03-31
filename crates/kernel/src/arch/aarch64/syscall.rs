/// SVC syscall handler for aarch64.
/// User code does `svc #0` which traps to EL1.
/// Uses aarch64 Linux syscall numbers.

use super::console;

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

        // Process creation + sigreturn (handled before generic dispatch)
        let result: i64 = match nr {
            // nr=220 is clone(flags, ...). COW fork replaces vfork — both
            // parent and child run concurrently with COW isolation.
            220 => {
                crate::fork::sys_fork() as i64
            }
            221 => { crate::syscall::generic_exec::<super::Aarch64>(a0 as usize, a1 as usize); 0 }
            139 => {
                // rt_sigreturn — restore pre-signal state
                // generic_sigreturn modifies the exception frame directly via SignalOps
                let _ = crate::syscall::generic_sigreturn::<super::Aarch64>();
                return; // exception frame already has restored x0, skip writing it
            }
            _ => {
                let sc = translate_aarch64(nr as usize);
                crate::syscall::dispatch(sc, a0 as usize, a1 as usize, a2 as usize, a3 as usize, a4 as usize) as i64
            }
        };

        // Return value in x0
        *regs.add(0) = result as u64;

        // Check for pending signals before returning to userspace
        if !crate::syscall::PROCESS.in_vfork_child && crate::syscall::PROCESS.signal_hot.has_deliverable() {
            crate::syscall::generic_deliver_signal::<super::Aarch64>(result);
        }
        // Check for pending reschedule (set by timer tick or fork).
        let sched = crate::scheduler::get();
        if sched.need_resched {
            sched.schedule();
        }
    }
}

/// Signal frame layout on user stack (aarch64).
#[repr(C)]
struct SignalFrameAarch64 {
    saved_elr: u64,      // original ELR_EL1 (user return PC)
    saved_spsr: u64,     // original SPSR_EL1
    saved_x0: u64,       // syscall return value
    saved_mask: u64,     // blocked signal mask before handler
    orig_user_sp: u64,   // original sp_el0 for exact restoration
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
        (*frame).saved_elr = *regs.add(31);
        (*frame).saved_spsr = *regs.add(32);
        (*frame).saved_x0 = syscall_result as u64;
        (*frame).saved_mask = blocked_mask;
        (*frame).orig_user_sp = sp;
    }

    unsafe fn sig_redirect_to_handler(handler: usize, signum: u8) {
        let regs = CURRENT_REGS_PTR;
        *regs.add(31) = handler as u64;                    // ELR_EL1 = handler
        *regs.add(0) = signum as u64;                      // x0 = signal number
        *regs.add(30) = SIGRETURN_TRAMPOLINE_VA as u64;    // x30 (LR) = sigreturn trampoline
    }

    unsafe fn sig_restore_frame(frame_addr: usize) -> (i64, u64) {
        let frame = frame_addr as *const SignalFrameAarch64;
        let saved_elr = (*frame).saved_elr;
        let saved_spsr = (*frame).saved_spsr;
        let saved_x0 = (*frame).saved_x0;
        let saved_mask = (*frame).saved_mask;
        let orig_user_sp = (*frame).orig_user_sp;

        // Restore exception frame registers
        let regs = CURRENT_REGS_PTR;
        *regs.add(31) = saved_elr;
        *regs.add(32) = saved_spsr;
        *regs.add(0) = saved_x0;

        // Restore user stack pointer
        core::arch::asm!("msr sp_el0, {}", in(reg) orig_user_sp, options(nostack));

        (saved_x0 as i64, saved_mask)
    }

    unsafe fn sig_pre_deliver() {
        ensure_trampoline();
    }
}

/// aarch64 Linux syscall number → generic Syscall enum.
fn translate_aarch64(nr: usize) -> crate::syscall::Syscall {
    use crate::syscall::Syscall;
    match nr {
        // File I/O
        56 => Syscall::OpenAt,
        57 => Syscall::Close,
        63 => Syscall::Read,
        64 => Syscall::Write,
        66 => Syscall::Writev,
        71 => Syscall::Sendfile,
        23 => Syscall::Dup,
        24 => Syscall::Dup2,
        25 => Syscall::Fcntl,
        29 => Syscall::Ioctl,
        62 => Syscall::Lseek,
        59 => Syscall::Pipe2,
        // File metadata
        79 => Syscall::FstatAt,
        80 => Syscall::Fstat,
        78 => Syscall::Readlinkat,          // readlinkat(dirfd, path, buf, bufsiz)
        48 => Syscall::Faccessat,
        // Directory / path ops
        17 => Syscall::Getcwd,
        33 => Syscall::Mknodat,             // mknodat(dirfd, path, mode, dev)
        34 => Syscall::Mkdirat,             // mkdirat(dirfd, path, mode)
        35 => Syscall::Unlinkat,            // unlinkat(dirfd, path, flags)
        36 => Syscall::Symlinkat,            // symlinkat(target, dirfd, linkpath)
        37 => Syscall::Linkat,              // linkat(olddirfd, old, newdirfd, new, flags)
        38 => Syscall::Renameat,            // renameat(olddirfd, old, newdirfd, new)
        49 => Syscall::Chdir,
        52 => Syscall::Fchmodat,            // fchmodat(dirfd, path, mode)
        53 => Syscall::Fchmod,              // fchmod(fd, mode)
        54 => Syscall::Fchownat,            // fchownat(dirfd, path, uid, gid, flags)
        55 => Syscall::Fchown,              // fchown(fd, uid, gid)
        88 => Syscall::Utimensat,
        // Memory
        222 => Syscall::Mmap,
        215 => Syscall::Munmap,
        226 => Syscall::Mprotect,
        214 => Syscall::Brk,
        // Process
        172 => Syscall::Getpid,
        173 => Syscall::Getppid,
        93 => Syscall::Exit,
        94 => Syscall::ExitGroup,
        129 => Syscall::Kill,
        160 => Syscall::Uname,
        260 => Syscall::Wait4,
        // User/group IDs
        158 | 159 => Syscall::Getgroups, // getgroups / setgroups
        174 => Syscall::Getuid,
        175 => Syscall::Geteuid,
        176 => Syscall::Getgid,
        177 => Syscall::Getegid,
        // Process groups
        154 => Syscall::Setpgid,
        155 => Syscall::Getpgid,
        157 => Syscall::Setsid,
        // Signals
        134 => Syscall::Sigaction,
        135 => Syscall::Sigprocmask,
        132 => Syscall::Sigaltstack,
        139 => Syscall::Sigreturn,
        // Time / scheduling
        113 => Syscall::ClockGettime,
        101 => Syscall::Nanosleep,
        124 => Syscall::SchedYield,
        // Linux extensions
        61 => Syscall::Getdents64,
        43 | 44 => Syscall::Statfs, // statfs / fstatfs
        179 => Syscall::Sysinfo,
        96 => Syscall::SetTidAddress,
        178 => Syscall::Gettid,
        167 => Syscall::Prctl,
        99 => Syscall::SetRobustList,
        98 => Syscall::Futex,
        131 => Syscall::Tgkill,
        130 => Syscall::Tkill,
        123 => Syscall::SchedGetaffinity,
        261 => Syscall::Prlimit64,
        293 => Syscall::Rseq,
        73 => Syscall::Poll,
        169 => Syscall::Gettimeofday,
        163 => Syscall::Getrlimit,
        _ => Syscall::Unknown(nr),
    }
}

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
pub unsafe fn enter_user_mode(entry: usize, user_stack: usize) -> ! {
    core::arch::asm!(
        "msr sp_el0, {sp}",         // user stack pointer
        "msr elr_el1, {entry}",     // return-to address
        "msr spsr_el1, xzr",        // SPSR = 0 = EL0t, interrupts enabled
        "eret",
        entry = in(reg) entry,
        sp = in(reg) user_stack,
        options(noreturn)
    );
}

unsafe impl rux_arch::UserModeOps for super::Aarch64 {
    unsafe fn enter_user_mode(entry: usize, user_stack: usize) -> ! {
        self::enter_user_mode(entry, user_stack)
    }
}
