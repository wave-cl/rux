/// Syscall handlers for x86_64.
/// Supports both INT 0x80 (rux-box) and SYSCALL instruction (Linux ABI).

use super::gdt::{USER_CS, USER_DS};
use super::console;

// ── SYSCALL instruction setup (Linux x86_64 ABI) ───────────────────

/// Kernel stack for syscall entry. For multi-process, each task will have
/// its own stack in KSTACKS; CURRENT_KSTACK_TOP selects which is active.
static mut SYSCALL_STACK: [u8; 65536] = [0; 65536];

/// Points to the top of the current task's kernel stack.
/// Used by SignalOps and VforkContext to access the saved register frame.
/// Updated on context switch (future).
pub static mut CURRENT_KSTACK_TOP: u64 = 0;

/// Get the top address of the default SYSCALL_STACK.
pub fn syscall_stack_top() -> u64 {
    unsafe { SYSCALL_STACK.as_ptr() as u64 + 65536 }
}

/// Saved user RSP during syscall (single-process, no swapgs needed).
#[no_mangle]
pub static mut SAVED_USER_RSP: u64 = 0;


/// Initialize the SYSCALL/SYSRET MSRs.
pub unsafe fn init_syscall_msrs() {
    // IA32_STAR (0xC0000081): segment selectors
    //   [47:32] = kernel CS (0x08), kernel SS = CS+8 = 0x10
    //   [63:48] = user base (0x10), sysret CS = base+16 = 0x20|3, SS = base+8 = 0x18|3
    let star: u64 = (0x0010u64 << 48) | (0x0008u64 << 32);
    core::arch::asm!("wrmsr", in("ecx") 0xC0000081u32, in("eax") star as u32, in("edx") (star >> 32) as u32);

    // IA32_LSTAR (0xC0000082): syscall entry point
    let lstar = syscall_entry as u64;
    core::arch::asm!("wrmsr", in("ecx") 0xC0000082u32, in("eax") lstar as u32, in("edx") (lstar >> 32) as u32);

    // IA32_SFMASK (0xC0000084): clear IF (bit 9) on syscall entry
    let sfmask: u64 = 0x200; // mask out IF
    core::arch::asm!("wrmsr", in("ecx") 0xC0000084u32, in("eax") sfmask as u32, in("edx") (sfmask >> 32) as u32);

    // Enable SCE (System Call Extensions) in IA32_EFER
    let mut efer: u64;
    core::arch::asm!("rdmsr", in("ecx") 0xC0000080u32, out("eax") efer, out("edx") _);
    efer |= 1; // SCE bit
    core::arch::asm!("wrmsr", in("ecx") 0xC0000080u32, in("eax") efer as u32, in("edx") (efer >> 32) as u32);

    console::write_str("rux: SYSCALL MSRs initialized\n");
}

/// Assembly entry point for the SYSCALL instruction.
/// On entry: RCX=user_RIP, R11=user_RFLAGS, RAX=syscall_nr
/// Args: RDI, RSI, RDX, R10 (not RCX!), R8, R9
#[unsafe(naked)]
unsafe extern "C" fn syscall_entry() {
    core::arch::naked_asm!(
        // Switch to per-task kernel stack (save user RSP).
        // CURRENT_KSTACK_TOP is updated by swap_process_state on every context switch
        // so each task uses its own kstack, preventing cross-task stack corruption.
        "mov [rip + {saved_user_rsp}], rsp",
        "mov rsp, [rip + {current_kstack_top}]",

        // Save callee-saved + syscall-specific regs
        "push rcx",      // user RIP
        "push r11",      // user RFLAGS
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",

        // Save args for the Rust handler
        // Linux syscall ABI: rax=nr, rdi=a0, rsi=a1, rdx=a2, r10=a3, r8=a4, r9=a5
        "push rax",       // syscall number
        "push rdi",       // arg0
        "push rsi",       // arg1
        "push rdx",       // arg2
        "push r10",       // arg3
        "push r8",        // arg4
        "push r9",        // arg5

        // Call Rust handler: syscall_dispatch_linux(nr, a0, a1, a2, a3, a4, a5)
        // Return value in RAX
        "mov rdi, rax",   // nr
        "mov rsi, [rsp + 40]", // arg0 (rdi was pushed at offset 5*8=40)
        "mov rdx, [rsp + 32]", // arg1 (rsi at 4*8=32)
        "mov rcx, [rsp + 24]", // arg2 (rdx at 3*8=24)
        "mov r8, [rsp + 16]",  // arg3 (r10 at 2*8=16)
        "mov r9, [rsp + 8]",   // arg4 (r8 at 1*8=8)
        // a5 would be [rsp + 0] but we pass max 5 args via regs

        "call {handler}",

        // RAX has the syscall return value.
        // Restore ALL caller-saved registers except RAX (which has return value).
        // Linux syscall ABI: only RCX and R11 are clobbered. All others preserved.
        // Stack: r9(sp), r8(sp+8), r10(sp+16), rdx(sp+24), rsi(sp+32), rdi(sp+40), rax(sp+48)
        "mov [rsp + 48], rax", // store return value where rax was saved
        "pop r9",
        "pop r8",
        "pop r10",
        "pop rdx",
        "pop rsi",
        "pop rdi",
        "pop rax",        // return value (we wrote it above)

        // Restore callee-saved
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "pop r11",        // user RFLAGS
        "pop rcx",        // user RIP

        // Restore user stack
        "mov rsp, [rip + {saved_user_rsp}]",

        // Return to user mode
        "sysretq",

        saved_user_rsp = sym SAVED_USER_RSP,
        current_kstack_top = sym CURRENT_KSTACK_TOP,
        handler = sym syscall_dispatch_linux,
    );
}

/// Fork child return trampoline.
/// context_switch retq's here. The child's kernel stack has a full
/// syscall register frame (same layout as syscall_entry pushes).
/// Pops all saved regs (with RAX=0 for fork return), then sysretq.
core::arch::global_asm!(r#"
.att_syntax prefix
.global fork_child_sysret
fork_child_sysret:
    popq %r9
    popq %r8
    popq %r10
    popq %rdx
    popq %rsi
    popq %rdi
    popq %rax
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx
    popq %r11
    popq %rcx
    movq SAVED_USER_RSP(%rip), %rsp
    sysretq
"#);

extern "C" {
    pub fn fork_child_sysret();
}

/// Rust dispatch for Linux x86_64 syscall ABI.
/// Called from the assembly entry point with syscall number and arguments.
#[no_mangle]
extern "C" fn syscall_dispatch_linux(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> i64 {
    use crate::syscall::Syscall;

    // Process creation syscalls (handled before generic dispatch)
    match nr {
        // 56=clone, 57=fork, 58=vfork
        // Route vfork (58) and clone with CLONE_VFORK flag to the setjmp path.
        // All other fork/clone calls go to sys_fork (real multi-process).
        58 => return unsafe { crate::syscall::generic_vfork::<super::X86_64>() } as i64,
        56 => {
            let flags = a0 as usize;
            const CLONE_VFORK: usize = 0x4000;
            if flags & CLONE_VFORK != 0 {
                return unsafe { crate::syscall::generic_vfork::<super::X86_64>() } as i64;
            }
            return unsafe { crate::fork::sys_fork() } as i64;
        }
        57 => return unsafe { crate::fork::sys_fork() } as i64,
        59 => { unsafe { crate::syscall::generic_exec::<super::X86_64>(a0 as usize, a1 as usize); } return 0; }
        _ => {}
    }

    // sigreturn is handled specially — it restores the pre-signal state
    if nr == 15 {
        return unsafe { crate::syscall::generic_sigreturn::<super::X86_64>() };
    }

    // Everything else goes through generic dispatch
    let sc = translate_x86_64(nr as usize);
    let result = crate::syscall::dispatch(sc, a0 as usize, a1 as usize, a2 as usize, a3 as usize, a4 as usize) as i64;

    // Check for pending signals before returning to userspace
    unsafe {
        if !crate::syscall::PROCESS.in_vfork_child && crate::syscall::PROCESS.signal_hot.has_deliverable() {
            return crate::syscall::generic_deliver_signal::<super::X86_64>(result);
        }
        // Check for pending reschedule (set by timer tick or fork).
        let sched = crate::scheduler::get();
        if sched.need_resched {
            sched.schedule();
        }
    }
    result
}

/// Signal frame layout on user stack (x86_64).
/// The restorer word is the "return address" for the signal handler (at frame[0]).
/// When the handler executes `ret`, RSP advances past the restorer to frame[1] (saved_rip).
/// At sigreturn time, SAVED_USER_RSP = frame_addr + 8. sig_restore_frame receives frame_addr + 8
/// and must subtract 8 to find the actual frame start.
#[repr(C)]
struct SignalFrameX86 {
    restorer: u64,       // return address (sa_restorer → calls sigreturn)  [frame+0]
    saved_rip: u64,      // original user RIP (was in RCX)                  [frame+8]
    saved_rflags: u64,   // original RFLAGS (was in R11)                    [frame+16]
    saved_rax: u64,      // syscall return value                             [frame+24]
    saved_mask: u64,     // blocked signal mask before handler               [frame+32]
    signum: u64,         // signal number                                    [frame+40]
    orig_user_sp: u64,   // original user RSP (for exact restoration)        [frame+48]
}

// ── SignalOps implementation ──────────────────────────────────────────

unsafe impl rux_arch::SignalOps for super::X86_64 {
    const SIGNAL_FRAME_SIZE: usize = core::mem::size_of::<SignalFrameX86>();

    unsafe fn sig_read_user_sp() -> usize { SAVED_USER_RSP as usize }

    unsafe fn sig_write_user_sp(sp: usize) { SAVED_USER_RSP = sp as u64; }

    unsafe fn sig_write_frame(
        frame_addr: usize, syscall_result: i64,
        blocked_mask: u64, restorer: usize, signum: u8,
    ) {
        // Read saved RCX (user RIP) and R11 (RFLAGS) from kernel stack
        let stack_top = CURRENT_KSTACK_TOP as *const u64;
        let saved_rip = *stack_top.sub(1);
        let saved_rflags = *stack_top.sub(2);

        let frame = frame_addr as *mut SignalFrameX86;
        (*frame).restorer = restorer as u64;
        (*frame).saved_rip = saved_rip;
        (*frame).saved_rflags = saved_rflags;
        (*frame).saved_rax = syscall_result as u64;
        (*frame).saved_mask = blocked_mask;
        (*frame).signum = signum as u64;
        // Save original user RSP so sigreturn can restore it exactly.
        (*frame).orig_user_sp = SAVED_USER_RSP;
    }

    unsafe fn sig_redirect_to_handler(handler: usize, signum: u8) {
        let stack_top_mut = CURRENT_KSTACK_TOP as *mut u64;
        *stack_top_mut.sub(1) = handler as u64;   // RCX = handler address → RIP via sysretq
        *stack_top_mut.sub(10) = signum as u64;    // RDI = signum (1st arg to handler)
    }

    unsafe fn sig_restore_frame(frame_addr: usize) -> (i64, u64) {
        // frame_addr = SAVED_USER_RSP at sigreturn time = frame_start + 8
        // (signal handler's `ret` popped the restorer word, advancing RSP by 8)
        let frame = (frame_addr - 8) as *const SignalFrameX86;
        let saved_rip = (*frame).saved_rip;
        let saved_rflags = (*frame).saved_rflags;
        let saved_rax = (*frame).saved_rax;
        let saved_mask = (*frame).saved_mask;
        let orig_user_sp = (*frame).orig_user_sp;

        // Restore original user RSP
        SAVED_USER_RSP = orig_user_sp;

        // Restore RCX (user RIP) and R11 (RFLAGS) on kernel stack
        let stack_top_mut = CURRENT_KSTACK_TOP as *mut u64;
        *stack_top_mut.sub(1) = saved_rip;
        *stack_top_mut.sub(2) = saved_rflags;

        (saved_rax as i64, saved_mask)
    }
}

/// x86_64 Linux syscall number → generic Syscall enum.
fn translate_x86_64(nr: usize) -> crate::syscall::Syscall {
    use crate::syscall::Syscall;
    match nr {
        0 => Syscall::Read,
        1 => Syscall::Write,
        2 => Syscall::Open,
        3 => Syscall::Close,
        4 => Syscall::Stat,                 // stat (follows symlinks)
        6 => Syscall::Lstat,                // lstat (no follow)
        5 => Syscall::Fstat,
        7 => Syscall::Poll,
        8 => Syscall::Lseek,
        9 => Syscall::Mmap,
        10 => Syscall::Mprotect,
        11 => Syscall::Munmap,
        12 => Syscall::Brk,
        13 => Syscall::Sigaction,
        14 => Syscall::Sigprocmask,
        15 => Syscall::Sigreturn,
        16 => Syscall::Ioctl,
        20 => Syscall::Writev,
        21 => Syscall::Access,
        22 | 293 => Syscall::Pipe2,
        24 => Syscall::SchedYield,
        32 => Syscall::Dup,
        33 => Syscall::Dup2,
        35 => Syscall::Nanosleep,
        37 => Syscall::Alarm,
        39 => Syscall::Getpid,
        40 => Syscall::Sendfile,
        60 => Syscall::Exit,
        61 => Syscall::Wait4,
        62 => Syscall::Kill,
        63 => Syscall::Uname,
        72 => Syscall::Fcntl,
        78 | 217 => Syscall::Getdents64,
        79 => Syscall::Getcwd,
        80 => Syscall::Chdir,
        82 | 264 => Syscall::Rename,       // rename / renameat
        83 => Syscall::Mkdir,
        86 => Syscall::Link,               // link(old, new)
        265 => Syscall::Linkat,            // linkat(olddirfd, old, newdirfd, new, flags)
        87 => Syscall::Unlink,
        88 | 266 => Syscall::Symlink,       // symlink / symlinkat
        89 | 267 => Syscall::Readlink,      // readlink / readlinkat
        90 => Syscall::Chmod,              // chmod(path, mode)
        91 => Syscall::Fchmod,             // fchmod(fd, mode)
        92 => Syscall::Chown,              // chown(path, uid, gid)
        93 => Syscall::Fchown,             // fchown(fd, uid, gid)
        96 => Syscall::Gettimeofday,
        97 => Syscall::Getrlimit,
        99 => Syscall::Sysinfo,
        137 | 138 => Syscall::Statfs, // statfs / fstatfs
        102 | 107 => Syscall::Getuid,
        104 | 108 => Syscall::Getgid,
        109 => Syscall::Setpgid,
        115 | 116 => Syscall::Getgroups, // getgroups / setgroups
        110 => Syscall::Getppid,
        111 => Syscall::Getpgid,
        112 => Syscall::Setsid,
        121 => Syscall::Getpgid,
        131 => Syscall::Sigaltstack,
        157 => Syscall::Prctl,
        186 => Syscall::Gettid,
        200 => Syscall::Tkill,
        202 => Syscall::Futex,
        204 => Syscall::SchedGetaffinity,
        218 => Syscall::SetTidAddress,
        228 => Syscall::ClockGettime,
        231 => Syscall::ExitGroup,
        257 => Syscall::OpenAt,
        262 => Syscall::FstatAt,
        269 => Syscall::Faccessat,
        273 => Syscall::SetRobustList,
        280 => Syscall::Utimensat,
        292 => Syscall::Dup2,               // dup3 → dup2 (ignore flags)
        302 => Syscall::Prlimit64,
        334 => Syscall::Rseq,
        // x86_64-specific
        158 => Syscall::ArchSpecific(nr),
        _ => Syscall::Unknown(nr),
    }
}

pub fn handle_syscall(_vector: u64, _error_code: u64, frame: *mut u8) {
    unsafe {
        let regs = frame as *mut u64;
        let nr = *regs.add(14);   // RAX = syscall number
        let a0 = *regs.add(9);    // RDI
        let a1 = *regs.add(10);   // RSI
        let a2 = *regs.add(11);   // RDX

        // Vfork/exec use generic implementation
        let result: i64 = match nr {
            57 => crate::syscall::generic_vfork::<super::X86_64>() as i64,
            59 => { crate::syscall::generic_exec::<super::X86_64>(a0 as usize, a1 as usize); 0 }
            _ => {
                let sc = translate_x86_64(nr as usize);
                crate::syscall::dispatch(sc, a0 as usize, a1 as usize, a2 as usize, 0, 0) as i64
            }
        };

        *regs.add(14) = result as u64;
    }
}

// setjmp/longjmp buffer: callee-saved regs + RSP + RIP
#[repr(C)]
struct JmpBuf {
    rbx: u64,
    rbp: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rsp: u64,
    rip: u64,
}

static mut VFORK_JMP: JmpBuf = JmpBuf {
    rbx: 0, rbp: 0, r12: 0, r13: 0, r14: 0, r15: 0, rsp: 0, rip: 0,
};

// setjmp/longjmp implemented in pure assembly for correctness
core::arch::global_asm!(r#"
.att_syntax prefix

// vfork_setjmp: saves callee-saved regs + RSP + return address into VFORK_JMP.
// Returns 0 on first call.
// RDI = pointer to JmpBuf
.global vfork_setjmp
vfork_setjmp:
    movq %rbx, 0(%rdi)
    movq %rbp, 8(%rdi)
    movq %r12, 16(%rdi)
    movq %r13, 24(%rdi)
    movq %r14, 32(%rdi)
    movq %r15, 40(%rdi)
    leaq 8(%rsp), %rax        // RSP after return
    movq %rax, 48(%rdi)
    movq (%rsp), %rax          // return address
    movq %rax, 56(%rdi)
    xorl %eax, %eax            // return 0
    retq

// vfork_longjmp: restores context from JmpBuf, makes setjmp return `val`.
// RDI = pointer to JmpBuf, RSI = return value
.global vfork_longjmp
vfork_longjmp:
    movq 0(%rdi), %rbx
    movq 8(%rdi), %rbp
    movq 16(%rdi), %r12
    movq 24(%rdi), %r13
    movq 32(%rdi), %r14
    movq 40(%rdi), %r15
    movq 48(%rdi), %rsp
    movq %rsi, %rax            // return value
    jmpq *56(%rdi)             // jump to saved return address
"#);

extern "C" {
    fn vfork_setjmp(buf: *mut JmpBuf) -> i64;
    fn vfork_longjmp(buf: *mut JmpBuf, val: i64) -> !;
}

#[unsafe(naked)]
pub extern "C" fn enter_user_mode(entry: usize, user_stack: usize) -> ! {
    core::arch::naked_asm!(
        "push {user_ds}",
        "push rsi",
        "push 0x202",
        "push {user_cs}",
        "push rdi",
        "iretq",
        user_ds = const (USER_DS as u64),
        user_cs = const (USER_CS as u64),
    );
}

unsafe impl rux_arch::UserModeOps for super::X86_64 {
    unsafe fn enter_user_mode(entry: usize, user_stack: usize) -> ! {
        self::enter_user_mode(entry, user_stack)
    }
}

pub fn syscall_arch_prctl(code: u64, addr: u64) -> i64 {
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_SET_GS: u64 = 0x1001;
    const ARCH_GET_FS: u64 = 0x1003;
    const ARCH_GET_GS: u64 = 0x1004;

    unsafe {
        match code {
            ARCH_SET_FS => {
                // Set FS base via IA32_FS_BASE MSR (0xC0000100)
                let lo = addr as u32;
                let hi = (addr >> 32) as u32;
                core::arch::asm!(
                    "wrmsr",
                    in("ecx") 0xC0000100u32,
                    in("eax") lo,
                    in("edx") hi,
                    options(nostack),
                );
                0
            }
            ARCH_SET_GS => {
                core::arch::asm!(
                    "wrmsr",
                    in("ecx") 0xC0000101u32,
                    in("eax") addr as u32,
                    in("edx") (addr >> 32) as u32,
                );
                0
            }
            _ => -22 // -EINVAL
        }
    }
}

// ── VforkContext implementation ─────────────────────────────────────────

unsafe impl rux_arch::VforkContext for super::X86_64 {
    const CHILD_STACK_VA: usize = 0x7FFE_0000;

    unsafe fn save_regs() {
        let stack_top = CURRENT_KSTACK_TOP as *const u64;
        for i in 0..15 {
            VFORK_PARENT_REGS[i] = *stack_top.sub(i + 1);
        }
    }

    unsafe fn save_user_sp() -> usize { SAVED_USER_RSP as usize }

    unsafe fn set_user_sp(sp: usize) { SAVED_USER_RSP = sp as u64; }

    unsafe fn save_tls() -> u64 {
        let lo: u32;
        let hi: u32;
        core::arch::asm!("rdmsr", in("ecx") 0xC0000100u32, out("eax") lo, out("edx") hi, options(nostack));
        (hi as u64) << 32 | lo as u64
    }

    unsafe fn restore_tls(val: u64) {
        let lo = val as u32;
        let hi = (val >> 32) as u32;
        core::arch::asm!("wrmsr", in("ecx") 0xC0000100u32, in("eax") lo, in("edx") hi, options(nostack));
    }

    unsafe fn read_pt_root() -> u64 {
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack));
        cr3
    }

    unsafe fn write_pt_root(root: u64) {
        core::arch::asm!("mov cr3, {}", in(reg) root, options(nostack));
    }

    unsafe fn clear_jmp() { VFORK_JMP.rsp = 0; }

    unsafe fn setjmp() -> isize { vfork_setjmp(&raw mut VFORK_JMP) as isize }

    fn jmp_active() -> bool { unsafe { VFORK_JMP.rsp != 0 } }

    unsafe fn longjmp(child_pid: isize) -> ! {
        vfork_longjmp(&raw mut VFORK_JMP, child_pid as i64);
    }

    unsafe fn restore_and_return_to_user(return_val: isize, user_sp: usize) -> ! {
        // Write saved regs back to kernel stack
        let stack_top = CURRENT_KSTACK_TOP as *mut u64;
        for i in 0..15 {
            *stack_top.sub(i + 1) = VFORK_PARENT_REGS[i];
        }
        // Override RAX slot with child PID (return value)
        *stack_top.sub(9) = return_val as u64; // index 8 = RAX slot
        SAVED_USER_RSP = user_sp as u64;

        let pop_rsp = stack_top.sub(15) as u64;
        core::arch::asm!(
            "mov rsp, {rsp}",
            "pop r9", "pop r8", "pop r10", "pop rdx", "pop rsi", "pop rdi", "pop rax",
            "pop r15", "pop r14", "pop r13", "pop r12", "pop rbp", "pop rbx",
            "pop r11", "pop rcx",
            "mov rsp, [{saved_user_rsp}]",
            "sysretq",
            rsp = in(reg) pop_rsp,
            saved_user_rsp = sym SAVED_USER_RSP,
            options(noreturn)
        );
    }
}

/// Saved parent register state from kernel stack for VforkContext.
/// All 15 pushed registers (used by save_regs/restore_and_return_to_user).
static mut VFORK_PARENT_REGS: [u64; 15] = [0; 15];

