/// Syscall handlers for x86_64.
/// Supports both INT 0x80 (rux-box) and SYSCALL instruction (Linux ABI).

use super::gdt::{USER_CS, USER_DS};
use super::console;

// ── SYSCALL instruction setup (Linux x86_64 ABI) ───────────────────

/// Kernel stack for syscall entry. For multi-process, each task will have
/// its own stack in KSTACKS; CURRENT_KSTACK_TOP selects which is active.
#[repr(C, align(16))]
struct AlignedStack([u8; 65536]);
static mut SYSCALL_STACK: AlignedStack = AlignedStack([0; 65536]);

/// Points to the top of the current task's kernel stack.
/// Used by SignalOps and VforkContext to access the saved register frame.
/// Updated on context switch (future).
pub static mut CURRENT_KSTACK_TOP: u64 = 0;

/// Get the top address of the default SYSCALL_STACK.
pub fn syscall_stack_top() -> u64 {
    unsafe { (&raw const SYSCALL_STACK).cast::<u8>() as u64 + 65536 }
}

/// Saved user RSP during syscall (single-process, no swapgs needed).
#[no_mangle]
pub static mut SAVED_USER_RSP: u64 = 0;
/// 6th syscall argument (r9) — saved by syscall_entry for mmap offset.
pub static mut SAVED_SYSCALL_A5: u64 = 0;

/// Whether to use swapgs + gs:[offset] for per-CPU syscall entry.
/// Set to true when running on KVM or real hardware (not QEMU TCG).
pub static mut GS_PERCPU_ACTIVE: bool = false;


/// Initialize the SYSCALL/SYSRET MSRs.
pub unsafe fn init_syscall_msrs() {
    // IA32_STAR (0xC0000081): segment selectors
    //   [47:32] = kernel CS (0x08), kernel SS = CS+8 = 0x10
    //   [63:48] = user base (0x10), sysret CS = base+16 = 0x20|3, SS = base+8 = 0x18|3
    let star: u64 = (0x0010u64 << 48) | (0x0008u64 << 32);
    core::arch::asm!("wrmsr", in("ecx") 0xC0000081u32, in("eax") star as u32, in("edx") (star >> 32) as u32);

    // IA32_LSTAR (0xC0000082): syscall entry point
    // Select gs-based entry on KVM/real hardware, RIP-relative on QEMU TCG
    let lstar = if GS_PERCPU_ACTIVE {
        syscall_entry_gs as *const () as u64
    } else {
        syscall_entry as *const () as u64
    };
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
        // SMAP: on KVM/real hardware with CR4.SMAP, stac/clac are handled
        // at the Rust level via dispatch() and uaccess helpers.
        // Switch to per-task kernel stack (save user RSP).
        "mov [rip + {saved_user_rsp}], rsp",
        "mov [rip + {saved_a5}], r9",
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
        // Save 6th arg (r9) to static for mmap offset
        "mov [rip + {saved_a5}], r9",

        "push rax",       // syscall number
        "push rdi",       // arg0
        "push rsi",       // arg1
        "push rdx",       // arg2
        "push r10",       // arg3
        "push r8",        // arg4
        "push r9",        // arg5

        // Call Rust handler: syscall_dispatch_linux(nr, a0, a1, a2, a3, a4)
        // Return value in RAX
        "mov rdi, rax",   // nr
        "mov rsi, [rsp + 40]", // arg0 (rdi was pushed at offset 5*8=40)
        "mov rdx, [rsp + 32]", // arg1 (rsi at 4*8=32)
        "mov rcx, [rsp + 24]", // arg2 (rdx at 3*8=24)
        "mov r8, [rsp + 16]",  // arg3 (r10 at 2*8=16)
        "mov r9, [rsp + 8]",   // arg4 (r8 at 1*8=8)

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
        saved_a5 = sym SAVED_SYSCALL_A5,
        current_kstack_top = sym CURRENT_KSTACK_TOP,
        handler = sym syscall_dispatch_linux,
    );
}

/// GS-based syscall entry for KVM/real hardware.
/// Uses swapgs + gs:[offset] for per-CPU state instead of RIP-relative globals.
/// Dual-writes to both gs:[offset] and RIP-relative globals so Rust code
/// (VforkContext, SignalOps) that reads SAVED_USER_RSP directly still works.
#[unsafe(naked)]
unsafe extern "C" fn syscall_entry_gs() {
    core::arch::naked_asm!(
        // swapgs: swap IA32_GS_BASE (user) ↔ IA32_KERNEL_GS_BASE (kernel percpu)
        "swapgs",

        // Save user RSP + 6th arg via GS-relative per-CPU struct
        "mov gs:[0], rsp",          // percpu.saved_user_rsp
        "mov gs:[8], r9",           // percpu.saved_syscall_a5
        "mov rsp, gs:[16]",         // percpu.syscall_kstack_top

        // Dual-write to RIP-relative globals for Rust code compatibility
        "mov [rip + {saved_user_rsp}], rsp",  // NOTE: rsp is NOW the kstack, but
        // we need the USER rsp. Read it back from gs:[0].
        "push rax",                 // temp save
        "mov rax, gs:[0]",          // user rsp from percpu
        "mov [rip + {saved_user_rsp}], rax",
        "mov rax, gs:[8]",          // saved_a5 from percpu
        "mov [rip + {saved_a5}], rax",
        "pop rax",                  // restore syscall number

        // Save callee-saved + syscall-specific regs (same layout as syscall_entry)
        "push rcx",      // user RIP
        "push r11",      // user RFLAGS
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",

        // Save args
        "push rax",       // syscall number
        "push rdi",       // arg0
        "push rsi",       // arg1
        "push rdx",       // arg2
        "push r10",       // arg3
        "push r8",        // arg4
        "push r9",        // arg5

        // Call Rust handler
        "mov rdi, rax",
        "mov rsi, [rsp + 40]",
        "mov rdx, [rsp + 32]",
        "mov rcx, [rsp + 24]",
        "mov r8, [rsp + 16]",
        "mov r9, [rsp + 8]",
        "call {handler}",

        // Restore (same as syscall_entry)
        "mov [rsp + 48], rax",
        "pop r9",
        "pop r8",
        "pop r10",
        "pop rdx",
        "pop rsi",
        "pop rdi",
        "pop rax",

        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "pop r11",
        "pop rcx",

        // Restore user stack from percpu
        "mov rsp, gs:[0]",
        // Swap back to user GS
        "swapgs",
        "sysretq",

        saved_user_rsp = sym SAVED_USER_RSP,
        saved_a5 = sym SAVED_SYSCALL_A5,
        handler = sym syscall_dispatch_linux,
    );
}

// Fork child return trampoline.
// context_switch retq's here. The child's kernel stack has a full
// syscall register frame (same layout as syscall_entry pushes).
// Pops all saved regs (with RAX=0 for fork return), then sysretq.
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

// GS-based fork child return trampoline (for KVM/real hardware).
core::arch::global_asm!(r#"
.att_syntax prefix
.global fork_child_sysret_gs
fork_child_sysret_gs:
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
    movq %gs:0, %rsp
    swapgs
    sysretq
"#);

extern "C" {
    pub fn fork_child_sysret();
    pub fn fork_child_sysret_gs();
}

/// Rust dispatch for Linux x86_64 syscall ABI.
/// Called from the assembly entry point with syscall number and arguments.
#[no_mangle]
extern "C" fn syscall_dispatch_linux(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> i64 {
    // Process creation syscalls (handled before generic dispatch)
    match nr {
        // 56=clone(flags, stack, ptid, ctid, tls), 57=fork, 58=vfork
        56 => {
            let flags = a0 as usize;
            if flags & crate::errno::CLONE_VM != 0 {
                // Thread: shared address space
                return unsafe { crate::fork::sys_clone(flags, a1 as usize, a3 as usize) } as i64;
            }
            return unsafe { crate::fork::sys_fork() } as i64;
        }
        57 | 58 => return unsafe { crate::fork::sys_fork() } as i64,
        59 => { unsafe { crate::syscall::generic_exec::<super::X86_64>(a0 as usize, a1 as usize); } }
        _ => {}
    }

    // sigreturn is handled specially — it restores the pre-signal state
    // stac/clac needed: sig_restore_frame reads the signal frame from user stack
    if nr == 15 {
        unsafe { crate::uaccess::stac(); }
        let r = unsafe { crate::syscall::generic_sigreturn::<super::X86_64>() };
        unsafe { crate::uaccess::clac(); }
        return r;
    }

    // Everything else goes through generic dispatch
    let sc = translate_x86_64(nr as usize);
    let result = crate::syscall::dispatch(sc, a0 as usize, a1 as usize, a2 as usize, a3 as usize, a4 as usize) as i64;

    // Signal delivery + reschedule check (shared with aarch64)
    unsafe { crate::syscall::post_syscall::<super::X86_64>(result) }
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
        let kt = CURRENT_KSTACK_TOP as usize;
        let saved_rip = core::ptr::read_volatile((kt - 8) as *const u64);
        let saved_rflags = core::ptr::read_volatile((kt - 16) as *const u64);

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
        let kt = CURRENT_KSTACK_TOP as usize;
        core::ptr::write_volatile((kt - 8) as *mut u64, handler as u64);   // RCX → RIP
        core::ptr::write_volatile((kt - 80) as *mut u64, signum as u64);   // RDI = signum
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
        let kt = CURRENT_KSTACK_TOP as usize;
        core::ptr::write_volatile((kt - 8) as *mut u64, saved_rip);
        core::ptr::write_volatile((kt - 16) as *mut u64, saved_rflags);

        (saved_rax as i64, saved_mask)
    }
}

/// x86_64 Linux syscall number → generic Syscall enum.
///
/// Const lookup table: O(1) bounds check + index. Entries not in the table
/// fall through to Unknown(nr). ArchSpecific(158) handled inline.
#[inline]
fn translate_x86_64(nr: usize) -> crate::syscall::Syscall {
    use crate::syscall::Syscall;
    // x86_64 arch_prctl
    if nr == 158 { return Syscall::ArchSpecific(nr); }
    SYSCALL_TABLE_X86.get(nr).copied().unwrap_or(Syscall::Unknown(nr))
}

/// Compile-time syscall number → Syscall enum table for x86_64 Linux.
/// Index = Linux syscall number. Unknown entries are Syscall::Unknown(0)
/// (never returned — translate_x86_64 uses .get() which returns None for gaps).
const SYSCALL_TABLE_X86: [crate::syscall::Syscall; 335] = {
    use crate::syscall::Syscall;
    let u = Syscall::Unknown(0); // placeholder for gaps
    let mut t = [u; 335];
    // File I/O
    t[0] = Syscall::Read;        t[1] = Syscall::Write;
    t[19] = Syscall::Readv;
    t[2] = Syscall::Open;        t[3] = Syscall::Close;
    t[4] = Syscall::Stat;        t[5] = Syscall::Fstat;
    t[6] = Syscall::Lstat;       t[7] = Syscall::Poll;
    t[8] = Syscall::Lseek;       t[16] = Syscall::Ioctl;
    t[17] = Syscall::Pread64;    t[20] = Syscall::Writev;
    t[22] = Syscall::Pipe2;      t[32] = Syscall::Dup;
    t[33] = Syscall::Dup2;       t[40] = Syscall::Sendfile;
    t[72] = Syscall::Fcntl;      t[292] = Syscall::Dup2; // dup3
    t[293] = Syscall::Pipe2;     // pipe2
    // File metadata
    t[21] = Syscall::Access;     t[78] = Syscall::Getdents64;
    t[217] = Syscall::Getdents64;
    // Memory
    t[9] = Syscall::Mmap;        t[10] = Syscall::Mprotect;
    t[11] = Syscall::Munmap;     t[12] = Syscall::Brk;
    // Signals
    t[13] = Syscall::Sigaction;  t[14] = Syscall::Sigprocmask;
    t[15] = Syscall::Sigreturn;  t[131] = Syscall::Sigaltstack;
    // Filesystem mounting
    t[165] = Syscall::Mount;     t[166] = Syscall::Umount;
    // Additional
    t[318] = Syscall::Getrandom; t[229] = Syscall::ClockGetres;
    t[292] = Syscall::Dup3;      t[156] = Syscall::Sysctl;
    t[73] = Syscall::Flock;
    t[38] = Syscall::SetItimer;
    t[270] = Syscall::Pselect6;
    t[230] = Syscall::ClockNanosleep;
    t[23] = Syscall::Pselect6;  // select() — same handler works
    t[81] = Syscall::Fchdir;
    // Sockets
    t[41] = Syscall::Socket;     t[42] = Syscall::Connect;
    t[44] = Syscall::Sendto;     t[45] = Syscall::Recvfrom;
    t[49] = Syscall::Bind;       t[54] = Syscall::Setsockopt;
    t[55] = Syscall::Getsockopt;
    t[51] = Syscall::Getsockname; t[52] = Syscall::Getpeername;
    t[46] = Syscall::Sendmsg;     t[47] = Syscall::Recvmsg;
    t[48] = Syscall::Shutdown;
    t[307] = Syscall::Sendmmsg;  t[299] = Syscall::Recvmmsg;
    // Process
    t[24] = Syscall::SchedYield; t[35] = Syscall::Nanosleep;
    t[37] = Syscall::Alarm;      t[39] = Syscall::Getpid;
    t[60] = Syscall::Exit;       t[61] = Syscall::Wait4;
    t[62] = Syscall::Kill;       t[63] = Syscall::Uname;
    t[110] = Syscall::Getppid;   t[231] = Syscall::ExitGroup;
    // Directory / path ops
    t[79] = Syscall::Getcwd;     t[80] = Syscall::Chdir;
    t[82] = Syscall::Rename;     t[264] = Syscall::Renameat;
    t[316] = Syscall::Renameat; // renameat2 → same handler (ignores flags arg)
    t[83] = Syscall::Mkdir;      t[86] = Syscall::Link;
    t[265] = Syscall::Linkat;    t[87] = Syscall::Unlink;
    t[88] = Syscall::Symlink;    t[266] = Syscall::Symlinkat;
    t[89] = Syscall::Readlink;   t[267] = Syscall::Readlinkat;
    t[258] = Syscall::Mkdirat;   t[263] = Syscall::Unlinkat;
    t[260] = Syscall::Fchownat;  t[268] = Syscall::Fchmodat;
    t[257] = Syscall::OpenAt;    t[262] = Syscall::FstatAt;
    t[269] = Syscall::Faccessat; t[280] = Syscall::Utimensat;
    // Permissions
    t[90] = Syscall::Chmod;      t[91] = Syscall::Fchmod;
    t[92] = Syscall::Chown;      t[93] = Syscall::Fchown;
    // User/group IDs
    t[102] = Syscall::Getuid;    t[104] = Syscall::Getgid;
    t[107] = Syscall::Geteuid;   t[108] = Syscall::Getegid;
    t[105] = Syscall::Setuid;    t[106] = Syscall::Setgid;
    t[113] = Syscall::Setreuid;  t[114] = Syscall::Setregid;
    t[115] = Syscall::Getgroups; t[116] = Syscall::Getgroups;
    // Process groups
    t[109] = Syscall::Setpgid;   t[111] = Syscall::Getpgid;
    t[112] = Syscall::Setsid;    t[121] = Syscall::Getpgid;
    // Time / info
    t[96] = Syscall::Gettimeofday; t[97] = Syscall::Getrlimit;
    t[99] = Syscall::Sysinfo;    t[228] = Syscall::ClockGettime;
    t[137] = Syscall::Statfs;    t[138] = Syscall::Statfs;
    // Linux extensions
    t[157] = Syscall::Prctl;     t[186] = Syscall::Gettid;
    t[200] = Syscall::Tkill;     t[202] = Syscall::Futex;
    t[204] = Syscall::SchedGetaffinity;
    t[218] = Syscall::SetTidAddress;
    t[273] = Syscall::SetRobustList;
    t[302] = Syscall::Prlimit64; t[334] = Syscall::Rseq;
    t
};

pub fn handle_syscall(_vector: u64, _error_code: u64, frame: *mut u8) {
    unsafe {
        let regs = frame as *mut u64;
        let nr = *regs.add(14);   // RAX = syscall number
        let a0 = *regs.add(9);    // RDI
        let a1 = *regs.add(10);   // RSI
        let a2 = *regs.add(11);   // RDX

        // Exec uses generic implementation
        let result: i64 = match nr {
            59 => { crate::syscall::generic_exec::<super::X86_64>(a0 as usize, a1 as usize); }
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

// setjmp/longjmp in pure assembly for correctness
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
    #[allow(dead_code)]
    const ARCH_GET_FS: u64 = 0x1003;
    #[allow(dead_code)]
    const ARCH_GET_GS: u64 = 0x1004;

    unsafe {
        match code {
            ARCH_SET_FS => {
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
        let kt = CURRENT_KSTACK_TOP as usize;
        for i in 0..15 {
            VFORK_PARENT_REGS[i] = core::ptr::read_volatile((kt - (i + 1) * 8) as *const u64);
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
        let kt = CURRENT_KSTACK_TOP as usize;
        for i in 0..15 {
            core::ptr::write_volatile((kt - (i + 1) * 8) as *mut u64, VFORK_PARENT_REGS[i]);
        }
        // Override RAX slot with child PID (return value)
        core::ptr::write_volatile((kt - 9 * 8) as *mut u64, return_val as u64);
        SAVED_USER_RSP = user_sp as u64;

        let pop_rsp = (kt - 15 * 8) as u64;
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

