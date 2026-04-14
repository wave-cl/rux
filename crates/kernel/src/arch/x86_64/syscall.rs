/// Syscall handlers for x86_64.
/// Supports both INT 0x80 (rux-box) and SYSCALL instruction (Linux ABI).

use super::gdt::{USER_CS, USER_DS};
use super::console;

// ── SYSCALL instruction setup (Linux x86_64 ABI) ───────────────────


/// Initialize the SYSCALL/SYSRET MSRs.
pub unsafe fn init_syscall_msrs() {
    // IA32_STAR (0xC0000081): segment selectors
    //   [47:32] = kernel CS (0x08), kernel SS = CS+8 = 0x10
    //   [63:48] = user base (0x10), sysret CS = base+16 = 0x20|3, SS = base+8 = 0x18|3
    let star: u64 = (0x0010u64 << 48) | (0x0008u64 << 32);
    core::arch::asm!("wrmsr", in("ecx") 0xC0000081u32, in("eax") star as u32, in("edx") (star >> 32) as u32);

    // IA32_LSTAR (0xC0000082): SWAPGS-based syscall entry (like Linux)
    let lstar = syscall_entry_gs as *const () as u64;
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

/// SWAPGS-based syscall entry — matches Linux.
/// Uses swapgs + gs:[offset] for per-CPU state. All kernel code
/// reads from this_cpu() — no legacy globals.
#[unsafe(naked)]
unsafe extern "C" fn syscall_entry_gs() {
    core::arch::naked_asm!(
        // swapgs: swap IA32_GS_BASE (user) ↔ IA32_KERNEL_GS_BASE (kernel percpu)
        "swapgs",

        // Save user RSP + 6th arg to per-CPU struct
        "mov gs:[0], rsp",          // percpu.saved_user_rsp
        "mov gs:[8], r9",           // percpu.saved_syscall_a5
        "mov rsp, gs:[16]",         // percpu.syscall_kstack_top

        // Save callee-saved + syscall-specific regs
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

        handler = sym syscall_dispatch_linux,
    );
}

// Fork child return trampoline (SWAPGS-based).
// context_switch retq's here. The child's kernel stack has a full
// syscall register frame. Pops all saved regs (RAX=0), then sysretq.
core::arch::global_asm!(r#"
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
"#, options(att_syntax));

extern "C" {
    pub fn fork_child_sysret_gs();
}

/// Rust dispatch for Linux x86_64 syscall ABI.
/// Called from the assembly entry point with syscall number and arguments.
#[no_mangle]
extern "C" fn syscall_dispatch_linux(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> i64 {
    // Save original syscall number for ERESTARTSYS restart (Linux orig_ax)
    unsafe { crate::percpu::this_cpu().saved_syscall_nr = nr; }

    // Phase 1 coverage: record that this syscall nr was exercised.
    crate::syscall::record_syscall(nr);

    // Process creation syscalls (handled before generic dispatch)
    match nr {
        // 56=clone(flags=rdi, stack=rsi, ptid=rdx, ctid=r10, tls=r8)
        56 => {
            let flags = a0 as usize;
            if flags & crate::errno::CLONE_VM != 0 {
                // Thread: shared address space
                return unsafe { crate::fork::sys_clone(
                    flags, a1 as usize, a2 as usize, a3 as usize, a4 as usize
                ) } as i64;
            }
            return unsafe { crate::fork::sys_fork() } as i64;
        }
        57 | 58 => return unsafe { crate::fork::sys_fork() } as i64,
        59 => { return unsafe { crate::syscall::generic_exec::<super::X86_64>(a0 as usize, a1 as usize, a2 as usize) } as i64; }
        // 322 = execveat(dirfd, path, argv, envp, flags)
        322 => unsafe {
            let dirfd = a0 as i32;
            let path = a1 as usize;
            // Only support AT_FDCWD (-100) or absolute paths
            if path == 0 { return crate::errno::EFAULT as i64; }
            if crate::uaccess::validate_user_ptr(path, 1).is_err() {
                return crate::errno::EFAULT as i64;
            }
            let first: u8 = crate::uaccess::get_user(path);
            if dirfd != -100 && first != b'/' {
                return crate::errno::ENOSYS as i64;
            }
            return crate::syscall::generic_exec::<super::X86_64>(path, a2 as usize, a3 as usize) as i64;
        }
        // 435 = clone3(clone_args, size)
        435 => unsafe {
            let args_ptr = a0 as usize;
            let size = a1 as usize;
            if size < 64 || crate::uaccess::validate_user_ptr(args_ptr, size).is_err() {
                return crate::errno::EINVAL as i64;
            }
            let flags: u64 = crate::uaccess::get_user(args_ptr);
            let ptid: u64 = crate::uaccess::get_user(args_ptr + 24);
            let ctid: u64 = crate::uaccess::get_user(args_ptr + 32);
            let stack: u64 = crate::uaccess::get_user(args_ptr + 40);
            let stack_size: u64 = crate::uaccess::get_user(args_ptr + 48);
            let tls: u64 = crate::uaccess::get_user(args_ptr + 64);
            let sp = if stack != 0 { stack + stack_size } else { 0 };
            if flags & crate::errno::CLONE_VM as u64 != 0 {
                return crate::fork::sys_clone(
                    flags as usize, sp as usize,
                    ptid as usize, ctid as usize, tls as usize
                ) as i64;
            }
            return crate::fork::sys_fork() as i64;
        }
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

    unsafe fn sig_read_user_sp() -> usize {
        let pc = crate::percpu::this_cpu();
        pc.saved_user_rsp as usize
    }

    unsafe fn sig_write_user_sp(sp: usize) {
        let pc = crate::percpu::this_cpu();
        pc.saved_user_rsp = sp as u64;
    }

    unsafe fn sig_write_frame(
        frame_addr: usize, syscall_result: i64,
        blocked_mask: u64, restorer: usize, signum: u8,
    ) {
        let pc = crate::percpu::this_cpu();
        let kt = pc.syscall_kstack_top as usize;
        let saved_rip = core::ptr::read_volatile((kt - 8) as *const u64);
        let saved_rflags = core::ptr::read_volatile((kt - 16) as *const u64);

        let frame = frame_addr as *mut SignalFrameX86;
        (*frame).restorer = restorer as u64;
        (*frame).saved_rip = saved_rip;
        (*frame).saved_rflags = saved_rflags;
        (*frame).saved_rax = syscall_result as u64;
        (*frame).saved_mask = blocked_mask;
        (*frame).signum = signum as u64;
        (*frame).orig_user_sp = pc.saved_user_rsp;
    }

    unsafe fn sig_redirect_to_handler(handler: usize, signum: u8) {
        let kt = crate::percpu::this_cpu().syscall_kstack_top as usize;
        core::ptr::write_volatile((kt - 8) as *mut u64, handler as u64);
        core::ptr::write_volatile((kt - 80) as *mut u64, signum as u64); // RDI = sig
    }

    unsafe fn sig_redirect_to_handler_siginfo(handler: usize, signum: u8, siginfo_ptr: usize) {
        // The C handler signature is:
        //     void handler(int sig, siginfo_t *info, void *ucontext)
        // SysV x86_64 ABI: RDI=sig, RSI=info, RDX=ucontext.
        //
        // syscall_entry_gs pushes registers in this order (relative to
        // syscall_kstack_top / `kt`):
        //   kt-8:   rcx (user RIP → overwritten with handler)
        //   kt-16:  r11 (rflags)
        //   kt-24:  rbx, kt-32: rbp, kt-40: r12, kt-48: r13, kt-56: r14, kt-64: r15
        //   kt-72:  rax (syscall nr, then syscall result)
        //   kt-80:  rdi (arg0) → signum
        //   kt-88:  rsi (arg1) → siginfo_ptr
        //   kt-96:  rdx (arg2) → ucontext (NULL)
        //
        // Prior code wrote siginfo_ptr to kt-72 (RAX) and 0 to kt-64 (R15),
        // which left RSI untouched. When the SIGCHLD handler dereferenced
        // info->field (e.g. si_pid), RSI was whatever leftover it inherited
        // from the syscall args — frequently NULL — causing a faulting load
        // at `NULL + field_offset` (0x11 for si_pid) and killing the shell
        // right after its child exited. This was the ruby post-exit SIGSEGV.
        let kt = crate::percpu::this_cpu().syscall_kstack_top as usize;
        core::ptr::write_volatile((kt - 8) as *mut u64, handler as u64);
        core::ptr::write_volatile((kt - 80) as *mut u64, signum as u64);      // RDI = sig
        core::ptr::write_volatile((kt - 88) as *mut u64, siginfo_ptr as u64); // RSI = info
        core::ptr::write_volatile((kt - 96) as *mut u64, 0u64);               // RDX = ucontext
    }

    unsafe fn sig_restore_frame(frame_addr: usize) -> (i64, u64) {
        let frame = (frame_addr - 8) as *const SignalFrameX86;
        let saved_rip = (*frame).saved_rip;
        let saved_rflags = (*frame).saved_rflags;
        let saved_rax = (*frame).saved_rax;
        let saved_mask = (*frame).saved_mask;
        let orig_user_sp = (*frame).orig_user_sp;

        // Restore user RSP to per-CPU
        let pc = crate::percpu::this_cpu();
        pc.saved_user_rsp = orig_user_sp;

        // Restore RCX (user RIP) and R11 (RFLAGS) on kernel stack
        let kt = pc.syscall_kstack_top as usize;
        core::ptr::write_volatile((kt - 8) as *mut u64, saved_rip);
        core::ptr::write_volatile((kt - 16) as *mut u64, saved_rflags);

        (saved_rax as i64, saved_mask)
    }

    unsafe fn sig_prepare_restart() {
        let pc = crate::percpu::this_cpu();
        let kt = pc.syscall_kstack_top as usize;
        // Decrement saved RIP by 2 (x86_64 SYSCALL instruction length)
        let rip = core::ptr::read_volatile((kt - 8) as *const u64);
        core::ptr::write_volatile((kt - 8) as *mut u64, rip - 2);
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

/// Linux user_regs_struct size on x86_64 (27 u64 = 216 bytes).
pub const USER_REGS_SIZE: usize = 216;

/// Read user register state at the time of the current syscall into the
/// caller's buffer (Linux user_regs_struct layout, 27 u64). Used by
/// PTRACE_GETREGS for self-introspection.
pub unsafe fn read_user_regs(buf: *mut u64) {
    let pc = crate::percpu::this_cpu();
    let kt = pc.syscall_kstack_top as usize;
    let read = |off: usize| core::ptr::read_volatile((kt - off) as *const u64);
    let saved_rip = read(8);
    let saved_rflags = read(16);
    let rbx = read(24);
    let rbp = read(32);
    let r12 = read(40);
    let r13 = read(48);
    let r14 = read(56);
    let r15 = read(64);
    let rax = read(72);
    let rdi = read(80);
    let rsi = read(88);
    let rdx = read(96);
    let r10 = read(104);
    let r8  = read(112);
    let r9  = read(120);
    let rsp = pc.saved_user_rsp as u64;
    let tls = crate::task_table::TASK_TABLE[crate::task_table::current_task_idx()].tls;
    // Linux user_regs_struct order
    *buf.add(0)  = r15;
    *buf.add(1)  = r14;
    *buf.add(2)  = r13;
    *buf.add(3)  = r12;
    *buf.add(4)  = rbp;
    *buf.add(5)  = rbx;
    *buf.add(6)  = saved_rflags; // r11 == RFLAGS at sysret time
    *buf.add(7)  = r10;
    *buf.add(8)  = r9;
    *buf.add(9)  = r8;
    *buf.add(10) = rax;       // ax (current syscall result, post-call)
    *buf.add(11) = saved_rip; // cx == saved RIP at sysret time
    *buf.add(12) = rdx;
    *buf.add(13) = rsi;
    *buf.add(14) = rdi;
    *buf.add(15) = rax;       // orig_ax (syscall number when entered)
    *buf.add(16) = saved_rip; // ip
    *buf.add(17) = 0x33;      // cs (user code segment)
    *buf.add(18) = saved_rflags; // flags
    *buf.add(19) = rsp;       // sp
    *buf.add(20) = 0x2B;      // ss (user data segment)
    *buf.add(21) = tls;       // fs_base
    *buf.add(22) = 0;         // gs_base
    *buf.add(23) = 0;         // ds
    *buf.add(24) = 0;         // es
    *buf.add(25) = 0;         // fs
    *buf.add(26) = 0;         // gs
}

/// Write user register state from a Linux user_regs_struct buffer.
/// Used by PTRACE_SETREGS for self-introspection.
pub unsafe fn write_user_regs(buf: *const u64) {
    let pc = crate::percpu::this_cpu();
    let kt = pc.syscall_kstack_top as usize;
    let write = |off: usize, v: u64| core::ptr::write_volatile((kt - off) as *mut u64, v);
    write(64,  *buf.add(0));   // r15
    write(56,  *buf.add(1));   // r14
    write(48,  *buf.add(2));   // r13
    write(40,  *buf.add(3));   // r12
    write(32,  *buf.add(4));   // rbp
    write(24,  *buf.add(5));   // rbx
    write(104, *buf.add(7));   // r10
    write(120, *buf.add(8));   // r9
    write(112, *buf.add(9));   // r8
    write(72,  *buf.add(10));  // rax
    write(96,  *buf.add(12));  // rdx
    write(88,  *buf.add(13));  // rsi
    write(80,  *buf.add(14));  // rdi
    write(8,   *buf.add(16));  // saved RIP
    write(16,  *buf.add(18));  // saved RFLAGS
    pc.saved_user_rsp = *buf.add(19); // rsp
}

/// Compile-time syscall number → Syscall enum table for x86_64 Linux.
/// Index = Linux syscall number. Unknown entries are Syscall::Unknown(0)
/// (never returned — translate_x86_64 uses .get() which returns None for gaps).
const SYSCALL_TABLE_X86: [crate::syscall::Syscall; 437] = {
    use crate::syscall::Syscall;
    let u = Syscall::Unknown(0); // placeholder for gaps
    let mut t = [u; 437];
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
    t[271] = Syscall::Ppoll2;       // ppoll
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
    t[316] = Syscall::Renameat2;
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
    t[137] = Syscall::Statfs;    t[138] = Syscall::Fstatfs;
    // Linux extensions
    t[157] = Syscall::Prctl;     t[186] = Syscall::Gettid;
    t[200] = Syscall::Tkill;     t[202] = Syscall::Futex;
    t[204] = Syscall::SchedGetaffinity;
    t[218] = Syscall::SetTidAddress;
    t[273] = Syscall::SetRobustList;
    t[302] = Syscall::Prlimit64; t[334] = Syscall::Rseq;
    // Phase 1 stubs
    t[98] = Syscall::Getrusage;  t[140] = Syscall::GetPriority;
    t[141] = Syscall::SetPriority; t[95] = Syscall::Umask;
    t[116] = Syscall::SetGroups;
    t[74] = Syscall::Fsync;      t[75] = Syscall::Fdatasync;
    t[162] = Syscall::Sync;      t[306] = Syscall::Syncfs;
    t[285] = Syscall::Fallocate;
    t[191] = Syscall::Getxattr;  t[188] = Syscall::Setxattr;
    t[193] = Syscall::Fgetxattr; t[190] = Syscall::Fsetxattr;
    t[192] = Syscall::Lgetxattr; t[189] = Syscall::Lsetxattr;
    t[194] = Syscall::Listxattr; t[196] = Syscall::Flistxattr;
    t[195] = Syscall::Llistxattr;
    t[197] = Syscall::Removexattr; t[199] = Syscall::Fremovexattr;
    t[198] = Syscall::Lremovexattr;
    t[125] = Syscall::Capget;    t[126] = Syscall::Capset;
    t[135] = Syscall::Personality; t[317] = Syscall::Seccomp;
    t[219] = Syscall::RestartSyscall; t[324] = Syscall::Membarrier;
    // Phase 2 wrappers
    t[18] = Syscall::Pwrite64;   t[77] = Syscall::Ftruncate;
    t[76] = Syscall::Truncate;   t[84] = Syscall::Rmdir;
    t[22] = Syscall::Pipe;       t[124] = Syscall::Getsid;
    // Phase 3 epoll
    t[213] = Syscall::EpollCreate; t[291] = Syscall::EpollCreate1;
    t[233] = Syscall::EpollCtl; t[232] = Syscall::EpollWait;
    t[281] = Syscall::EpollPwait;
    // Phase 4 server sockets
    t[50] = Syscall::Listen;     t[43] = Syscall::Accept;
    t[288] = Syscall::Accept4;
    // Phase 5 event/timer fds + signalfd
    t[289] = Syscall::Signalfd4;
    t[290] = Syscall::Eventfd2;
    t[283] = Syscall::TimerfdCreate; t[286] = Syscall::TimerfdSettime;
    t[287] = Syscall::TimerfdGettime;
    // Batch 2: memory
    t[28] = Syscall::Madvise;    t[27] = Syscall::Mincore;
    t[25] = Syscall::Mremap;     t[26] = Syscall::Msync;
    t[149] = Syscall::Mlock;     t[150] = Syscall::Munlock;
    t[151] = Syscall::Mlockall;  t[152] = Syscall::Munlockall;
    // Batch 2: signals
    t[127] = Syscall::SigPending; t[128] = Syscall::SigTimedwait;
    t[129] = Syscall::SigQueueinfo; t[297] = Syscall::TgSigQueueinfo;
    // Batch 2: splice
    t[275] = Syscall::Splice;    t[278] = Syscall::Vmsplice;
    t[276] = Syscall::Tee;
    // Batch 2: process
    t[148] = Syscall::SchedGetparam; t[142] = Syscall::SchedSetparam;
    t[145] = Syscall::SchedGetscheduler; t[144] = Syscall::SchedSetscheduler;
    t[203] = Syscall::SchedSetaffinity;
    t[118] = Syscall::Getresuid; t[120] = Syscall::Getresgid;
    t[117] = Syscall::Setresuid; t[119] = Syscall::Setresgid;
    // Batch 2: filesystem
    t[161] = Syscall::Chroot;    t[155] = Syscall::PivotRoot;
    t[221] = Syscall::Fadvise;
    t[253] = Syscall::Inotify;   t[254] = Syscall::InotifyAddWatch;
    t[255] = Syscall::InotifyRmWatch;
    // Batch 2: misc
    t[103] = Syscall::Syslog;    t[169] = Syscall::Reboot;
    t[171] = Syscall::Setdomainname; t[170] = Syscall::Sethostname;
    t[34] = Syscall::Pause;      t[36] = Syscall::Getitimer;
    t[94] = Syscall::Lchown;
    t[122] = Syscall::Setfsuid;  t[123] = Syscall::Setfsgid;
    t[319] = Syscall::MemfdCreate; t[326] = Syscall::CopyFileRange;
    t[332] = Syscall::Statx;
    // Batch 3: POSIX IPC
    t[64] = Syscall::Semget;     t[65] = Syscall::Semop;
    t[66] = Syscall::Semctl;     t[29] = Syscall::Shmget;
    t[30] = Syscall::Shmat;      t[67] = Syscall::Shmdt;
    t[31] = Syscall::Shmctl;     t[68] = Syscall::Msgget;
    t[69] = Syscall::Msgsnd;     t[70] = Syscall::Msgrcv;
    t[71] = Syscall::Msgctl;
    // Batch 3: process
    t[435] = Syscall::Clone3;    t[247] = Syscall::Waitid;
    t[322] = Syscall::Execveat;  t[310] = Syscall::ProcessVmReadv;
    t[311] = Syscall::ProcessVmWritev; t[101] = Syscall::Ptrace;
    // Batch 3: resource limits
    t[160] = Syscall::Setrlimit;
    // Batch 3: timer/clock
    t[227] = Syscall::ClockSettime; t[222] = Syscall::TimerCreate;
    t[223] = Syscall::TimerSettime; t[224] = Syscall::TimerGettime;
    t[225] = Syscall::TimerGetoverrun; t[226] = Syscall::TimerDelete;
    // Batch 3: filesystem
    t[187] = Syscall::Readahead; t[179] = Syscall::Quotactl;
    t[303] = Syscall::NameToHandleAt; t[304] = Syscall::OpenByHandleAt;
    // Batch 3: misc
    t[312] = Syscall::Kcmp;
    t[434] = Syscall::Pidfd;     t[424] = Syscall::PidfdSendSignal;
    t[425] = Syscall::IoUringSetup; t[426] = Syscall::IoUringEnter;
    t[427] = Syscall::IoUringRegister;
    t[436] = Syscall::Close2;    // close_range
    t[53] = Syscall::Socketpair;
    t
};

/// INT 0x80 handler — legacy syscall path. Extracts all 6 args from the
/// interrupt frame and delegates to the same dispatch as the SYSCALL path.
pub fn handle_syscall(_vector: u64, _error_code: u64, frame: *mut u8) {
    unsafe {
        let regs = frame as *mut u64;
        // Frame layout: R15[0] R14[1] R13[2] R12[3] R11[4] R10[5] R9[6] R8[7]
        //               RBP[8] RDI[9] RSI[10] RDX[11] RCX[12] RBX[13] RAX[14]
        let nr = *regs.add(14);   // RAX
        let a0 = *regs.add(9);    // RDI
        let a1 = *regs.add(10);   // RSI
        let a2 = *regs.add(11);   // RDX
        let a3 = *regs.add(5);    // R10
        let a4 = *regs.add(7);    // R8
        let _a5 = *regs.add(6);   // R9 (unused — vfork passes ≤5 args)

        let result = syscall_dispatch_linux(nr, a0, a1, a2, a3, a4);
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
"#, options(att_syntax));

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
        let kt = crate::percpu::this_cpu().syscall_kstack_top as usize;
        for i in 0..15 {
            VFORK_PARENT_REGS[i] = core::ptr::read_volatile((kt - (i + 1) * 8) as *const u64);
        }
    }

    unsafe fn save_user_sp() -> usize {
        crate::percpu::this_cpu().saved_user_rsp as usize
    }

    unsafe fn set_user_sp(sp: usize) {
        crate::percpu::this_cpu().saved_user_rsp = sp as u64;
    }

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
        let kt = crate::percpu::this_cpu().syscall_kstack_top as usize;
        for i in 0..15 {
            core::ptr::write_volatile((kt - (i + 1) * 8) as *mut u64, VFORK_PARENT_REGS[i]);
        }
        // Override RAX slot with child PID (return value)
        core::ptr::write_volatile((kt - 9 * 8) as *mut u64, return_val as u64);
        // Store user SP in per-CPU for gs:[0] restore
        crate::percpu::this_cpu().saved_user_rsp = user_sp as u64;

        let pop_rsp = (kt - 15 * 8) as u64;
        core::arch::asm!(
            "mov rsp, {rsp}",
            "pop r9", "pop r8", "pop r10", "pop rdx", "pop rsi", "pop rdi", "pop rax",
            "pop r15", "pop r14", "pop r13", "pop r12", "pop rbp", "pop rbx",
            "pop r11", "pop rcx",
            "mov rsp, gs:[0]",  // restore user RSP from per-CPU
            "swapgs",
            "sysretq",
            rsp = in(reg) pop_rsp,
            options(noreturn)
        );
    }
}

/// Saved parent register state from kernel stack for VforkContext.
/// All 15 pushed registers (used by save_regs/restore_and_return_to_user).
static mut VFORK_PARENT_REGS: [u64; 15] = [0; 15];

