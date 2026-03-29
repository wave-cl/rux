/// Syscall handlers for x86_64.
/// Supports both INT 0x80 (rux-box) and SYSCALL instruction (Linux ABI).

use super::gdt::{USER_CS, USER_DS};
use super::serial;

// ── SYSCALL instruction setup (Linux x86_64 ABI) ───────────────────

/// Kernel stack for syscall entry (used when switching from user RSP).
/// 64KB should be plenty for the syscall handler call chain.
static mut SYSCALL_STACK: [u8; 65536] = [0; 65536];

/// Saved user RSP during syscall (single-process, no swapgs needed).
static mut SAVED_USER_RSP: u64 = 0;

/// Debug: last RCX value before sysretq
pub static mut DEBUG_RCX: u64 = 0;
/// Debug: FS base before sysretq
pub static mut DEBUG_FS: u64 = 0;

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

    serial::write_str("rux: SYSCALL MSRs initialized\n");
}

/// Assembly entry point for the SYSCALL instruction.
/// On entry: RCX=user_RIP, R11=user_RFLAGS, RAX=syscall_nr
/// Args: RDI, RSI, RDX, R10 (not RCX!), R8, R9
#[unsafe(naked)]
unsafe extern "C" fn syscall_entry() {
    core::arch::naked_asm!(
        // Switch to kernel stack (save user RSP)
        "mov [rip + {saved_user_rsp}], rsp",
        "lea rsp, [{syscall_stack} + 65536]",

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
        syscall_stack = sym SYSCALL_STACK,
        handler = sym syscall_dispatch_linux,
    );
}

/// Rust dispatch for Linux x86_64 syscall ABI.
/// Called from the assembly entry point with syscall number and arguments.
#[no_mangle]
extern "C" fn syscall_dispatch_linux(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> i64 {
    // Keep interrupts disabled during syscall handling for now
    // (enabling would require saving/restoring more state on timer IRQ)

    let mut nb = [0u8; 10]; let _ = nb;

    use crate::syscall_impl::{posix, linux};

    let result = match nr {
        // ── POSIX.1 syscalls ────────────────────────────────────────
        0 => posix::read(a0, a1, a2),
        1 => posix::write(a0, a1, a2),
        2 => posix::open(a0),
        3 => posix::close(a0),
        4 => posix::stat(a0, a1),
        5 => posix::fstat(a0, a1),
        6 => posix::stat(a0, a1),              // lstat (no symlink distinction)
        7 => 1,                                 // poll
        8 => posix::lseek(a0, a1 as i64, a2),
        9 => posix::mmap(a0, a1, a2, a3, a4),
        10 => 0,                                // mprotect
        11 => 0,                                // munmap
        13 => posix::sigaction(a0, a1, a2),
        14 => posix::sigprocmask(a0, a1, a2, a3),
        16 => posix::ioctl(a0, a1, a2),
        20 => posix::writev(a0, a1, a2),
        21 => 0,                                // access
        24 => 0,                                // sched_yield
        33 => posix::dup2(a0, a1),
        35 => 0,                                // nanosleep
        37 => 0,                                // alarm
        39 => 1,                                // getpid
        48 => 0,                                // shutdown
        50 => -95,                              // listen
        // fork/exec — arch-specific entry, POSIX semantics
        56 => syscall_vfork_linux(),            // clone (as vfork)
        57 => syscall_vfork_linux(),            // fork (as vfork)
        59 => { unsafe { syscall_exec(a0, a1); } 0 } // execve
        60 => posix::exit(a0 as i32),           // _exit
        62 => 0,                                // kill
        63 => posix::uname(a0),
        72 => 0,                                // fcntl
        79 => posix::getcwd(a0, a1),
        80 => 0,                                // chdir
        83 => posix::mkdir(a0),
        87 => posix::unlink(a0),
        96 => crate::syscall_impl::arch::ticks() as i64,
        97 => 0,                                // getrlimit
        102 => 0, 104 => 0, 107 => 0, 108 => 0, // uid/gid
        109 => 0,                               // setpgid
        110 => 1,                               // getppid
        111 => 1,                               // getpgrp
        112 => 1,                               // setsid
        228 => posix::clock_gettime(a0, a1),
        257 => posix::openat(a0, a1),
        262 => posix::fstatat(a0, a1, a2),      // newfstatat
        269 => 0,                               // faccessat

        // ── Linux extensions ────────────────────────────────────────
        12 => linux::brk(a0),
        61 => linux::wait4(a0, a1, a2, a3),
        78 => linux::getdents64(a0, a1, a2),
        121 => 1,                               // getpgid
        131 => -38,                             // sigaltstack
        157 => 0,                               // prctl
        186 => 1,                               // gettid
        200 => 0, 202 => 0, 204 => 0,          // tkill/futex/sched
        217 => linux::getdents64(a0, a1, a2),
        218 => linux::set_tid_address(a0),
        231 => linux::exit_group(a0 as i32),
        273 => 0,                               // set_robust_list
        293 => -38, 302 => -38, 334 => -38,    // pipe2/prlimit64/rseq

        // ── x86_64-specific ─────────────────────────────────────────
        158 => syscall_arch_prctl(a0, a1),

        _ => {
            serial::write_str("rux: unknown syscall ");
            let mut buf = [0u8; 10];
            serial::write_str(crate::write_u32(&mut buf, nr as u32));
            serial::write_str("\n");
            -38
        }
    };

    result
}

pub fn handle_syscall(_vector: u64, _error_code: u64, frame: *mut u8) {
    unsafe {
        use crate::syscall_impl::{posix, linux};

        let regs = frame as *mut u64;
        let syscall_nr = *regs.add(14); // RAX
        let arg0 = *regs.add(9);        // RDI
        let arg1 = *regs.add(10);       // RSI
        let arg2 = *regs.add(11);       // RDX

        let result: i64 = match syscall_nr {
            0 => posix::read(arg0, arg1, arg2),
            1 => posix::write(arg0, arg1, arg2),
            2 => posix::open(arg0),
            3 => posix::close(arg0),
            8 => posix::creat(arg0),
            83 => posix::mkdir(arg0),
            87 => posix::unlink(arg0),
            39 => 1, // getpid
            96 => super::pit::ticks() as i64,
            57 => syscall_vfork(regs),
            59 => { syscall_exec(arg0, arg1); 0 }
            60 => posix::exit(arg0 as i32),
            61 => linux::wait4(arg0, arg1, arg2, 0),
            78 => linux::getdents64(arg0, arg1, arg2),
            _ => -38,
        };

        *regs.add(14) = result as u64;
    }
}

/// vfork — saves parent context, returns 0 to child.
/// When child calls exit(), longjmp restores parent context
/// and vfork returns the child PID to the parent.
fn syscall_vfork(regs: *mut u64) -> i64 {
    unsafe {
        serial::write_str("rux: vfork()\n");

        // Save the parent's entire interrupt frame before the child runs.
        // The child's syscalls will overwrite this kernel stack area.
        for i in 0..22 {
            SAVED_PARENT_FRAME[i] = *regs.add(i);
        }

        // setjmp: save callee-saved registers + RSP + return address
        let val = vfork_setjmp(&raw mut VFORK_JMP);
        if val == 0 {
            // First return: child path. Set RAX=0 in the frame.
            *regs.add(14) = 0;
            return 0; // iretq will return to user mode as child with RAX=0
        } else {
            // Second return (from longjmp in exit): parent path.
            // Restore the parent's page table (exec replaced it)
            if SAVED_CR3 != 0 {
                core::arch::asm!("mov cr3, {}", in(reg) SAVED_CR3, options(nostack));
            }
            serial::write_str("rux: vfork parent resumed\n");

            // Clear vfork state so exit() doesn't longjmp again
            VFORK_JMP.rsp = 0;

            // Restore the parent's interrupt frame (child's syscalls overwrote it)
            for i in 0..22 {
                *regs.add(i) = SAVED_PARENT_FRAME[i];
            }
            // Set RAX in the frame to the child PID (vfork return value for parent)
            *regs.add(14) = val as u64;

            return val; // child PID (also written to frame above)
        }
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

/// Check if a vfork parent is waiting.
pub fn vfork_jmp_active() -> bool {
    unsafe { VFORK_JMP.rsp != 0 }
}

/// Resume the vfork parent with the given child PID. Does not return.
pub unsafe fn vfork_longjmp_to_parent(child_pid: i64) -> ! {
    vfork_longjmp(&raw mut VFORK_JMP, child_pid);
}

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

// Saved CR3 from before exec, so the parent can restore its page table
static mut SAVED_CR3: u64 = 0;

// Saved parent interrupt frame (22 u64s: 15 GPRs + vector + error_code + RIP + CS + RFLAGS + RSP + SS)
// The child's syscalls overwrite the kernel stack, so we must save/restore the parent's frame.
static mut SAVED_PARENT_FRAME: [u64; 22] = [0; 22];

fn syscall_exec(path_ptr: u64, argv_ptr: u64) -> ! {
    unsafe {
        use rux_mm::FrameAllocator;
        use rux_vfs::{FileSystem, InodeStat};

        let fs = crate::kstate::fs();
        let alloc = crate::kstate::alloc();

        let path_cstr = path_ptr as *const u8;
        let mut path_len = 0usize;
        while *path_cstr.add(path_len) != 0 && path_len < 256 { path_len += 1; }
        let path = core::slice::from_raw_parts(path_cstr, path_len);

        // Read full argv[] and envp[] from user memory
        crate::execargs::set_from_user(path, argv_ptr, 0);

        serial::write_str("rux: exec(\"");
        serial::write_bytes(path);
        serial::write_str("\")\n");

        let ino = match rux_vfs::path::resolve_path(fs, path) {
            Ok(ino) => ino,
            Err(_) => { serial::write_str("rux: exec: not found\n"); loop {} }
        };

        // Save current CR3 so the parent can restore its page table after exec
        core::arch::asm!("mov {}, cr3", out(reg) SAVED_CR3, options(nostack));

        // Free previous child's pages and mark subsequent allocs as child.
        // The parent's page table is preserved via SAVED_CR3.
        crate::pgtrack::begin_child(alloc);

        serial::write_str("rux: entering user mode...\n");
        crate::elf::load_elf_from_inode(ino as u64, alloc);
    }
}

#[unsafe(naked)]
pub extern "C" fn enter_user_mode(entry: u64, user_stack: u64) -> ! {
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

fn syscall_arch_prctl(code: u64, addr: u64) -> i64 {
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

/// vfork entry from the SYSCALL instruction path.
/// This is trickier because we need to save/restore the syscall frame.
/// vfork from the SYSCALL instruction path.
///
/// The SYSCALL asm entry pushes: RCX(user_rip), R11(user_rflags), RBX, RBP,
/// R12-R15, then RAX, RDI, RSI, RDX, R10, R8, R9 (15 total).
/// After `call handler`, the handler returns and the asm pops everything.
///
/// For vfork, we need to preserve these across the child's execution.
/// The setjmp/longjmp saves callee-saved regs + RSP + return address,
/// which is enough to return from this function back to the dispatch,
/// which returns to the asm, which pops and sysretqs.
///
/// The trick: the asm pops from SYSCALL_STACK. The child's syscalls use
/// the SAME SYSCALL_STACK and overwrite the parent's saved registers.
/// So we must save the ENTIRE SYSCALL_STACK content and restore it.
/// Saved parent register state from SYSCALL_STACK for vfork resume.
/// All 15 pushed registers + user RSP.
static mut VFORK_PARENT_REGS: [u64; 15] = [0; 15];
static mut VFORK_PARENT_USER_RSP: u64 = 0;

#[inline(never)]
fn syscall_vfork_linux() -> i64 {
    unsafe {
        serial::write_str("rux: vfork()\n");

        // Save ALL 15 pushed registers from SYSCALL_STACK entry.
        // Push order: rcx r11 rbx rbp r12 r13 r14 r15 rax rdi rsi rdx r10 r8 r9
        // Index:       0   1   2   3   4   5   6   7   8   9  10  11  12  13  14
        let stack_top = SYSCALL_STACK.as_ptr().add(65536) as *const u64;
        for i in 0..15 {
            VFORK_PARENT_REGS[i] = *stack_top.sub(i + 1);
        }
        VFORK_PARENT_USER_RSP = SAVED_USER_RSP;

        crate::syscall_impl::CHILD_AVAILABLE = true;

        let val = vfork_setjmp(&raw mut VFORK_JMP);
        if val == 0 {
            // Child path: give it a COPY of the parent's stack so it doesn't
            // corrupt the parent's stack between fork-return and execve.
            use rux_mm::FrameAllocator;
            let alloc = crate::kstate::alloc();

            // Copy 4 pages of the parent's stack for the child, starting from
            // the page containing RSP downward. This prevents the child from
            // corrupting the parent's stack between vfork return and execve.
            let parent_rsp = SAVED_USER_RSP;
            let parent_page_base = parent_rsp & !0xFFF;
            let child_stack_pages = 4u64;
            let child_va_base = 0x7FFE_0000u64; // well below parent stack

            let mut cr3: u64;
            core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack));
            let mut upt = crate::x86_64::paging::PageTable4Level::from_cr3(
                rux_klib::PhysAddr::new(cr3 as usize));
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

            // Adjust RSP: same offset from page base, but in the child VA range
            let offset_in_page = parent_rsp - parent_page_base;
            let child_top_va = child_va_base + (child_stack_pages - 1) * 4096;
            SAVED_USER_RSP = child_top_va + offset_in_page;

            return 0; // child gets fork return 0, runs on child stack
        } else {
            // Parent resumed
            if SAVED_CR3 != 0 {
                core::arch::asm!("mov cr3, {}", in(reg) SAVED_CR3, options(nostack));
            }
            serial::write_str("rux: vfork parent resumed\n");
            VFORK_JMP.rsp = 0;

            // Restore ALL user registers by writing them back to SYSCALL_STACK
            // and then using the normal asm pop path.
            // Write saved regs back to the SYSCALL_STACK top area.
            let stack_top = SYSCALL_STACK.as_mut_ptr().add(65536) as *mut u64;
            for i in 0..15 {
                *stack_top.sub(i + 1) = VFORK_PARENT_REGS[i];
            }
            // Override RAX slot with child PID (return value)
            *stack_top.sub(9) = val as u64; // index 8 = RAX slot
            SAVED_USER_RSP = VFORK_PARENT_USER_RSP;

            // Now switch to SYSCALL_STACK at the point after all 15 pushes,
            // and execute the pop sequence + sysretq from the normal asm path.
            let pop_rsp = stack_top.sub(15) as u64;
            core::arch::asm!(
                "mov rsp, {rsp}",
                // Pop args (reverse of push: r9, r8, r10, rdx, rsi, rdi, rax)
                "pop r9",
                "pop r8",
                "pop r10",
                "pop rdx",
                "pop rsi",
                "pop rdi",
                "pop rax",   // child PID return value
                // Pop callee-saved (reverse: r15, r14, r13, r12, rbp, rbx, r11, rcx)
                "pop r15",
                "pop r14",
                "pop r13",
                "pop r12",
                "pop rbp",
                "pop rbx",
                "pop r11",   // user RFLAGS
                "pop rcx",   // user RIP
                // Restore user RSP
                "mov rsp, [{saved_user_rsp}]",
                "sysretq",
                rsp = in(reg) pop_rsp,
                saved_user_rsp = sym SAVED_USER_RSP,
                options(noreturn)
            );
        }
    }
}
