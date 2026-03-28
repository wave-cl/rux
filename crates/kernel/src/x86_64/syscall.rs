/// Syscall handlers for x86_64.
/// Supports both INT 0x80 (rux-box) and SYSCALL instruction (Linux ABI).

use super::gdt::{USER_CS, USER_DS, KERNEL_CS};
use super::serial;

// ── SYSCALL instruction setup (Linux x86_64 ABI) ───────────────────

/// Kernel stack for syscall entry (used when switching from user RSP).
/// 64KB should be plenty for the syscall handler call chain.
static mut SYSCALL_STACK: [u8; 65536] = [0; 65536];

/// Saved user RSP during syscall (single-process, no swapgs needed).
static mut SAVED_USER_RSP: u64 = 0;

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

        // RAX has return value
        "add rsp, 56",    // pop arg saves

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

    let result = match nr {
        // File I/O
        0 => syscall_read(a0, a1, a2),           // read
        1 => syscall_write(a0, a1, a2),           // write
        2 => syscall_open(a0),                     // open
        3 => crate::fdtable::sys_close(a0 as usize), // close
        5 => syscall_fstat(a0, a1),               // fstat
        8 => syscall_creat(a0),                    // creat
        9 => syscall_mmap(a0, a1, a2, a3, a4),   // mmap
        10 => 0,                                   // mprotect (stub)
        11 => 0,                                   // munmap (stub)
        12 => syscall_brk(a0),                    // brk
        13 => syscall_rt_sigaction(a0, a1, a2),   // rt_sigaction
        14 => 0,                                   // rt_sigprocmask (stub)
        16 => syscall_ioctl(a0, a1, a2),          // ioctl
        20 => syscall_writev(a0, a1, a2),         // writev
        21 => 0,                                   // access (stub: always OK)
        33 => -38,                                 // dup2 (TODO)
        39 => 1,                                   // getpid
        56 => { unsafe { syscall_vfork_from_linux(); } 0 } // clone (as vfork)
        57 => { unsafe { syscall_vfork_from_linux(); } 0 } // fork (as vfork)
        59 => { unsafe { syscall_exec(a0, a1); } 0 } // execve
        60 => unsafe { syscall_exit(a0 as i32) }, // exit
        61 => syscall_wait(),                      // wait4
        63 => syscall_uname(a0),                   // uname
        72 => 0,                                   // fcntl (stub)
        78 => syscall_getdents(a0, a1),           // getdents
        79 => syscall_getcwd(a0, a1),             // getcwd
        80 => 0,                                   // chdir (stub)
        83 => unsafe { syscall_mkdir(a0) as i64 },// mkdir
        87 => unsafe { syscall_unlink(a0) as i64 },// unlink
        96 => super::pit::ticks() as i64,         // gettimeofday
        102 => 0,                                  // getuid
        104 => 0,                                  // getgid
        107 => 0,                                  // geteuid
        108 => 0,                                  // getegid
        110 => 1,                                  // getppid
        158 => syscall_arch_prctl(a0, a1),            // arch_prctl
        217 => syscall_getdents(a0, a1),          // getdents64
        218 => 1,                                  // set_tid_address → return pid
        228 => syscall_clock_gettime(a0, a1),     // clock_gettime
        231 => unsafe { syscall_exit(a0 as i32) },// exit_group
        257 => syscall_openat(a0, a1),            // openat
        262 => syscall_fstatat(a0, a1, a2),       // newfstatat
        269 => 0,                                  // faccessat (stub)
        293 => -38,                                // pipe2 (TODO)
        302 => -38,                                // prlimit64 (stub)
        334 => -38,                                // rseq (stub)
        _ => {
            serial::write_str("rux: unknown syscall ");
            let mut buf = [0u8; 10];
            serial::write_str(crate::write_u32(&mut buf, nr as u32));
            serial::write_str("\n");
            -38 // -ENOSYS
        }
    };

    // Interrupts already disabled (SFMASK clears IF on syscall entry)
    result
}

pub fn handle_syscall(_vector: u64, _error_code: u64, frame: *mut u8) {
    unsafe {
        let regs = frame as *mut u64;
        let syscall_nr = *regs.add(14); // RAX
        let arg0 = *regs.add(9);        // RDI
        let arg1 = *regs.add(10);       // RSI
        let arg2 = *regs.add(11);       // RDX

        let result: i64 = match syscall_nr {
            0 => syscall_read(arg0, arg1, arg2),
            1 => syscall_write(arg0, arg1, arg2),
            2 => syscall_open(arg0),
            3 => crate::fdtable::sys_close(arg0 as usize),
            8 => syscall_creat(arg0), // creat
            83 => syscall_mkdir(arg0), // mkdir
            87 => syscall_unlink(arg0), // unlink
            39 => 1, // getpid
            96 => super::pit::ticks() as i64, // gettimeofday → ticks
            57 => syscall_vfork(regs),
            59 => { syscall_exec(arg0, arg1); 0 }
            60 => syscall_exit(arg0 as i32),
            61 => syscall_wait(),
            78 => syscall_getdents(arg0, arg1),
            _ => -38,
        };

        *regs.add(14) = result as u64;
    }
}

fn syscall_read(fd: u64, buf: u64, len: u64) -> i64 {
    if fd == 0 {
        // stdin: read from serial
        unsafe {
            let ptr = buf as *mut u8;
            for i in 0..len as usize {
                *ptr.add(i) = serial::read_byte();
            }
        }
        return len as i64;
    }
    // File fd
    crate::fdtable::sys_read_fd(fd as usize, buf as *mut u8, len as usize)
}

fn syscall_open(path_ptr: u64) -> i64 {
    unsafe {
        let cstr = path_ptr as *const u8;
        let mut len = 0usize;
        while *cstr.add(len) != 0 && len < 256 { len += 1; }
        let path = core::slice::from_raw_parts(cstr, len);
        crate::fdtable::sys_open(path)
    }
}

fn syscall_write(fd: u64, buf: u64, len: u64) -> i64 {
    if fd == 1 || fd == 2 {
        // stdout/stderr → serial
        unsafe {
            let ptr = buf as *const u8;
            for i in 0..len as usize { serial::write_byte(*ptr.add(i)); }
        }
        return len as i64;
    }
    // File fd
    crate::fdtable::sys_write_fd(fd as usize, buf as *const u8, len as usize)
}

/// Resolve a path to (parent_inode, basename).
/// E.g. "/bin/ls" → (inode_of_bin, b"ls"), "/foo" → (root, b"foo")
unsafe fn resolve_parent_and_name(path_ptr: u64) -> Result<(rux_vfs::InodeId, &'static [u8]), i64> {
    use rux_vfs::FileSystem;
    let cstr = path_ptr as *const u8;
    let mut len = 0usize;
    while *cstr.add(len) != 0 && len < 256 { len += 1; }
    let path = core::slice::from_raw_parts(cstr, len);

    // Find the last '/' to split into parent path and basename
    let mut last_slash = 0;
    for j in 0..len {
        if path[j] == b'/' { last_slash = j; }
    }

    let fs = crate::kstate::fs();
    if last_slash == 0 {
        // Path like "/foo" — parent is root, name is everything after '/'
        let name = &path[1..];
        Ok((fs.root_inode(), name))
    } else {
        // Path like "/bin/ls" — resolve parent "/bin", name is "ls"
        let parent_path = &path[..last_slash];
        let name = &path[last_slash + 1..];
        match rux_vfs::path::resolve_path(fs, parent_path) {
            Ok(parent_ino) => Ok((parent_ino, name)),
            Err(_) => Err(-2), // -ENOENT
        }
    }
}

fn syscall_creat(path_ptr: u64) -> i64 {
    unsafe {
        use rux_vfs::{FileSystem, FileName};

        let (dir_ino, name) = match resolve_parent_and_name(path_ptr) {
            Ok(v) => v,
            Err(e) => return e,
        };

        let fs = crate::kstate::fs();
        let fname = match FileName::new(name) {
            Ok(f) => f,
            Err(_) => return -22,
        };

        match fs.create(dir_ino, fname, 0o644) {
            Ok(_ino) => {
                // Auto-open the created file
                let cstr = path_ptr as *const u8;
                let mut len = 0usize;
                while *cstr.add(len) != 0 && len < 256 { len += 1; }
                crate::fdtable::sys_open(core::slice::from_raw_parts(cstr, len))
            }
            Err(_) => -17,
        }
    }
}

fn syscall_mkdir(path_ptr: u64) -> i64 {
    unsafe {
        use rux_vfs::{FileSystem, FileName};

        let (dir_ino, name) = match resolve_parent_and_name(path_ptr) {
            Ok(v) => v,
            Err(e) => return e,
        };

        let fs = crate::kstate::fs();
        let fname = match FileName::new(name) {
            Ok(f) => f,
            Err(_) => return -22,
        };

        match fs.mkdir(dir_ino, fname, 0o755) {
            Ok(_) => 0,
            Err(_) => -17,
        }
    }
}

fn syscall_unlink(path_ptr: u64) -> i64 {
    unsafe {
        use rux_vfs::{FileSystem, FileName};

        let (dir_ino, name) = match resolve_parent_and_name(path_ptr) {
            Ok(v) => v,
            Err(e) => return e,
        };

        let fs = crate::kstate::fs();
        let fname = match FileName::new(name) {
            Ok(f) => f,
            Err(_) => return -22,
        };

        match fs.unlink(dir_ino, fname) {
            Ok(()) => 0,
            Err(_) => -2, // -ENOENT
        }
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

fn syscall_exec(path_ptr: u64, arg_ptr: u64) -> ! {
    unsafe {
        use rux_mm::FrameAllocator;
        use rux_vfs::{FileSystem, InodeStat};

        let fs = crate::kstate::fs();
        let alloc = crate::kstate::alloc();

        let path_cstr = path_ptr as *const u8;
        let mut path_len = 0usize;
        while *path_cstr.add(path_len) != 0 && path_len < 256 { path_len += 1; }
        let path = core::slice::from_raw_parts(path_cstr, path_len);

        // Read optional argument
        let arg = if arg_ptr != 0 {
            let arg_cstr = arg_ptr as *const u8;
            let mut arg_len = 0usize;
            while *arg_cstr.add(arg_len) != 0 && arg_len < 256 { arg_len += 1; }
            core::slice::from_raw_parts(arg_cstr, arg_len)
        } else {
            &[]
        };

        // Store path + arg for the new process's stack
        crate::execargs::set(path, arg);

        serial::write_str("rux: exec(\"");
        serial::write_bytes(path);
        serial::write_str("\")\n");

        let ino = match rux_vfs::path::resolve_path(fs, path) {
            Ok(ino) => ino,
            Err(_) => { serial::write_str("rux: exec: not found\n"); loop {} }
        };

        // Save current CR3 so the parent can restore its page table after exec
        core::arch::asm!("mov {}, cr3", out(reg) SAVED_CR3, options(nostack));

        // Free previous child's pages — but NOT if inside a vfork
        if VFORK_JMP.rsp == 0 {
            crate::pgtrack::begin_child(alloc);
        }

        serial::write_str("rux: entering user mode...\n");
        crate::elf::load_elf_from_inode(ino as u64, alloc);
    }
}

fn syscall_exit(status: i32) -> ! {
    serial::write_str("rux: user exit(");
    let mut buf = [0u8; 10];
    serial::write_str(crate::write_u32(&mut buf, status as u32));
    serial::write_str(")\n");

    unsafe {
        // If parent is blocked in vfork, resume it with child PID
        if VFORK_JMP.rsp != 0 {
            vfork_longjmp(&raw mut VFORK_JMP, 42); // child PID = 42
        }
    }

    crate::x86_64::exit::exit_qemu(crate::x86_64::exit::EXIT_SUCCESS);
}

/// getdents(buf, bufsize) — list root directory entries into user buffer.
/// Writes null-terminated filenames consecutively. Returns bytes written.
fn syscall_getdents(buf_ptr: u64, bufsize: u64) -> i64 {
    unsafe {
        use rux_vfs::{FileSystem, DirEntry};

        let fs = crate::kstate::fs();
        let out = buf_ptr as *mut u8;
        let mut pos = 0usize;
        let mut offset = 0usize;
        let limit = bufsize as usize;

        loop {
            let mut entry = core::mem::zeroed::<DirEntry>();
            match fs.readdir(0, offset, &mut entry) {
                Ok(true) => {
                    let nlen = entry.name_len as usize;
                    if pos + nlen + 1 > limit { break; }
                    for i in 0..nlen {
                        *out.add(pos + i) = entry.name[i];
                    }
                    *out.add(pos + nlen) = b'\n';
                    pos += nlen + 1;
                    offset += 1;
                }
                _ => break,
            }
        }
        pos as i64
    }
}

fn syscall_wait() -> i64 {
    // vfork semantics: child already ran to completion before parent resumes.
    // The child PID was returned by vfork. Nothing to wait for.
    serial::write_str("rux: wait() (child already exited)\n");
    42
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

// ── Linux-specific syscall implementations ──────────────────────────

/// Program break for brk() syscall.
static mut PROGRAM_BRK: u64 = 0;

fn syscall_brk(addr: u64) -> i64 {
    unsafe {
        if PROGRAM_BRK == 0 {
            // Initialize to a reasonable default (end of data segment area)
            PROGRAM_BRK = 0x800000; // 8 MiB — well above typical ELF segments
        }
        if addr == 0 {
            return PROGRAM_BRK as i64;
        }
        if addr > PROGRAM_BRK {
            // Grow: map new pages in the user page table
            // For now, just track the break — pages are identity-mapped
            // or will fault and need a proper page fault handler.
            // TODO: actually map pages
            PROGRAM_BRK = addr;
        }
        PROGRAM_BRK as i64
    }
}

fn syscall_mmap(addr: u64, len: u64, _prot: u64, flags: u64, _fd: u64) -> i64 {
    // Minimal mmap stub: for anonymous private mappings, bump a counter
    unsafe {
        static mut MMAP_BASE: u64 = 0x10000000; // start at 256 MiB
        let map_flags = flags;
        let _ = addr;
        // MAP_ANONYMOUS = 0x20, MAP_PRIVATE = 0x02
        if map_flags & 0x20 != 0 {
            let aligned_len = (len + 0xFFF) & !0xFFF;
            let result = MMAP_BASE;
            MMAP_BASE += aligned_len;
            // TODO: actually map pages
            return result as i64;
        }
        -12 // -ENOMEM
    }
}

fn syscall_rt_sigaction(_signum: u64, _act: u64, _oldact: u64) -> i64 {
    // Stub: accept any signal handler setup, don't actually deliver signals
    0
}

fn syscall_ioctl(fd: u64, request: u64, arg: u64) -> i64 {
    // Terminal ioctls
    const TCGETS: u64 = 0x5401;
    const TIOCGWINSZ: u64 = 0x5413;
    const TIOCSPGRP: u64 = 0x5410;
    const TIOCGPGRP: u64 = 0x540F;

    match request {
        TIOCGWINSZ => {
            // Return window size: 24 rows, 80 cols
            if arg != 0 {
                unsafe {
                    let ws = arg as *mut [u16; 4]; // rows, cols, xpixel, ypixel
                    (*ws) = [24, 80, 0, 0];
                }
            }
            0
        }
        TCGETS => {
            // Return a zeroed termios (raw mode)
            if arg != 0 {
                unsafe {
                    let ptr = arg as *mut u8;
                    for i in 0..60 { *ptr.add(i) = 0; }
                }
            }
            0
        }
        _ => -25 // -ENOTTY
    }
}

fn syscall_writev(fd: u64, iov_ptr: u64, iovcnt: u64) -> i64 {
    // Gather write: iov is an array of { base: *const u8, len: usize }
    unsafe {
        let iov = iov_ptr as *const [u64; 2]; // [base, len] pairs
        let mut total: i64 = 0;
        for i in 0..iovcnt as usize {
            let base = (*iov.add(i))[0];
            let len = (*iov.add(i))[1];
            let n = syscall_write(fd, base, len);
            if n < 0 { return n; }
            total += n;
        }
        total
    }
}

fn syscall_fstat(_fd: u64, buf: u64) -> i64 {
    // Return a minimal stat struct (zeroed, regular file)
    if buf != 0 {
        unsafe {
            let ptr = buf as *mut u8;
            for i in 0..144 { *ptr.add(i) = 0; } // sizeof(struct stat) = 144
            // st_mode at offset 24: regular file + 0644
            let mode_ptr = (buf + 24) as *mut u32;
            *mode_ptr = 0o100644;
            // st_blksize at offset 56
            let blksz_ptr = (buf + 56) as *mut u64;
            *blksz_ptr = 4096;
        }
    }
    0
}

fn syscall_fstatat(_dirfd: u64, pathname: u64, buf: u64) -> i64 {
    // newfstatat: resolve path and stat it
    // For now, treat like fstat with basic info
    syscall_fstat(0, buf)
}

fn syscall_openat(_dirfd: u64, pathname: u64) -> i64 {
    // openat with AT_FDCWD (-100): just open the path
    syscall_open(pathname)
}

fn syscall_uname(buf: u64) -> i64 {
    // struct utsname: 5 fields of 65 bytes each = 325 bytes
    // sysname, nodename, release, version, machine
    if buf == 0 { return -14; }
    unsafe {
        let ptr = buf as *mut u8;
        for i in 0..325 { *ptr.add(i) = 0; }
        // sysname
        let s = b"Linux";
        for (i, &b) in s.iter().enumerate() { *ptr.add(i) = b; }
        // nodename (offset 65)
        let s = b"rux";
        for (i, &b) in s.iter().enumerate() { *ptr.add(65 + i) = b; }
        // release (offset 130)
        let s = b"6.1.0-rux";
        for (i, &b) in s.iter().enumerate() { *ptr.add(130 + i) = b; }
        // version (offset 195)
        let s = b"#1 SMP";
        for (i, &b) in s.iter().enumerate() { *ptr.add(195 + i) = b; }
        // machine (offset 260)
        let s = b"x86_64";
        for (i, &b) in s.iter().enumerate() { *ptr.add(260 + i) = b; }
    }
    0
}

fn syscall_getcwd(buf: u64, size: u64) -> i64 {
    if buf == 0 || size < 2 { return -34; }
    unsafe {
        let ptr = buf as *mut u8;
        *ptr = b'/';
        *ptr.add(1) = 0;
    }
    buf as i64
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
                core::arch::asm!(
                    "wrmsr",
                    in("ecx") 0xC0000100u32,
                    in("eax") addr as u32,
                    in("edx") (addr >> 32) as u32,
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

fn syscall_clock_gettime(_clockid: u64, tp: u64) -> i64 {
    if tp == 0 { return -14; }
    let ticks = super::pit::ticks();
    unsafe {
        let sec_ptr = tp as *mut u64;
        let nsec_ptr = (tp + 8) as *mut u64;
        *sec_ptr = ticks / 1000;
        *nsec_ptr = (ticks % 1000) * 1_000_000;
    }
    0
}

/// vfork entry from the SYSCALL instruction path.
/// This is trickier because we need to save/restore the syscall frame.
unsafe fn syscall_vfork_from_linux() -> i64 {
    // For now, just return -38 (ENOSYS) since the busybox shell
    // will fall back to fork behavior. We'll implement this properly
    // once basic busybox execution is confirmed.
    // TODO: proper vfork from syscall context
    -38
}
