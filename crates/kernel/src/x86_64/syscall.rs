/// INT 0x80 syscall handler for x86_64.

use super::gdt::{USER_CS, USER_DS};
use super::serial;

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

fn syscall_creat(path_ptr: u64) -> i64 {
    unsafe {
        use rux_vfs::{FileSystem, FileName};

        let cstr = path_ptr as *const u8;
        let mut len = 0usize;
        while *cstr.add(len) != 0 && len < 256 { len += 1; }

        // Extract filename from path (skip leading '/')
        let name_start = if len > 0 && *cstr == b'/' { 1 } else { 0 };
        let name = core::slice::from_raw_parts(cstr.add(name_start), len - name_start);

        let fs = crate::kstate::fs();
        let fname = match FileName::new(name) {
            Ok(f) => f,
            Err(_) => return -22, // -EINVAL
        };

        match fs.create(0, fname, 0o644) {
            Ok(ino) => {
                // Auto-open the created file
                crate::fdtable::sys_open(core::slice::from_raw_parts(cstr, len))
            }
            Err(_) => -17, // -EEXIST or other error
        }
    }
}

fn syscall_unlink(path_ptr: u64) -> i64 {
    unsafe {
        use rux_vfs::{FileSystem, FileName};

        let cstr = path_ptr as *const u8;
        let mut len = 0usize;
        while *cstr.add(len) != 0 && len < 256 { len += 1; }

        let name_start = if len > 0 && *cstr == b'/' { 1 } else { 0 };
        let name = core::slice::from_raw_parts(cstr.add(name_start), len - name_start);

        let fs = crate::kstate::fs();
        let fname = match FileName::new(name) {
            Ok(f) => f,
            Err(_) => return -22,
        };

        match fs.unlink(0, fname) {
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

        let mut stat = core::mem::zeroed::<InodeStat>();
        fs.stat(ino, &mut stat).unwrap();
        let size = stat.size as usize;

        let buf_page = alloc.alloc(rux_mm::PageSize::FourK).expect("exec buf");
        let buf = core::slice::from_raw_parts_mut(buf_page.as_usize() as *mut u8, 4096);
        let n = fs.read(ino, 0, &mut buf[..size.min(4096)]).unwrap_or(0);

        // Save current CR3 so the parent can restore its page table after exec
        core::arch::asm!("mov {}, cr3", out(reg) SAVED_CR3, options(nostack));

        // Free previous child's pages before allocating new ones
        crate::pgtrack::begin_child(alloc);

        serial::write_str("rux: entering user mode...\n");
        crate::elf::load_and_exec_elf(&buf[..n], alloc);
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
