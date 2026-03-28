/// SVC syscall handler for aarch64.
/// User code does `svc #0` which traps to EL1.
/// Uses aarch64 Linux syscall numbers: write=64, exit=93, vfork=220, execve=221, wait4=260.

use super::serial;

/// Exception frame layout from exception.S save_context:
///   regs[0..30] = x0..x29  (each 8 bytes)
///   regs[30] = x30 (lr)
///   regs[31] = elr_el1 (user return address)
///   regs[32] = spsr_el1
/// Total: 34 u64s (272 bytes)
const FRAME_REGS: usize = 34;

/// Handle SVC from user mode. Called from exception_dispatch.
pub fn handle_syscall(frame: *mut u8) {
    unsafe {
        let regs = frame as *mut u64;

        // aarch64 syscall convention: x8 = number, x0-x5 = args
        let syscall_nr = *regs.add(8);  // x8
        let arg0 = *regs.add(0);        // x0
        let arg1 = *regs.add(1);        // x1
        let arg2 = *regs.add(2);        // x2

        let result: i64 = match syscall_nr {
            35 => syscall_creat(arg0),                   // unlinkat → creat (repurposed)
            56 => syscall_open(arg0),                   // openat (path in x0)
            57 => crate::fdtable::sys_close(arg0 as usize), // close
            61 => syscall_getdents(arg0, arg1),        // getdents64
            63 => syscall_read(arg0, arg1, arg2),    // read
            64 => syscall_write(arg0, arg1, arg2),  // write
            93 => syscall_exit(arg0 as i32),          // exit
            169 => super::timer::ticks() as i64,     // gettimeofday → ticks
            220 => syscall_vfork(regs),               // vfork
            221 => { syscall_exec(arg0, arg1); 0 }     // execve
            260 => syscall_wait(),                     // wait4
            _ => -38, // -ENOSYS
        };

        // Return value in x0
        *regs.add(0) = result as u64;
    }
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

/// read(fd, buf, len) — fd=0 reads from serial, fd>=3 reads from file.
fn syscall_read(fd: u64, buf: u64, len: u64) -> i64 {
    if fd == 0 {
        unsafe {
            let ptr = buf as *mut u8;
            for i in 0..len as usize {
                *ptr.add(i) = serial::read_byte();
            }
        }
        return len as i64;
    }
    crate::fdtable::sys_read_fd(fd as usize, buf as *mut u8, len as usize)
}

/// write(fd, buf, len) — fd=1/2 writes to serial, fd>=3 writes to file.
fn syscall_write(fd: u64, buf: u64, len: u64) -> i64 {
    if fd == 1 || fd == 2 {
        unsafe {
            let ptr = buf as *const u8;
            for i in 0..len as usize {
                serial::write_byte(*ptr.add(i));
            }
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

        let name_start = if len > 0 && *cstr == b'/' { 1 } else { 0 };
        let name = core::slice::from_raw_parts(cstr.add(name_start), len - name_start);

        let fs = crate::kstate::fs();
        let fname = match FileName::new(name) {
            Ok(f) => f,
            Err(_) => return -22,
        };

        match fs.create(0, fname, 0o644) {
            Ok(_ino) => {
                crate::fdtable::sys_open(core::slice::from_raw_parts(cstr, len))
            }
            Err(_) => -17,
        }
    }
}

/// vfork — saves parent context, returns 0 to child.
/// When child calls exit(), longjmp restores parent context
/// and vfork returns the child PID to the parent.
fn syscall_vfork(regs: *mut u64) -> i64 {
    unsafe {
        serial::write_str("rux: vfork()\n");

        // Save the parent's entire exception frame before the child runs.
        // The child's syscalls will overwrite this kernel stack area.
        for i in 0..FRAME_REGS {
            SAVED_PARENT_FRAME[i] = *regs.add(i);
        }
        // Save SP_EL0 (not part of exception frame, but enter_user_mode overwrites it)
        core::arch::asm!("mrs {}, sp_el0", out(reg) SAVED_SP_EL0, options(nostack));

        // setjmp: save callee-saved registers + SP + return address
        let val = vfork_setjmp(&raw mut VFORK_JMP);
        if val == 0 {
            // First return: child path. Set x0=0 in the frame.
            *regs.add(0) = 0;
            return 0; // eret will return to user mode as child with x0=0
        } else {
            // Second return (from longjmp in exit): parent path.
            // Restore the parent's page table (exec replaced it)
            if SAVED_TTBR0 != 0 {
                core::arch::asm!(
                    "msr ttbr0_el1, {}",
                    "isb",
                    "tlbi vmalle1is",
                    "dsb ish",
                    "isb",
                    in(reg) SAVED_TTBR0,
                    options(nostack)
                );
            }
            serial::write_str("rux: vfork parent resumed\n");

            // Clear vfork state so exit() doesn't longjmp again
            VFORK_JMP.sp = 0;

            // Restore SP_EL0 (enter_user_mode set it to the child's stack)
            core::arch::asm!("msr sp_el0, {}", in(reg) SAVED_SP_EL0, options(nostack));

            // Restore the parent's exception frame (child's syscalls overwrote it)
            for i in 0..FRAME_REGS {
                *regs.add(i) = SAVED_PARENT_FRAME[i];
            }
            // Set x0 in the frame to the child PID (vfork return value for parent)
            *regs.add(0) = val as u64;

            return val; // child PID
        }
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

// Saved parent exception frame (34 u64s)
static mut SAVED_PARENT_FRAME: [u64; FRAME_REGS] = [0; FRAME_REGS];

// Saved parent SP_EL0 (user stack pointer) — not part of exception frame
static mut SAVED_SP_EL0: u64 = 0;

// Saved TTBR0_EL1 from before exec, so the parent can restore its page table
static mut SAVED_TTBR0: u64 = 0;

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

        // Read ELF from VFS
        let buf_page = alloc.alloc(rux_mm::PageSize::FourK).expect("exec buf");
        let buf = core::slice::from_raw_parts_mut(buf_page.as_usize() as *mut u8, 4096);
        let n = fs.read(ino, 0, &mut buf[..size.min(4096)]).unwrap_or(0);

        // Save current TTBR0 so the parent can restore its page table after exec
        core::arch::asm!("mrs {}, ttbr0_el1", out(reg) SAVED_TTBR0, options(nostack));

        serial::write_str("rux: entering user mode...\n");
        crate::elf::load_and_exec_elf(&buf[..n], alloc);
    }
}

/// getdents(buf, bufsize) — list root directory entries into user buffer.
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

fn syscall_exit(status: i32) -> ! {
    serial::write_str("rux: user exit(");
    let mut buf = [0u8; 10];
    serial::write_str(crate::write_u32(&mut buf, status as u32));
    serial::write_str(")\n");

    unsafe {
        // If parent is blocked in vfork, resume it with child PID
        if VFORK_JMP.sp != 0 {
            vfork_longjmp(&raw mut VFORK_JMP, 42); // child PID = 42
        }
    }

    crate::aarch64::exit::exit_qemu(crate::aarch64::exit::EXIT_SUCCESS);
}

fn syscall_wait() -> i64 {
    // vfork semantics: child already ran to completion before parent resumes.
    serial::write_str("rux: wait() (child already exited)\n");
    42
}

/// Enter user mode (EL0) via eret.
/// Sets ELR_EL1 = entry, SP_EL0 = user_stack, SPSR_EL1 = 0 (EL0t).
pub unsafe fn enter_user_mode(entry: u64, user_stack: u64) -> ! {
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
