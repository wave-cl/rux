/// SVC syscall handler for aarch64.
/// User code does `svc #0` which traps to EL1.
/// Uses aarch64 Linux syscall numbers.

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
        use crate::syscall_impl::{posix, linux};

        let regs = frame as *mut u64;

        // aarch64 syscall convention: x8 = number, x0-x5 = args
        let nr = *regs.add(8);   // x8
        let a0 = *regs.add(0);   // x0
        let a1 = *regs.add(1);   // x1
        let a2 = *regs.add(2);   // x2
        let a3 = *regs.add(3);   // x3
        let a4 = *regs.add(4);   // x4

        let result: i64 = match nr {
            // ── POSIX.1 syscalls (aarch64 Linux numbers) ──────────────

            // File I/O
            56 => posix::openat(a0, a1, a2, a3),      // openat
            57 => posix::close(a0),                   // close
            63 => posix::read(a0, a1, a2),            // read
            64 => posix::write(a0, a1, a2),           // write
            66 => posix::writev(a0, a1, a2),          // writev
            71 => posix::sendfile(a0, a1, a2, a3),    // sendfile
            23 => posix::dup(a0),                     // dup
            24 => posix::dup2(a0, a1),                // dup3 → dup2
            25 => posix::fcntl(a0, a1, a2),            // fcntl
            29 => posix::ioctl(a0, a1, a2),           // ioctl
            62 => posix::lseek(a0, a1 as i64, a2),    // lseek
            59 => linux::pipe2(a0, a1),                // pipe2

            // File metadata
            79 => posix::fstatat(a0, a1, a2),         // newfstatat
            80 => posix::fstat(a0, a1),               // fstat
            78 => posix::stat(a0, a1),                // readlinkat → stat
            48 => 0,                                  // faccessat

            // Directory operations
            17 => posix::getcwd(a0, a1),              // getcwd
            33 => posix::creat(a0),                   // mknodat → creat
            34 => posix::mkdir(a0),                   // mkdirat
            35 => posix::unlink(a0),                  // unlinkat
            49 => posix::chdir(a0),                    // chdir

            // Memory management
            222 => posix::mmap(a0, a1, a2, a3, a4),   // mmap
            215 => 0,                                  // munmap
            226 => 0,                                  // mprotect

            // Process control
            172 => 1,                                  // getpid
            173 => 1,                                  // getppid
            93 => posix::exit(a0 as i32),              // exit
            129 => 0,                                  // kill
            160 => posix::uname(a0),                   // uname

            // User/group IDs
            174 => 0,                                  // getuid
            175 => 0,                                  // geteuid
            176 => 0,                                  // getgid
            177 => 0,                                  // getegid

            // Process groups / sessions
            154 => 0,                                  // setpgid
            155 => 1,                                  // getpgid
            157 => 1,                                  // setsid

            // Signals
            134 => posix::sigaction(a0, a1, a2),       // rt_sigaction
            135 => posix::sigprocmask(a0, a1, a2, a3), // rt_sigprocmask
            132 => -38,                                // sigaltstack

            // Terminal
            113 => posix::clock_gettime(a0, a1),       // clock_gettime
            101 => 0,                                  // nanosleep
            124 => 0,                                  // sched_yield

            // ── Linux extensions ──────────────────────────────────────

            214 => linux::brk(a0),                     // brk
            61 => linux::getdents64(a0, a1, a2),       // getdents64
            260 => linux::wait4(a0, a1, a2, a3),       // wait4
            94 => linux::exit_group(a0 as i32),        // exit_group
            96 => linux::set_tid_address(a0),           // set_tid_address
            178 => 1,                                  // gettid
            167 => 0,                                  // prctl
            99 => 0,                                   // set_robust_list
            98 => 0,                                   // futex
            131 => 0,                                  // tgkill
            130 => 0,                                  // tkill
            123 => 0,                                  // sched_getaffinity
            261 => -38,                                // prlimit64
            293 => -38,                                // rseq
            73 => 1,                                   // ppoll
            169 => super::timer::ticks() as i64,       // gettimeofday (stub)
            163 => 0,                                  // getrlimit

            // ── aarch64-specific (vfork/exec need arch asm) ───────────
            220 => syscall_vfork(regs),                // clone (as vfork)
            221 => { syscall_exec(a0, a1); 0 }         // execve

            _ => {
                serial::write_str("rux: unknown syscall ");
                let mut buf = [0u8; 10];
                serial::write_str(crate::write_u32(&mut buf, nr as u32));
                serial::write_str("\n");
                -38
            }
        };

        // Return value in x0
        *regs.add(0) = result as u64;
    }
}

/// vfork — saves parent context, returns 0 to child.
/// When child calls exit(), longjmp restores parent context
/// and vfork returns the child PID to the parent.
fn syscall_vfork(regs: *mut u64) -> i64 {
    unsafe {
        serial::write_str("rux: vfork()\n");

        for i in 0..FRAME_REGS {
            SAVED_PARENT_FRAME[i] = *regs.add(i);
        }
        SAVED_REGS_PTR = regs;  // save regs pointer (x0 is caller-saved, lost after longjmp)
        core::arch::asm!("mrs {}, sp_el0", out(reg) SAVED_SP_EL0, options(nostack));
        // Save TPIDR_EL0 (TLS base) — musl uses it; child's exec overwrites it
        core::arch::asm!("mrs {}, tpidr_el0", out(reg) SAVED_TPIDR, options(nostack));

        // Save process state that exec resets
        SAVED_MMAP_BASE = crate::syscall_impl::MMAP_BASE;
        SAVED_PROGRAM_BRK = crate::syscall_impl::PROGRAM_BRK;
        static mut SAVED_CWD_INODE: u64 = 0;
        SAVED_CWD_INODE = crate::syscall_impl::CWD_INODE;
        for i in 0..64 { SAVED_FDS[i] = crate::fdtable::FD_TABLE[i]; }

        crate::syscall_impl::CHILD_AVAILABLE = true;

        let val = vfork_setjmp(&raw mut VFORK_JMP);
        if val == 0 {
            crate::syscall_impl::IN_VFORK_CHILD = true;
            // Copy 4 pages of the parent's stack for the child.
            use rux_mm::FrameAllocator;
            let alloc = crate::kstate::alloc();
            let parent_rsp = SAVED_SP_EL0;
            let parent_page_base = parent_rsp & !0xFFF;
            let child_stack_pages = 4u64;
            let child_va_base = 0x7FFD_0000u64;

            let mut ttbr0: u64;
            core::arch::asm!("mrs {}, ttbr0_el1", out(reg) ttbr0, options(nostack));
            let mut upt = crate::aarch64::paging::PageTable4Level::from_cr3(
                rux_klib::PhysAddr::new(ttbr0 as usize));
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

            let offset_in_page = parent_rsp - parent_page_base;
            let child_top_va = child_va_base + (child_stack_pages - 1) * 4096;
            let child_sp = child_top_va + offset_in_page;
            core::arch::asm!("msr sp_el0, {}", in(reg) child_sp, options(nostack));

            *regs.add(0) = 0;
            return 0;
        } else {
            // Second return (from longjmp in exit): parent path.
            // Restore the parent's page table (exec replaced it)
            if SAVED_TTBR0 != 0 {
                // Switch back to parent's page table with full cache maintenance.
                // The child used the same VAs mapped to different PAs.
                // - TLB must be flushed (VA→PA translation changed)
                // - I-cache must be invalidated (VIPT on Cortex-A72, stale entries)
                core::arch::asm!(
                    "msr ttbr0_el1, {}",
                    "isb",
                    "tlbi vmalle1is",
                    "dsb ish",
                    "ic iallu",       // invalidate entire instruction cache
                    "dsb ish",
                    "isb",
                    in(reg) SAVED_TTBR0,
                    options(nostack)
                );
            }
                serial::write_str("rux: vfork parent resumed\n");

            // Clear vfork state so exit() doesn't longjmp again
            VFORK_JMP.sp = 0;

            // Restore SP_EL0 and TPIDR_EL0 (TLS base)
            core::arch::asm!("msr sp_el0, {}", in(reg) SAVED_SP_EL0, options(nostack));
            core::arch::asm!("msr tpidr_el0, {}", in(reg) SAVED_TPIDR, options(nostack));

            // Restore process state that exec reset
            crate::syscall_impl::IN_VFORK_CHILD = false;
            crate::syscall_impl::MMAP_BASE = SAVED_MMAP_BASE;
            crate::syscall_impl::PROGRAM_BRK = SAVED_PROGRAM_BRK;
            crate::syscall_impl::CWD_INODE = SAVED_CWD_INODE;
            for i in 0..64 { crate::fdtable::FD_TABLE[i] = SAVED_FDS[i]; }

            // Restore frame and eret directly (kernel stack is corrupted).
            let frame = SAVED_REGS_PTR;
            for i in 0..FRAME_REGS {
                *frame.add(i) = SAVED_PARENT_FRAME[i];
            }
            *frame.add(0) = val as u64; // x0 = child PID

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

/// Check if a vfork parent is waiting.
pub fn vfork_jmp_active() -> bool {
    unsafe { VFORK_JMP.sp != 0 }
}

/// Resume the vfork parent with the given child PID. Does not return.
pub unsafe fn vfork_longjmp_to_parent(child_pid: i64) -> ! {
    vfork_longjmp(&raw mut VFORK_JMP, child_pid);
}

// Saved parent exception frame (34 u64s)
static mut SAVED_PARENT_FRAME: [u64; FRAME_REGS] = [0; FRAME_REGS];

// Saved parent SP_EL0 (user stack pointer) — not part of exception frame
static mut SAVED_SP_EL0: u64 = 0;

// Saved TTBR0_EL1 from before exec, so the parent can restore its page table
static mut SAVED_TTBR0: u64 = 0;
static mut SAVED_REGS_PTR: *mut u64 = core::ptr::null_mut();
static mut SAVED_TPIDR: u64 = 0;
static mut SAVED_MMAP_BASE: u64 = 0;
static mut SAVED_PROGRAM_BRK: u64 = 0;
static mut SAVED_FDS: [crate::fdtable::OpenFile; 64] = [crate::fdtable::OpenFile {
    ino: 0, offset: 0, flags: 0, active: false, is_serial: false,
    is_pipe: false, pipe_id: 0, pipe_write: false,
}; 64];

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

fn syscall_exec(path_ptr: u64, argv_ptr: u64) -> ! {
    unsafe {
        use rux_vfs::FileSystem;

        // Save TTBR0 FIRST, before any allocations or page table changes.
        // We need the parent's page table root so the parent can restore it.
        core::arch::asm!("mrs {}, ttbr0_el1", out(reg) SAVED_TTBR0, options(nostack));

        let alloc = crate::kstate::alloc();
        let fs = crate::kstate::fs();

        let path_cstr = path_ptr as *const u8;
        let mut path_len = 0usize;
        while *path_cstr.add(path_len) != 0 && path_len < 256 { path_len += 1; }
        let path = core::slice::from_raw_parts(path_cstr, path_len);

        crate::execargs::set_from_user(path, argv_ptr, 0);

        serial::write_str("rux: exec(\"");
        serial::write_bytes(path);
        serial::write_str("\")\n");

        let ino = match rux_vfs::path::resolve_path(fs, path) {
            Ok(ino) => ino,
            Err(_) => { serial::write_str("rux: exec: not found\n"); loop {} }
        };

        // Switch to kernel PT and mark subsequent allocations as child pages.
        crate::pgtrack::begin_child(alloc);

        serial::write_str("rux: entering user mode...\n");
        crate::elf::load_elf_from_inode(ino as u64, alloc);
    }
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
