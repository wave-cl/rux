//! Minimal Rust runtime for rux userspace programs.
//!
//! Provides syscall wrappers, a startup stub, and helpers.
//! Programs link against this crate and define `extern "C" fn main(argc, argv)`.

#![no_std]

// ── Architecture-specific syscall ABI ───────────────────────────────

#[cfg(target_arch = "x86_64")]
mod numbers {
    pub const READ: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const OPEN: u64 = 2;
    pub const CLOSE: u64 = 3;
    pub const CREAT: u64 = 8;
    pub const MKDIR: u64 = 83;
    pub const UNLINK: u64 = 87;
    pub const GETPID: u64 = 39;
    pub const GETTIME: u64 = 96;
    pub const VFORK: u64 = 57;
    pub const EXECVE: u64 = 59;
    pub const EXIT: u64 = 60;
    pub const WAIT: u64 = 61;
    pub const GETDENTS: u64 = 78;
}

#[cfg(target_arch = "aarch64")]
mod numbers {
    pub const READ: u64 = 63;
    pub const WRITE: u64 = 64;
    pub const OPEN: u64 = 56;
    pub const CLOSE: u64 = 57;
    pub const CREAT: u64 = 33;
    pub const MKDIR: u64 = 34;
    pub const UNLINK: u64 = 35;
    pub const GETPID: u64 = 172;
    pub const GETTIME: u64 = 169;
    pub const VFORK: u64 = 220;
    pub const EXECVE: u64 = 221;
    pub const EXIT: u64 = 93;
    pub const WAIT: u64 = 260;
    pub const GETDENTS: u64 = 61;
}

// ── Raw syscall primitives ──────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod raw {
    #[inline(always)]
    pub unsafe fn syscall0(nr: u64) -> i64 {
        let r: i64;
        core::arch::asm!("int 0x80", inlateout("rax") nr => r, options(nostack));
        r
    }
    #[inline(always)]
    pub unsafe fn syscall1(nr: u64, a0: u64) -> i64 {
        let r: i64;
        core::arch::asm!("int 0x80", inlateout("rax") nr => r, in("rdi") a0, options(nostack));
        r
    }
    #[inline(always)]
    pub unsafe fn syscall2(nr: u64, a0: u64, a1: u64) -> i64 {
        let r: i64;
        core::arch::asm!("int 0x80", inlateout("rax") nr => r, in("rdi") a0, in("rsi") a1, options(nostack));
        r
    }
    #[inline(always)]
    pub unsafe fn syscall3(nr: u64, a0: u64, a1: u64, a2: u64) -> i64 {
        let r: i64;
        core::arch::asm!("int 0x80", inlateout("rax") nr => r, in("rdi") a0, in("rsi") a1, in("rdx") a2, options(nostack));
        r
    }
}

#[cfg(target_arch = "aarch64")]
mod raw {
    #[inline(always)]
    pub unsafe fn syscall0(nr: u64) -> i64 {
        let r: i64;
        core::arch::asm!("svc #0", in("x8") nr, lateout("x0") r, options(nostack));
        r
    }
    #[inline(always)]
    pub unsafe fn syscall1(nr: u64, a0: u64) -> i64 {
        let r: i64;
        core::arch::asm!("svc #0", in("x8") nr, inlateout("x0") a0 => r, options(nostack));
        r
    }
    #[inline(always)]
    pub unsafe fn syscall2(nr: u64, a0: u64, a1: u64) -> i64 {
        let r: i64;
        core::arch::asm!("svc #0", in("x8") nr, inlateout("x0") a0 => r, in("x1") a1, options(nostack));
        r
    }
    #[inline(always)]
    pub unsafe fn syscall3(nr: u64, a0: u64, a1: u64, a2: u64) -> i64 {
        let r: i64;
        core::arch::asm!("svc #0", in("x8") nr, inlateout("x0") a0 => r, in("x1") a1, in("x2") a2, options(nostack));
        r
    }
}

// ── Public syscall API ──────────────────────────────────────────────

pub fn exit(code: i32) -> ! {
    unsafe { raw::syscall1(numbers::EXIT, code as u64); }
    loop {}
}

pub fn write(fd: u32, buf: &[u8]) -> isize {
    unsafe { raw::syscall3(numbers::WRITE, fd as u64, buf.as_ptr() as u64, buf.len() as u64) as isize }
}

pub fn read(fd: u32, buf: &mut [u8]) -> isize {
    unsafe { raw::syscall3(numbers::READ, fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64) as isize }
}

/// Open a file. `path` must be null-terminated.
pub fn open(path: &[u8]) -> isize {
    unsafe { raw::syscall1(numbers::OPEN, path.as_ptr() as u64) as isize }
}

pub fn close(fd: u32) -> isize {
    unsafe { raw::syscall1(numbers::CLOSE, fd as u64) as isize }
}

/// Create a file. `path` must be null-terminated. Returns fd.
pub fn creat(path: &[u8]) -> isize {
    unsafe { raw::syscall1(numbers::CREAT, path.as_ptr() as u64) as isize }
}

/// Create a directory. `path` must be null-terminated.
pub fn mkdir(path: &[u8]) -> isize {
    unsafe { raw::syscall1(numbers::MKDIR, path.as_ptr() as u64) as isize }
}

/// Unlink (delete) a file. `path` must be null-terminated.
pub fn unlink(path: &[u8]) -> isize {
    unsafe { raw::syscall1(numbers::UNLINK, path.as_ptr() as u64) as isize }
}

pub fn getdents(buf: &mut [u8]) -> isize {
    unsafe { raw::syscall2(numbers::GETDENTS, buf.as_mut_ptr() as u64, buf.len() as u64) as isize }
}

pub fn getpid() -> i32 {
    unsafe { raw::syscall0(numbers::GETPID) as i32 }
}

pub fn ticks() -> u64 {
    unsafe { raw::syscall0(numbers::GETTIME) as u64 }
}

/// vfork — returns 0 in child, child PID in parent.
pub fn vfork() -> i64 {
    unsafe { raw::syscall0(numbers::VFORK) }
}

/// execve(path, arg) — path and arg must be null-terminated.
/// arg may be null (pass empty slice or b"\0").
pub fn execve(path: &[u8], arg: &[u8]) -> ! {
    let arg_ptr = if arg.is_empty() || (arg.len() == 1 && arg[0] == 0) {
        0u64
    } else {
        arg.as_ptr() as u64
    };
    unsafe { raw::syscall2(numbers::EXECVE, path.as_ptr() as u64, arg_ptr); }
    loop {} // unreachable if exec succeeds
}

/// wait — returns child PID.
pub fn wait() -> i64 {
    unsafe { raw::syscall0(numbers::WAIT) }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Print a string to stdout.
pub fn print(s: &str) {
    write(1, s.as_bytes());
}

/// Print a string followed by newline.
pub fn println(s: &str) {
    print(s);
    write(1, b"\n");
}

/// Print a byte slice to stdout.
pub fn print_bytes(b: &[u8]) {
    write(1, b);
}

/// Print a u64 as decimal.
pub fn print_u64(mut n: u64) {
    if n == 0 {
        write(1, b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 20;
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    write(1, &buf[i..]);
}

/// Read a line from stdin into buf. Returns bytes read (excluding newline).
pub fn read_line(buf: &mut [u8]) -> usize {
    let mut pos = 0;
    let mut byte = [0u8; 1];
    loop {
        if read(0, &mut byte) != 1 { break; }
        if byte[0] == b'\n' || byte[0] == b'\r' {
            write(1, b"\n");
            break;
        }
        // Echo
        write(1, &byte);
        if pos < buf.len() {
            buf[pos] = byte[0];
            pos += 1;
        }
    }
    pos
}

/// Extract basename from a path (everything after the last '/').
pub fn basename(path: &[u8]) -> &[u8] {
    let mut last = 0;
    for i in 0..path.len() {
        if path[i] == b'/' { last = i + 1; }
    }
    &path[last..]
}

/// Build a null-terminated path string: prefix + name.
/// Returns the total length (including null terminator).
pub fn build_path(out: &mut [u8], prefix: &[u8], name: &[u8]) -> usize {
    let mut p = 0;
    for &b in prefix {
        if p < out.len() { out[p] = b; p += 1; }
    }
    for &b in name {
        if p < out.len() { out[p] = b; p += 1; }
    }
    if p < out.len() { out[p] = 0; }
    p
}

// ── Startup ─────────────────────────────────────────────────────────

/// Programs must define: `#[unsafe(no_mangle)] extern "C" fn main(argc: usize, argv: *const *const u8)`
/// The _start stub captures the original SP, builds argc/argv, and calls main.

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".global _start",
    "_start:",
    "mov rdi, [rsp]",       // argc
    "lea rsi, [rsp + 8]",   // argv (pointer to array of pointers)
    "call main",
    "mov rdi, rax",          // exit code = main return value
    "mov rax, 60",           // exit syscall
    "int 0x80",
    "ud2",
);

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".global _start",
    "_start:",
    "ldr x0, [sp]",         // argc
    "add x1, sp, #8",       // argv
    "bl main",
    "mov x8, #93",           // exit syscall
    "svc #0",
    "brk #0",
);

// ── Panic handler ───────────────────────────────────────────────────

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    print("panic!\n");
    exit(127);
}
