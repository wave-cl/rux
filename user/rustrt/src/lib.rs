//! Minimal Rust runtime for rux userspace programs.
//!
//! Provides syscall wrappers and a startup stub. Programs define
//! `fn main()` and link against this crate.

#![no_std]

// ── Syscall ABI ─────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod sys {
    #[inline(always)]
    pub unsafe fn syscall0(nr: u64) -> i64 {
        let ret: i64;
        core::arch::asm!("int 0x80", in("rax") nr, lateout("rax") ret, options(nostack));
        ret
    }

    #[inline(always)]
    pub unsafe fn syscall1(nr: u64, a0: u64) -> i64 {
        let ret: i64;
        core::arch::asm!("int 0x80", in("rax") nr, in("rdi") a0, lateout("rax") ret, options(nostack));
        ret
    }

    #[inline(always)]
    pub unsafe fn syscall2(nr: u64, a0: u64, a1: u64) -> i64 {
        let ret: i64;
        core::arch::asm!("int 0x80", in("rax") nr, in("rdi") a0, in("rsi") a1, lateout("rax") ret, options(nostack));
        ret
    }

    #[inline(always)]
    pub unsafe fn syscall3(nr: u64, a0: u64, a1: u64, a2: u64) -> i64 {
        let ret: i64;
        core::arch::asm!("int 0x80", in("rax") nr, in("rdi") a0, in("rsi") a1, in("rdx") a2, lateout("rax") ret, options(nostack));
        ret
    }

    pub const SYS_READ: u64 = 0;
    pub const SYS_WRITE: u64 = 1;
    pub const SYS_OPEN: u64 = 2;
    pub const SYS_CLOSE: u64 = 3;
    pub const SYS_CREAT: u64 = 8;
    pub const SYS_GETDENTS: u64 = 78;
    pub const SYS_UNLINK: u64 = 87;
    pub const SYS_GETTIMEOFDAY: u64 = 96;
    pub const SYS_EXIT: u64 = 60;
}

#[cfg(target_arch = "aarch64")]
mod sys {
    #[inline(always)]
    pub unsafe fn syscall0(nr: u64) -> i64 {
        let ret: i64;
        core::arch::asm!("svc #0", in("x8") nr, lateout("x0") ret, options(nostack));
        ret
    }

    #[inline(always)]
    pub unsafe fn syscall1(nr: u64, a0: u64) -> i64 {
        let ret: i64;
        core::arch::asm!("svc #0", in("x8") nr, inlateout("x0") a0 => ret, options(nostack));
        ret
    }

    #[inline(always)]
    pub unsafe fn syscall2(nr: u64, a0: u64, a1: u64) -> i64 {
        let ret: i64;
        core::arch::asm!("svc #0", in("x8") nr, inlateout("x0") a0 => ret, in("x1") a1, options(nostack));
        ret
    }

    #[inline(always)]
    pub unsafe fn syscall3(nr: u64, a0: u64, a1: u64, a2: u64) -> i64 {
        let ret: i64;
        core::arch::asm!("svc #0", in("x8") nr, inlateout("x0") a0 => ret, in("x1") a1, in("x2") a2, options(nostack));
        ret
    }

    pub const SYS_READ: u64 = 63;
    pub const SYS_WRITE: u64 = 64;
    pub const SYS_OPEN: u64 = 56;
    pub const SYS_CLOSE: u64 = 57;
    pub const SYS_CREAT: u64 = 33;
    pub const SYS_GETDENTS: u64 = 61;
    pub const SYS_UNLINK: u64 = 35;
    pub const SYS_GETTIMEOFDAY: u64 = 169;
    pub const SYS_EXIT: u64 = 93;
}

// ── Public API ──────────────────────────────────────────────────────

pub fn exit(code: i32) -> ! {
    unsafe { sys::syscall1(sys::SYS_EXIT, code as u64); }
    loop {}
}

pub fn write(fd: u32, buf: &[u8]) -> isize {
    unsafe { sys::syscall3(sys::SYS_WRITE, fd as u64, buf.as_ptr() as u64, buf.len() as u64) as isize }
}

pub fn read(fd: u32, buf: &mut [u8]) -> isize {
    unsafe { sys::syscall3(sys::SYS_READ, fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64) as isize }
}

pub fn open(path: &[u8]) -> isize {
    // path must be null-terminated
    unsafe { sys::syscall1(sys::SYS_OPEN, path.as_ptr() as u64) as isize }
}

pub fn close(fd: u32) -> isize {
    unsafe { sys::syscall1(sys::SYS_CLOSE, fd as u64) as isize }
}

pub fn getdents(buf: &mut [u8]) -> isize {
    unsafe { sys::syscall2(sys::SYS_GETDENTS, buf.as_mut_ptr() as u64, buf.len() as u64) as isize }
}

pub fn ticks() -> u64 {
    unsafe { sys::syscall0(sys::SYS_GETTIMEOFDAY) as u64 }
}

/// Print a string to stdout.
pub fn print(s: &str) {
    write(1, s.as_bytes());
}

/// Print a string followed by newline.
pub fn println(s: &str) {
    print(s);
    write(1, b"\n");
}

/// Print a u64 as decimal.
pub fn print_u64(mut n: u64) {
    let mut buf = [0u8; 20];
    let mut i = 20;
    if n == 0 {
        write(1, b"0");
        return;
    }
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    write(1, &buf[i..]);
}

// ── Argv access ─────────────────────────────────────────────────────

/// Get argc from the stack. Must be called from _start or its callees.
///
/// # Safety
/// Only valid when called with the original stack pointer from _start.
pub unsafe fn argc(sp: *const u64) -> usize {
    *sp as usize
}

/// Get argv[i] as a byte slice. Returns None if i >= argc.
///
/// # Safety
/// Only valid when called with the original stack pointer from _start.
pub unsafe fn argv(sp: *const u64, i: usize) -> Option<&'static [u8]> {
    let ac = *sp as usize;
    if i >= ac { return None; }
    let ptr = *sp.add(1 + i) as *const u8;
    if ptr.is_null() { return None; }
    let mut len = 0;
    while *ptr.add(len) != 0 { len += 1; }
    Some(core::slice::from_raw_parts(ptr, len))
}

// ── Panic handler ───────────────────────────────────────────────────

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    print("panic!\n");
    exit(127);
}
