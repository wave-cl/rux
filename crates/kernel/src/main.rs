#![no_std]
#![no_main]

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "aarch64")]
mod aarch64;

mod scheduler;
mod elf;
mod kstate;
pub mod fdtable;
pub mod pipe;
pub mod execargs;
pub mod pgtrack;
pub mod rootfs;
pub mod syscall_impl;

#[cfg(target_arch = "x86_64")]
use x86_64::{serial, exit};
#[cfg(target_arch = "aarch64")]
use aarch64::{serial, exit};

/// Kernel entry point. Called from boot.S.
/// On x86_64: `arg` is the multiboot info physical address.
/// On aarch64: `arg` is unused (DTB pointer, ignored for now).
#[no_mangle]
pub extern "C" fn kernel_main(arg: usize) -> ! {
    unsafe { serial::init(); }
    serial::write_str("rux: boot OK\n");

    #[cfg(target_arch = "x86_64")]
    x86_64::init::x86_64_init(arg);

    #[cfg(target_arch = "aarch64")]
    aarch64::init::aarch64_init(arg);

    serial::write_str("rux: all checks passed\n");
    exit::exit_qemu(exit::EXIT_SUCCESS);
}

// ── Shared state for preemptive scheduler tests ─────────���───────────

pub static COUNTER_A: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
pub static COUNTER_B: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

// ── Panic handler ───────────────────────────────────────────────────

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    serial::write_str("PANIC: ");
    if let Some(location) = info.location() {
        serial::write_str(location.file());
        serial::write_str(":");
        let mut buf = [0u8; 10];
        let s = write_u32(&mut buf, location.line());
        serial::write_str(s);
    }
    serial::write_str("\n");
    if let Some(msg) = info.message().as_str() {
        serial::write_str(msg);
        serial::write_str("\n");
    }
    exit::exit_qemu(exit::EXIT_FAILURE);
}

// ── Utility functions (used by both archs) ──────────────────────────

pub fn write_hex_serial(n: usize) {
    serial::write_str("0x");
    let mut buf = [0u8; 16];
    write_hex_buf(&mut buf, n);
}

fn write_hex_buf(buf: &mut [u8; 16], mut n: usize) {
    if n == 0 {
        serial::write_str("0");
        return;
    }
    let mut i = 16;
    while n > 0 && i > 0 {
        i -= 1;
        let digit = (n & 0xF) as u8;
        buf[i] = if digit < 10 { b'0' + digit } else { b'a' + digit - 10 };
        n >>= 4;
    }
    serial::write_bytes(&buf[i..]);
}

pub fn write_u32(buf: &mut [u8; 10], mut n: u32) -> &str {
    if n == 0 {
        buf[0] = b'0';
        return unsafe { core::str::from_utf8_unchecked(&buf[..1]) };
    }
    let mut i = 10;
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    unsafe { core::str::from_utf8_unchecked(&buf[i..]) }
}
