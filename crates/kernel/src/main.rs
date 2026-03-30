#![no_std]
#![no_main]

mod arch;

mod scheduler;
mod elf;
mod kstate;
pub mod pipe;
pub mod execargs;
pub mod pgtrack;
pub mod syscall;

use rux_arch::{SerialOps, ExitOps, BootOps};
use arch::Arch;

/// Kernel entry point. Called from boot.S.
/// On x86_64: `arg` is the multiboot info physical address.
/// On aarch64: `arg` is unused (DTB pointer, ignored for now).
#[no_mangle]
pub extern "C" fn kernel_main(arg: usize) -> ! {
    unsafe { Arch::init(); }
    Arch::write_str("rux: boot OK\n");

    Arch::boot_init(arg);

    Arch::write_str("rux: all checks passed\n");
    Arch::exit(Arch::EXIT_SUCCESS);
}

// ── Shared state for preemptive scheduler tests ─────────���───────────

pub static COUNTER_A: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
pub static COUNTER_B: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

// ── Panic handler ───────────────────────────────────────────────────

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    Arch::write_str("PANIC: ");
    if let Some(location) = info.location() {
        Arch::write_str(location.file());
        Arch::write_str(":");
        let mut buf = [0u8; 10];
        let s = write_u32(&mut buf, location.line());
        Arch::write_str(s);
    }
    Arch::write_str("\n");
    if let Some(msg) = info.message().as_str() {
        Arch::write_str(msg);
        Arch::write_str("\n");
    }
    Arch::exit(Arch::EXIT_FAILURE);
}

// ── Utility functions (used by both archs) ──────────────────────────

pub fn write_hex_serial(n: usize) {
    Arch::write_str("0x");
    let mut buf = [0u8; 16];
    write_hex_buf(&mut buf, n);
}

fn write_hex_buf(buf: &mut [u8; 16], mut n: usize) {
    if n == 0 {
        Arch::write_str("0");
        return;
    }
    let mut i = 16;
    while n > 0 && i > 0 {
        i -= 1;
        let digit = (n & 0xF) as u8;
        buf[i] = if digit < 10 { b'0' + digit } else { b'a' + digit - 10 };
        n >>= 4;
    }
    Arch::write_bytes(&buf[i..]);
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
