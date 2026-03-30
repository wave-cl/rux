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
    {
        use rux_arch::ArchInfo;
        Arch::write_str(concat!("rux ", env!("CARGO_PKG_VERSION"), " ("));
        Arch::write_bytes(Arch::MACHINE_NAME);
        Arch::write_str(")\n");
    }

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
        Arch::write_str(rux_klib::fmt::u32_to_str(&mut buf, location.line()));
    }
    Arch::write_str("\n");
    if let Some(msg) = info.message().as_str() {
        Arch::write_str(msg);
        Arch::write_str("\n");
    }
    Arch::exit(Arch::EXIT_FAILURE);
}
