#![cfg_attr(not(feature = "native"), no_std)]
#![cfg_attr(not(feature = "native"), no_main)]

mod arch;
mod scheduler;
mod elf;
mod boot;
mod cmdline;
mod kstate;
mod pipe;
mod cow;
mod demand_paging;
mod tty;
mod pgtrack;
mod syscall;
mod uaccess;
mod task_table;
mod percpu;
mod fork;
mod errno;

#[cfg(feature = "native")]
mod tests;

/// Entry point for native binary builds (not tests).
/// Actual testing is done via `cargo test --features native`.
#[cfg(all(feature = "native", not(test)))]
fn main() {
    eprintln!("rux native harness: run with `cargo test --features native`");
}

use rux_arch::{ConsoleOps, ExitOps, BootOps};
use arch::Arch;

/// Kernel entry point. Called from boot.S.
/// On x86_64: `arg` is the multiboot info physical address.
/// On aarch64: `arg` is unused (DTB pointer, ignored for now).
#[cfg(not(feature = "native"))]
#[no_mangle]
pub extern "C" fn kernel_main(arg: usize) -> ! {
    // Zero Rust BSS statics explicitly — QEMU multiboot may not zero large
    // BSS sections reliably. We zero __bss_start..__bss_rust_end which covers
    // all Rust statics but NOT the boot page tables/stack (in .boot_bss,
    // placed after __bss_rust_end in the linker script).
    #[cfg(target_arch = "x86_64")]
    {
        extern "C" { static __bss_start: u8; static __bss_rust_end: u8; }
        let start = unsafe { &__bss_start as *const u8 as usize };
        let end = unsafe { &__bss_rust_end as *const u8 as usize };
        if end > start {
            unsafe { core::ptr::write_bytes(start as *mut u8, 0, end - start); }
        }
    }
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

// ── Panic handler (no_std mode only; std provides one in native mode) ─

#[cfg(not(feature = "native"))]
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
