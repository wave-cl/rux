#![no_std]
#![no_main]

#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "x86_64")]
use x86_64::{serial, exit};

/// Kernel entry point. Called from boot.S after long mode is set up.
#[no_mangle]
pub extern "C" fn kernel_main(_multiboot_info: usize) -> ! {
    unsafe { serial::init(); }
    serial::write_str("rux: boot OK\n");

    // Initialize GDT with TSS
    // The boot stack top is defined in boot.S. We use 0x104000 + 16384 = 0x108000
    // (bss starts at ~0x104000, boot_stack is 16K after page tables)
    unsafe { x86_64::gdt::init(0x108000); }
    serial::write_str("rux: GDT + TSS loaded\n");

    // Initialize IDT with all exception/IRQ handlers
    unsafe { x86_64::idt::init(); }
    serial::write_str("rux: IDT loaded\n");

    // Initialize PIT timer at 1000 Hz
    unsafe { x86_64::pit::init(1000); }
    serial::write_str("rux: PIT timer initialized (1000 Hz)\n");

    // Enable interrupts
    unsafe { core::arch::asm!("sti", options(nostack, preserves_flags)); }
    serial::write_str("rux: interrupts enabled\n");

    // Wait for some timer ticks
    let start = x86_64::pit::ticks();
    while x86_64::pit::ticks() < start + 100 {
        core::hint::spin_loop();
    }
    let elapsed = x86_64::pit::ticks() - start;
    serial::write_str("rux: timer test OK (");
    let mut buf = [0u8; 10];
    serial::write_str(write_u32(&mut buf, elapsed as u32));
    serial::write_str(" ticks)\n");

    serial::write_str("rux: all checks passed\n");
    exit::exit_qemu(exit::EXIT_SUCCESS);
}

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
