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
    while x86_64::pit::ticks() < start + 10 {
        core::hint::spin_loop();
    }
    serial::write_str("rux: timer OK\n");

    // ── Context switch test ─────────────────────────────────────────────
    // Create a second kernel task on a separate stack. Switch to it,
    // it prints a message, switches back. Proves context_switch works.
    serial::write_str("rux: context switch test...\n");

    unsafe {
        // Allocate a 16K stack for task B (use a static buffer)
        static mut TASK_B_STACK: [u8; 16384] = [0; 16384];
        let stack_top = TASK_B_STACK.as_ptr() as u64 + 16384;

        // Initialize task B's stack to "return" to task_b_entry(0x42)
        let task_b_rsp = x86_64::context::init_task_stack(
            stack_top,
            task_b_entry as u64,
            0x42,
        );

        // Switch to task B (saves our RSP in the module-level MAIN_RSP)
        x86_64::context::context_switch(
            &raw mut MAIN_RSP,
            task_b_rsp,
        );

        // We're back! Task B switched back to us.
        serial::write_str("rux: back in main task\n");
    }

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

/// Task B entry point — runs on its own stack.
extern "C" fn task_b_entry() {
    serial::write_str("rux: task B running!\n");

    // Switch back to main task
    unsafe {
        static mut TASK_B_RSP: u64 = 0;
        // MAIN_RSP was set by the switch that got us here
        x86_64::context::context_switch(
            &raw mut TASK_B_RSP,
            MAIN_RSP,
        );
    }
    // Should not reach here
    loop { core::hint::spin_loop(); }
}

/// Reference to main task's saved RSP (set during context switch).
/// Task B reads this to switch back.
static mut MAIN_RSP: u64 = 0;

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
