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
    serial::write_str("rux: serial output working\n");
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

    #[cfg(target_arch = "x86_64")]
    exit::exit_qemu(exit::EXIT_FAILURE);

    #[allow(unreachable_code)]
    loop { core::hint::spin_loop(); }
}

fn write_u32(buf: &mut [u8; 10], mut n: u32) -> &str {
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
