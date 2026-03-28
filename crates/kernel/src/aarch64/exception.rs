/// Exception dispatch for aarch64.

/// Install the exception vector table.
pub unsafe fn init() {
    extern "C" {
        static exception_vectors: u8;
    }
    let vbar = &exception_vectors as *const u8 as u64;
    core::arch::asm!("msr vbar_el1, {}", in(reg) vbar, options(nostack));
    // ISB to ensure VBAR is updated before any exception can fire
    core::arch::asm!("isb", options(nostack));
}

/// ESR_EL1 exception class (bits 31:26).
#[inline(always)]
fn esr_ec(esr: u64) -> u32 {
    ((esr >> 26) & 0x3F) as u32
}

/// Rust exception dispatch. Called from the assembly stubs.
/// `exc_type`: 0 = synchronous, 1 = IRQ, 99 = unhandled
/// `esr`: ESR_EL1 value (for synchronous exceptions)
/// `far`: FAR_EL1 value (fault address)
/// `frame`: pointer to saved registers on stack
#[no_mangle]
pub extern "C" fn exception_dispatch(exc_type: u64, esr: u64, far: u64, _frame: *const u8) {
    match exc_type {
        0 => {
            // Synchronous exception — check ESR for type
            let ec = esr_ec(esr);
            match ec {
                0b100100 | 0b100101 => {
                    // Data abort (from EL1 or EL0)
                    panic_serial("Data abort at ", far);
                }
                0b100000 | 0b100001 => {
                    // Instruction abort
                    panic_serial("Instruction abort at ", far);
                }
                0b010101 => {
                    // SVC (syscall from EL0)
                    // TODO: syscall dispatch
                }
                _ => {
                    super::serial::write_str("rux: sync EC=");
                    write_hex(ec as usize);
                    super::serial::write_str(" ESR=");
                    write_hex(esr as usize);
                    super::serial::write_str(" ELR=");
                    // Read ELR_EL1 for the faulting PC
                    let elr: u64;
                    unsafe { core::arch::asm!("mrs {}, elr_el1", out(reg) elr, options(nostack)); }
                    write_hex(elr as usize);
                    super::serial::write_str("\n");
                }
            }
        }
        1 => {
            // IRQ — dispatch to GIC handler
            super::gic::handle_irq();
        }
        _ => {
            super::serial::write_str("rux: unhandled exception type=");
            write_hex(exc_type as usize);
            super::serial::write_str(" ESR=");
            write_hex(esr as usize);
            super::serial::write_str("\n");
        }
    }
}

fn panic_serial(msg: &str, addr: u64) {
    super::serial::write_str("PANIC: ");
    super::serial::write_str(msg);
    write_hex(addr as usize);
    super::serial::write_str("\n");
    super::exit::exit_qemu(super::exit::EXIT_FAILURE);
}

fn write_hex(mut n: usize) {
    super::serial::write_str("0x");
    if n == 0 {
        super::serial::write_byte(b'0');
        return;
    }
    let mut buf = [0u8; 16];
    let mut i = 16;
    while n > 0 && i > 0 {
        i -= 1;
        let d = (n & 0xF) as u8;
        buf[i] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
        n >>= 4;
    }
    super::serial::write_bytes(&buf[i..]);
}
