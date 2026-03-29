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
                    dump_user_fault("KERNEL DATA ABORT", far, esr, _frame);
                }
                0b100000 | 0b100001 => {
                    dump_user_fault("KERNEL INSTR ABORT", far, esr, _frame);
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
            // IRQ from EL1 — dispatch to GIC handler
            super::gic::handle_irq();
        }
        2 => {
            // Synchronous exception from EL0 (user mode)
            let ec = esr_ec(esr);
            match ec {
                0b010101 => {
                    // SVC — syscall from user space
                    super::syscall::handle_syscall(_frame as *mut u8);
                }
                0b100100 | 0b100101 => {
                    dump_user_fault("USER DATA ABORT", far, esr, _frame);
                }
                0b100000 | 0b100001 => {
                    dump_user_fault("USER INSTR ABORT", far, esr, _frame);
                }
                _ => {
                    super::serial::write_str("rux: user sync EC=");
                    write_hex(ec as usize);
                    super::serial::write_str(" ESR=");
                    write_hex(esr as usize);
                    super::serial::write_str("\n");
                }
            }
        }
        3 => {
            // IRQ from EL0 — same GIC handler
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

fn dump_user_fault(label: &str, far: u64, esr: u64, frame: *const u8) {
    let s = super::serial::write_str;
    let h = |v: usize| crate::write_hex_serial(v);
    unsafe {
        let r = frame as *const u64;
        // frame: x0..x29(30 regs), x30(lr), elr_el1, spsr_el1
        let elr = *r.add(31);
        let sp_el0: u64;
        core::arch::asm!("mrs {}, sp_el0", out(reg) sp_el0, options(nostack));
        let ttbr0: u64;
        core::arch::asm!("mrs {}, ttbr0_el1", out(reg) ttbr0, options(nostack));
        let tpidr: u64;
        core::arch::asm!("mrs {}, tpidr_el0", out(reg) tpidr, options(nostack));

        s("\n=== "); s(label); s(" ===\n");
        s("  far:  "); h(far as usize); s("  esr: "); h(esr as usize); s("\n");
        s("  elr:  "); h(elr as usize); s("  sp:  "); h(sp_el0 as usize); s("\n");
        s("  x0:   "); h(*r.add(0) as usize); s("  x1:  "); h(*r.add(1) as usize); s("\n");
        s("  x2:   "); h(*r.add(2) as usize); s("  x3:  "); h(*r.add(3) as usize); s("\n");
        s("  x8:   "); h(*r.add(8) as usize); s("  x29: "); h(*r.add(29) as usize); s("\n");
        s("  x30:  "); h(*r.add(30) as usize); s("\n");
        s("  ttbr0:"); h(ttbr0 as usize); s("  tpidr:"); h(tpidr as usize); s("\n");

        // Try to read the faulting instruction (if elr is in mapped range)
        if elr >= 0x400000 && elr < 0x600000 {
            let insn = *(elr as *const u32);
            s("  insn: "); h(insn as usize); s("\n");
        }
    }
    super::exit::exit_qemu(super::exit::EXIT_FAILURE);
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
