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
                    // Kernel-mode data abort (kernel accessing user address)
                    let wnr = esr & (1 << 6) != 0;
                    if unsafe { crate::demand_paging::handle_user_fault(far, wnr) } {
                        return;
                    }
                    dump_user_fault("KERNEL DATA ABORT", far, esr, _frame);
                }
                0b100000 | 0b100001 => {
                    dump_user_fault("KERNEL INSTR ABORT", far, esr, _frame);
                }
                0b010101 => {
                    // SVC from EL1 — should not happen (user SVC handled in exc_type==2)
                }
                _ => {
                    super::console::write_str("rux: sync EC=");
                    write_hex(ec as usize);
                    super::console::write_str(" ESR=");
                    write_hex(esr as usize);
                    super::console::write_str(" ELR=");
                    // Read ELR_EL1 for the faulting PC
                    let elr: u64;
                    unsafe { core::arch::asm!("mrs {}, elr_el1", out(reg) elr, options(nostack)); }
                    write_hex(elr as usize);
                    super::console::write_str("\n");
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
                    // User data abort — shared COW + demand paging resolution
                    let wnr = esr & (1 << 6) != 0;
                    if unsafe { crate::demand_paging::handle_user_fault(far, wnr) } {
                        return;
                    }
                    super::console::write_str("rux: SIGSEGV at ");
                    write_hex(far as usize);
                    super::console::write_str("\n");
                    crate::syscall::posix::exit(139);
                }
                0b100000 | 0b100001 => {
                    // User instruction abort — try demand paging (lazy mmap,
                    // COW text pages that need re-mapping as executable).
                    if unsafe { crate::demand_paging::handle_user_fault(far, false) } {
                        return;
                    }
                    super::console::write_str("rux: SIGSEGV (instr) at ");
                    write_hex(far as usize);
                    super::console::write_str("\n");
                    crate::syscall::posix::exit(139);
                }
                _ => {
                    super::console::write_str("rux: user sync EC=");
                    write_hex(ec as usize);
                    super::console::write_str(" ESR=");
                    write_hex(esr as usize);
                    super::console::write_str("\n");
                    // Kill the process for unhandled user exceptions
                    crate::syscall::posix::exit(139);
                }
            }
        }
        3 => {
            // IRQ from EL0 — same GIC handler
            super::gic::handle_irq();
        }
        _ => {
            super::console::write_str("rux: unhandled exception type=");
            write_hex(exc_type as usize);
            super::console::write_str(" ESR=");
            write_hex(esr as usize);
            super::console::write_str("\n");
        }
    }
}


fn dump_user_fault(label: &str, far: u64, esr: u64, frame: *const u8) {
    let s = super::console::write_str;
    let h = |v: usize| {
        let mut b = [0u8; 16];
        super::console::write_str("0x");
        super::console::write_bytes(rux_klib::fmt::usize_to_hex(&mut b, v));
    };
    unsafe {
        let r = frame as *const u64;
        // frame: x0..x29(30 regs), x30(lr), elr_el1, spsr_el1
        let elr = *r.add(31);
        let sp_el0: u64;
        core::arch::asm!("mrs {}, sp_el0", out(reg) sp_el0, options(nostack));
        let ttbr0: u64;
        core::arch::asm!("mrs {}, ttbr0_el1", out(reg) ttbr0, options(nostack));
        let ttbr0 = ttbr0 & 0x0000_FFFF_FFFF_FFFF; // mask out ASID bits
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

#[allow(dead_code)]
fn panic_console(msg: &str, addr: u64) {
    super::console::write_str("PANIC: ");
    super::console::write_str(msg);
    write_hex(addr as usize);
    super::console::write_str("\n");
    super::exit::exit_qemu(super::exit::EXIT_FAILURE);
}

/// Print a hex value using the shared formatter.
#[inline]
fn write_hex(n: usize) {
    let mut buf = [0u8; 16];
    super::console::write_str("0x");
    super::console::write_bytes(rux_klib::fmt::usize_to_hex(&mut buf, n));
}
