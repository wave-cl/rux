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
                    // Kernel-mode data abort (kernel accessing user address).
                    // The kernel may write to user pages (e.g., epoll_wait writing
                    // events, fstat writing struct stat). Allow demand paging for
                    // all fault types — the demand_page VALID guard prevents
                    // replacing already-mapped pages.
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
            // IRQ from EL1 (kernel mode) — dispatch to GIC handler.
            // No preemption: we're in kernel context (syscall, pipe_block, etc.)
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
                    // User data abort — route by DFSC (Data Fault Status Code, ESR bits [5:0])
                    let dfsc = (esr & 0x3F) as u32;
                    let wnr = esr & (1 << 6) != 0;
                    let is_translation = dfsc & 0b111100 == 0b000100; // 0x04-0x07
                    let is_permission  = dfsc & 0b111100 == 0b001100; // 0x0C-0x0F
                    let is_access_flag = dfsc & 0b111100 == 0b001000; // 0x08-0x0B

                    if is_permission && wnr {
                        // Permission fault on write → try COW only (not demand paging)
                        if unsafe { crate::cow::handle_cow_fault(far as usize).is_ok() } {
                            return;
                        }
                    } else if is_translation || is_access_flag {
                        // Translation fault or access flag fault → demand paging + COW
                        if unsafe { crate::demand_paging::handle_user_fault(far, wnr) } {
                            return;
                        }
                    }
                    // Unresolvable user-space fault → SIGSEGV
                    unsafe {
                        let r = _frame as *const u64;
                        let elr = *r.add(31);
                        super::console::write_str("rux: SIGSEGV addr=");
                        write_hex(far as usize);
                        super::console::write_str(" pc=");
                        write_hex(elr as usize);
                        super::console::write_str("\n");
                    }
                    crate::syscall::linux::exit_group(139);
                }
                0b100000 | 0b100001 => {
                    // User instruction abort — route by IFSC (ESR bits [5:0])
                    let ifsc = (esr & 0x3F) as u32;
                    let is_translation = ifsc & 0b111100 == 0b000100; // 0x04-0x07

                    if is_translation {
                        // Translation fault → demand paging (lazy mmap, COW text re-map)
                        if unsafe { crate::demand_paging::handle_user_fault(far, false) } {
                            return;
                        }
                    }
                    // Permission fault or unresolvable → SIGSEGV
                    super::console::write_str("rux: SIGSEGV (instr) at ");
                    write_hex(far as usize);
                    super::console::write_str("\n");
                    crate::syscall::linux::exit_group(139);
                }
                _ => {
                    unsafe {
                        let r = _frame as *const u64;
                        let elr = *r.add(31);
                        super::console::write_str("rux: user sync EC=");
                        write_hex(ec as usize);
                        super::console::write_str(" ESR=");
                        write_hex(esr as usize);
                        super::console::write_str(" pc=");
                        write_hex(elr as usize);
                        super::console::write_str("\n");
                    }
                    crate::syscall::linux::exit_group(139);
                }
            }
        }
        3 => {
            // IRQ from EL0 (user mode) — dispatch to GIC handler
            super::gic::handle_irq();
            // Preemptive scheduling: the full exception frame (x0-x30, ELR, SPSR)
            // is saved on the current task's kernel stack. context_switch saves SP,
            // so the frame is preserved. The new task's SP points to its own frame.
            // exception_return (eret) uses the new frame correctly.
            unsafe {
                let sched = crate::scheduler::get();
                if sched.need_resched {
                    sched.schedule();
                }
            }
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
