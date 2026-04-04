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
                    // Kernel-mode data abort — may be a COW fault caused by the
                    // kernel writing to a user COW page (e.g. sys_read into a
                    // user buffer whose page hasn't been touched since fork).
                    // User addresses have top 16 bits = 0 (TTBR0 range).
                    let wnr = esr & (1 << 6) != 0;
                    let dfsc = esr & 0x3F;
                    let is_perm = dfsc == 0x0F || dfsc == 0x0E || dfsc == 0x0D;
                    if wnr && is_perm && (far & 0xFFFF_0000_0000_0000u64 == 0) {
                        if unsafe { crate::cow::handle_cow_fault(far as usize).is_ok() } {
                            return; // COW resolved
                        }
                    }
                    // Demand paging: translation fault at user address → map zero page
                    let is_translation = dfsc == 0x05 || dfsc == 0x06 || dfsc == 0x07;
                    if (is_translation || is_perm) && far < 0x8000_0000 && far >= 0x1000 {
                        if unsafe { demand_page(far as usize) } { return; }
                    }
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
                    // Data abort from EL0.
                    // ISS bits: [6]=WnR (write), [5:0]=DFSC (fault status)
                    let wnr = esr & (1 << 6) != 0;   // write fault
                    let dfsc = esr & 0x3F;
                    let is_perm = dfsc == 0x0F || dfsc == 0x0E || dfsc == 0x0D;  // permission fault level 1/2/3
                    if wnr && is_perm {
                        if unsafe { crate::cow::handle_cow_fault(far as usize).is_ok() } {
                            return; // COW resolved
                        }
                    }
                    // Demand paging: translation or permission fault → map zero page
                    let is_translation = dfsc == 0x05 || dfsc == 0x06 || dfsc == 0x07;
                    if (is_translation || is_perm) && far < 0x8000_0000 && far >= 0x1000 {
                        if unsafe { demand_page(far as usize) } { return; }
                    }
                    // Unresolvable user fault → kill process (SIGSEGV)
                    super::console::write_str("rux: SIGSEGV at ");
                    write_hex(far as usize);
                    super::console::write_str("\n");
                    unsafe { crate::syscall::posix::exit(139); } // 128 + SIGSEGV
                }
                0b100000 | 0b100001 => {
                    super::console::write_str("rux: SIGSEGV (instr) at ");
                    write_hex(far as usize);
                    super::console::write_str("\n");
                    unsafe { crate::syscall::posix::exit(139); }
                }
                _ => {
                    super::console::write_str("rux: user sync EC=");
                    write_hex(ec as usize);
                    super::console::write_str(" ESR=");
                    write_hex(esr as usize);
                    super::console::write_str("\n");
                    // Kill the process for unhandled user exceptions
                    unsafe { crate::syscall::posix::exit(139); }
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

/// Demand page: allocate and map a zero-filled page at the faulting address.
/// Returns true if the page was mapped, false if allocation failed.
unsafe fn demand_page(addr: usize) -> bool {
    use rux_mm::FrameAllocator;
    let alloc = crate::kstate::alloc();
    let frame = match alloc.alloc(rux_mm::PageSize::FourK) {
        Ok(f) => f,
        Err(_) => return false,
    };
    core::ptr::write_bytes(frame.as_usize() as *mut u8, 0, 4096);
    let va = rux_klib::VirtAddr::new(addr & !0xFFF);
    let flags = rux_mm::MappingFlags::READ
        .or(rux_mm::MappingFlags::WRITE)
        .or(rux_mm::MappingFlags::EXECUTE)
        .or(rux_mm::MappingFlags::USER);
    let mut upt = crate::syscall::current_user_page_table();
    let _ = upt.unmap_4k(va); // remove any stale entry
    match upt.map_4k(va, frame, flags, alloc) {
        Ok(()) => true,
        Err(_) => false,
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

fn panic_console(msg: &str, addr: u64) {
    super::console::write_str("PANIC: ");
    super::console::write_str(msg);
    write_hex(addr as usize);
    super::console::write_str("\n");
    super::exit::exit_qemu(super::exit::EXIT_FAILURE);
}

fn write_hex(mut n: usize) {
    super::console::write_str("0x");
    if n == 0 {
        super::console::write_byte(b'0');
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
    super::console::write_bytes(&buf[i..]);
}
