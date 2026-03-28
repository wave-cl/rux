/// SVC syscall handler for aarch64.
/// User code does `svc #0` which traps to EL1.
/// Uses aarch64 Linux syscall numbers: write=64, exit=93.

use super::serial;

/// Handle SVC from user mode. Called from exception_dispatch.
///
/// Frame layout (from exception.S save_context):
///   [0]=x0, [8]=x1, ..., [64]=x8, ..., [240]=x30+elr, [256]=spsr
///   Each register is 8 bytes, x0 at offset 0, x1 at offset 8, etc.
pub fn handle_syscall(frame: *mut u8) {
    unsafe {
        let regs = frame as *mut u64;

        // aarch64 syscall convention: x8 = number, x0-x5 = args
        let syscall_nr = *regs.add(8);  // x8
        let arg0 = *regs.add(0);        // x0
        let arg1 = *regs.add(1);        // x1
        let arg2 = *regs.add(2);        // x2

        let result: i64 = match syscall_nr {
            64 => syscall_write(arg0, arg1, arg2),  // write (aarch64 Linux)
            93 => syscall_exit(arg0 as i32),         // exit (aarch64 Linux)
            _ => -38, // -ENOSYS
        };

        // Return value in x0
        *regs.add(0) = result as u64;
    }
}

/// write(fd, buf, len) — fd=1 or 2 writes to serial console.
fn syscall_write(fd: u64, buf: u64, len: u64) -> i64 {
    if fd != 1 && fd != 2 {
        return -9; // -EBADF
    }
    unsafe {
        let ptr = buf as *const u8;
        for i in 0..len as usize {
            serial::write_byte(*ptr.add(i));
        }
    }
    len as i64
}

/// exit(status) — terminate the user process.
fn syscall_exit(status: i32) -> ! {
    serial::write_str("rux: user exit(");
    let mut buf = [0u8; 10];
    serial::write_str(crate::write_u32(&mut buf, status as u32));
    serial::write_str(")\n");
    crate::aarch64::exit::exit_qemu(crate::aarch64::exit::EXIT_SUCCESS);
}

/// Enter user mode (EL0) via eret.
/// Sets ELR_EL1 = entry, SP_EL0 = user_stack, SPSR_EL1 = 0 (EL0t).
pub unsafe fn enter_user_mode(entry: u64, user_stack: u64) -> ! {
    core::arch::asm!(
        "msr sp_el0, {sp}",         // user stack pointer
        "msr elr_el1, {entry}",     // return-to address
        "msr spsr_el1, xzr",        // SPSR = 0 = EL0t, interrupts enabled
        "eret",
        entry = in(reg) entry,
        sp = in(reg) user_stack,
        options(noreturn)
    );
}
