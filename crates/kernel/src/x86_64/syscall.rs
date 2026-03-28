/// INT 0x80 syscall handler for x86_64.
/// Uses the existing IDT infrastructure — vector 128 with DPL=3.

use super::gdt::{USER_CS, USER_DS};
use super::serial;

/// Handle INT 0x80. Called from interrupt_dispatch with the saved register frame.
///
/// Frame layout (pushed by interrupt_common):
///   [frame+0..7]   = R15,R14,R13,R12,R11,R10,R9,R8,RBP,RDI,RSI,RDX,RCX,RBX,RAX
///   [frame+120]    = vector (128)
///   [frame+128]    = error code (0)
///   [frame+136]    = RIP, CS, RFLAGS, RSP, SS (pushed by CPU)
pub fn handle_syscall(_vector: u64, _error_code: u64, frame: *mut u8) {
    unsafe {
        let regs = frame as *mut u64;

        // Read saved registers — offsets are indices into the u64 array
        // Push order: R15(0) R14(1) R13(2) R12(3) R11(4) R10(5) R9(6) R8(7)
        //             RBP(8) RDI(9) RSI(10) RDX(11) RCX(12) RBX(13) RAX(14)
        let syscall_nr = *regs.add(14); // RAX
        let arg0 = *regs.add(9);        // RDI
        let arg1 = *regs.add(10);       // RSI
        let arg2 = *regs.add(11);       // RDX

        let result: i64 = match syscall_nr {
            1 => syscall_write(arg0, arg1, arg2),
            60 => syscall_exit(arg0 as i32),
            _ => -38, // -ENOSYS
        };

        // Write return value to saved RAX — restored by iretq path
        *regs.add(14) = result as u64;
    }
}

/// write(fd, buf, len) — fd=1 writes to serial console.
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
    crate::x86_64::exit::exit_qemu(crate::x86_64::exit::EXIT_SUCCESS);
}

/// Enter user mode via iretq. Pushes SS, RSP, RFLAGS, CS, RIP and irets.
#[unsafe(naked)]
pub extern "C" fn enter_user_mode(entry: u64, user_stack: u64) -> ! {
    // RDI = entry (RIP), RSI = user_stack (RSP)
    // Build iretq frame: SS, RSP, RFLAGS, CS, RIP
    core::arch::naked_asm!(
        "push {user_ds}",       // SS = USER_DS
        "push rsi",             // RSP = user_stack
        "push 0x202",           // RFLAGS = IF enabled
        "push {user_cs}",       // CS = USER_CS
        "push rdi",             // RIP = entry
        "iretq",
        user_ds = const (USER_DS as u64),
        user_cs = const (USER_CS as u64),
    );
}
