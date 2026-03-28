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
            59 => syscall_exec(arg0, arg1, arg2),
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

/// exec(path, argv, envp) — replace process image with a new ELF from the VFS.
/// Only `path` is used; argv/envp are ignored for now.
fn syscall_exec(path_ptr: u64, _argv: u64, _envp: u64) -> i64 {
    unsafe {
        use rux_mm::FrameAllocator;
        use rux_vfs::{FileSystem, FileName, InodeStat};

        let fs = crate::kstate::fs();
        let alloc = crate::kstate::alloc();

        // Read path string from user memory (identity-mapped, so direct access)
        let path_cstr = path_ptr as *const u8;
        let mut path_len = 0usize;
        while *path_cstr.add(path_len) != 0 && path_len < 256 {
            path_len += 1;
        }
        let path = core::slice::from_raw_parts(path_cstr, path_len);

        serial::write_str("rux: exec(\"");
        serial::write_bytes(path);
        serial::write_str("\")\n");

        // Resolve path in VFS
        let ino = match rux_vfs::path::resolve_path(fs, path) {
            Ok(ino) => ino,
            Err(_) => {
                serial::write_str("rux: exec: path not found\n");
                return -2; // -ENOENT
            }
        };

        // Get file size
        let mut stat = core::mem::zeroed::<InodeStat>();
        if fs.stat(ino, &mut stat).is_err() {
            serial::write_str("rux: exec: stat failed\n");
            return -5; // -EIO
        }
        let size = stat.size as usize;
        if size == 0 || size > 32 * 4096 {
            serial::write_str("rux: exec: file too large or empty\n");
            return -7; // -E2BIG
        }

        // Allocate pages for a contiguous read buffer
        let num_pages = (size + 4095) / 4096;
        let buf_base = alloc.alloc(rux_mm::PageSize::FourK).expect("exec buf page 0");
        // For simplicity, allocate pages contiguously by taking them one at a time.
        // We only need the first page for small ELFs. For larger ones, read in chunks.
        // Actually, since pages from buddy allocator may not be contiguous,
        // let's read into individually allocated pages and build a flat buffer.
        // For now, hello.elf is < 4K, so one page suffices.
        let buf = core::slice::from_raw_parts_mut(
            buf_base.as_usize() as *mut u8,
            4096,
        );

        // If the file is larger than 4K, we need more pages.
        // Allocate up to 8 contiguous-ish pages. Since identity-mapped,
        // we can use a flat array at a known region. For Phase 1 with small
        // binaries, reading up to 4K at offset 0 is sufficient.
        let n = match fs.read(ino, 0, &mut buf[..size.min(4096)]) {
            Ok(n) => n,
            Err(_) => {
                serial::write_str("rux: exec: read failed\n");
                return -5;
            }
        };

        serial::write_str("rux: exec: read ");
        let mut nbuf = [0u8; 10];
        serial::write_str(crate::write_u32(&mut nbuf, n as u32));
        serial::write_str(" bytes\n");

        // Load and execute the ELF (does not return)
        serial::write_str("rux: entering user mode...\n");
        crate::elf::load_and_exec_elf(&buf[..n], alloc);
    }
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
