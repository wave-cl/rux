//! Auxiliary vector verifier for rux kernel.
//!
//! Walks the initial stack to find the auxv (after argc, argv, envp),
//! prints each entry, and exits with 0 if AT_PAGESZ is present.

#![no_std]
#![no_main]

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".global _start",
    "_start:",
    "mov rdi, rsp",
    "call {main}",
    "ud2",
    main = sym rust_main,
);

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".global _start",
    "_start:",
    "mov x0, sp",
    "bl {main}",
    "brk #0",
    main = sym rust_main,
);

// ── Inline syscalls ─────────────────────────────────────────────────

fn sys_write(fd: u64, buf: &[u8]) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("syscall",
            in("rax") 1u64, in("rdi") fd, in("rsi") buf.as_ptr() as u64, in("rdx") buf.len() as u64,
            lateout("rax") _, lateout("rcx") _, lateout("r11") _,
            options(nostack));
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let _ret: u64;
        core::arch::asm!("svc #0",
            in("x8") 64u64, inlateout("x0") fd => _ret, in("x1") buf.as_ptr() as u64, in("x2") buf.len() as u64,
            options(nostack));
    }
}

fn sys_exit(code: u64) -> ! {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("syscall",
            in("rax") 231u64, in("rdi") code,
            options(nostack, noreturn));
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("svc #0",
            in("x8") 93u64, in("x0") code,
            options(nostack, noreturn));
    }
}

fn print(s: &[u8]) { sys_write(1, s); }

fn print_num(mut n: usize) {
    if n == 0 { print(b"0"); return; }
    let mut buf = [0u8; 20];
    let mut i = 20;
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    sys_write(1, &buf[i..]);
}

fn print_hex(mut n: usize) {
    if n == 0 { print(b"0x0"); return; }
    let mut buf = [0u8; 18];
    buf[0] = b'0'; buf[1] = b'x';
    let mut i = 18;
    while n > 0 {
        i -= 1;
        let d = (n & 0xF) as u8;
        buf[i] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
        n >>= 4;
    }
    sys_write(1, &[b'0', b'x']);
    sys_write(1, &buf[i..]);
}

// ── Auxv walker ─────────────────────────────────────────────────────

#[unsafe(no_mangle)]
unsafe extern "C" fn rust_main(sp: *const usize) -> ! {
    print(b"auxv: start\n");

    // Stack layout: argc, argv[0..argc], NULL, envp[0..], NULL, auxv pairs, AT_NULL
    let argc = *sp;
    let mut ptr = sp.add(1); // skip argc

    // Skip argv
    for _ in 0..argc { ptr = ptr.add(1); }
    ptr = ptr.add(1); // skip argv NULL terminator

    // Skip envp
    while *ptr != 0 { ptr = ptr.add(1); }
    ptr = ptr.add(1); // skip envp NULL terminator

    // Read auxv pairs
    let mut found_pagesz = false;
    loop {
        let a_type = *ptr;
        let a_val = *ptr.add(1);
        ptr = ptr.add(2);

        if a_type == 0 { break; } // AT_NULL

        let name: &[u8] = match a_type {
            3  => b"AT_PHDR",
            4  => b"AT_PHENT",
            5  => b"AT_PHNUM",
            6  => b"AT_PAGESZ",
            7  => b"AT_BASE",
            9  => b"AT_ENTRY",
            11 => b"AT_UID",
            13 => b"AT_GID",
            14 => b"AT_EGID",
            23 => b"AT_EUID",
            _  => b"AT_UNKNOWN",
        };

        print(name);
        print(b"=");
        if a_type == 6 || a_type == 4 || a_type == 5 || a_type == 11 || a_type == 13 || a_type == 14 || a_type == 23 {
            print_num(a_val);
        } else {
            print_hex(a_val);
        }
        print(b"\n");

        if a_type == 6 && a_val == 4096 { found_pagesz = true; }
    }

    if found_pagesz {
        print(b"auxv_ok\n");
        sys_exit(0);
    } else {
        print(b"auxv_FAIL: AT_PAGESZ not found\n");
        sys_exit(1);
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { sys_exit(99); }
