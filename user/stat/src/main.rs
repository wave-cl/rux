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
        core::arch::asm!("int 0x80",
            in("rax") 1u64, in("rdi") fd, in("rsi") buf.as_ptr() as u64, in("rdx") buf.len() as u64,
            lateout("rax") _, options(nostack));
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let _ret: u64;
        core::arch::asm!("svc #0",
            in("x8") 64u64, inlateout("x0") fd => _ret, in("x1") buf.as_ptr() as u64, in("x2") buf.len() as u64,
            options(nostack));
    }
}

fn sys_read(fd: u64, buf: &mut [u8]) -> isize {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let ret: i64;
        core::arch::asm!("int 0x80",
            in("rax") 0u64, in("rdi") fd, in("rsi") buf.as_mut_ptr() as u64, in("rdx") buf.len() as u64,
            lateout("rax") ret, options(nostack));
        ret as isize
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let ret: i64;
        core::arch::asm!("svc #0",
            in("x8") 63u64, inlateout("x0") fd => ret, in("x1") buf.as_mut_ptr() as u64, in("x2") buf.len() as u64,
            options(nostack));
        ret as isize
    }
}

fn sys_open(path: &[u8]) -> isize {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let ret: i64;
        core::arch::asm!("int 0x80",
            in("rax") 2u64, in("rdi") path.as_ptr() as u64,
            lateout("rax") ret, options(nostack));
        ret as isize
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let ret: i64;
        core::arch::asm!("svc #0",
            in("x8") 56u64, inlateout("x0") path.as_ptr() as u64 => ret,
            options(nostack));
        ret as isize
    }
}

fn sys_close(fd: u64) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("int 0x80",
            in("rax") 3u64, in("rdi") fd,
            lateout("rax") _, options(nostack));
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let _ret: u64;
        core::arch::asm!("svc #0",
            in("x8") 57u64, inlateout("x0") fd => _ret,
            options(nostack));
    }
}

fn sys_exit(code: u64) -> ! {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("int 0x80", in("rax") 60u64, in("rdi") code, options(nostack, noreturn));
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("svc #0", in("x8") 93u64, in("x0") code, options(nostack, noreturn));
    }
}

fn print(s: &str) { sys_write(1, s.as_bytes()); }

fn print_u64(mut n: u64) {
    let mut buf = [0u8; 20];
    let mut i = 20;
    if n == 0 {
        sys_write(1, b"0");
        return;
    }
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    sys_write(1, &buf[i..]);
}

// ── Main ────────────────────────────────────────────────────────────

extern "C" fn rust_main(sp: *const u64) -> ! {
    let argc = unsafe { *sp } as usize;
    if argc < 2 {
        print("usage: stat <name>\n");
        sys_exit(1);
    }

    let name_ptr = unsafe { *sp.add(2) } as *const u8;
    let mut name_len = 0;
    unsafe { while *name_ptr.add(name_len) != 0 { name_len += 1; } }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };

    // Build path: "/" + name + "\0"
    let mut path = [0u8; 64];
    path[0] = b'/';
    let len = name.len().min(62);
    path[1..1 + len].copy_from_slice(&name[..len]);
    path[1 + len] = 0;

    let fd = sys_open(&path[..1 + len + 1]);
    if fd < 0 {
        print("not found\n");
        sys_exit(1);
    }

    let mut total: u64 = 0;
    let mut buf = [0u8; 512];
    loop {
        let n = sys_read(fd as u64, &mut buf);
        if n <= 0 { break; }
        total += n as u64;
    }
    sys_close(fd as u64);

    sys_write(1, name);
    print(": ");
    print_u64(total);
    print(" bytes\n");

    sys_exit(0);
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
