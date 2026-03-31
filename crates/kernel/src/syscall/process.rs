//! Process control, CWD, and time syscalls.

use rux_arch::{ConsoleOps, TimerOps};
type Arch = crate::arch::Arch;
/// _exit(status) — POSIX.1
pub fn exit(status: i32) -> ! {
    Arch::write_str("rux: user exit(");
    let mut buf = [0u8; 10];
    Arch::write_str(rux_klib::fmt::u32_to_str(&mut buf, status as u32));
    Arch::write_str(")\n");

    unsafe { super::PROCESS.last_child_exit = status; }

    unsafe {
        use rux_arch::VforkContext;
        if crate::arch::Arch::jmp_active() {
            crate::arch::Arch::longjmp(42);
        }
    }
    use rux_arch::ExitOps;
    crate::arch::Arch::exit(crate::arch::Arch::EXIT_SUCCESS);
}

/// waitpid(pid, wstatus, options) — POSIX.1
pub fn waitpid(_pid: usize, wstatus_ptr: usize, _options: usize) -> isize {
    unsafe {
        if !super::PROCESS.child_available { return -10; } // -ECHILD
        super::PROCESS.child_available = false;
        if wstatus_ptr != 0 {
            let status = (super::PROCESS.last_child_exit as u32) << 8;
            *(wstatus_ptr as *mut u32) = status;
        }
        42
    }
}

/// getcwd(buf, size) — POSIX.1
pub fn getcwd(buf: usize, size: usize) -> isize {
    unsafe {
        let len = super::PROCESS.cwd_path_len;
        if buf == 0 || size < len + 1 { return -34; } // -ERANGE
        let ptr = buf as *mut u8;
        for i in 0..len {
            *ptr.add(i) = super::PROCESS.cwd_path[i];
        }
        *ptr.add(len) = 0;
    }
    buf as isize
}

/// uname(buf) — POSIX.1
pub fn uname(buf: usize) -> isize {
    if buf == 0 { return -14; }
    unsafe {
        let ptr = buf as *mut u8;
        for i in 0..325 { *ptr.add(i) = 0; }
        // sysname
        for (i, &b) in b"rux".iter().enumerate() { *ptr.add(i) = b; }
        // nodename (offset 65) — read from /etc/hostname
        {
            use rux_fs::FileSystem;
            let mut name = [0u8; 64];
            let mut len = 3usize;
            name[0] = b'r'; name[1] = b'u'; name[2] = b'x';
            let fs = crate::kstate::fs();
            if let Ok(ino) = rux_fs::path::resolve_path(fs, b"/etc/hostname") {
                if let Ok(n) = fs.read(ino, 0, &mut name) {
                    len = n;
                    while len > 0 && (name[len - 1] == b'\n' || name[len - 1] == b'\r') {
                        len -= 1;
                    }
                }
            }
            for i in 0..len { *ptr.add(65 + i) = name[i]; }
        }
        // release (offset 130)
        for (i, &b) in env!("CARGO_PKG_VERSION").as_bytes().iter().enumerate() { *ptr.add(130 + i) = b; }
        // version (offset 195)
        for (i, &b) in b"#1 SMP".iter().enumerate() { *ptr.add(195 + i) = b; }
        // machine (offset 260)
        {
            use rux_arch::ArchInfo;
            for (i, &b) in crate::arch::Arch::MACHINE_NAME.iter().enumerate() {
                *ptr.add(260 + i) = b;
            }
        }
    }
    0
}
pub fn clock_gettime(_clockid: usize, tp: usize) -> isize {
    if tp == 0 { return -14; }
    let ticks = Arch::ticks();
    unsafe {
        *(tp as *mut u64) = ticks / 1000;
        *((tp + 8) as *mut u64) = (ticks % 1000) * 1_000_000;
    }
    0
}

pub fn nanosleep(req_ptr: usize) -> isize {
    if req_ptr == 0 { return -14; }
    unsafe {
        use rux_arch::HaltOps;
        let tv_sec = *(req_ptr as *const u64);
        let tv_nsec = *((req_ptr + 8) as *const u64);
        let ms = tv_sec * 1000 + tv_nsec / 1_000_000;
        // Ensure timer is running for accurate sleep
        use rux_arch::TimerControl;
        Arch::start_timer();
        let target = Arch::ticks() + ms;
        while Arch::ticks() < target {
            Arch::halt_until_interrupt();
        }
    }
    0
}

// ── Resource limits ─────────────────────────────────────────────────

/// prlimit64(pid, resource, new_limit, old_limit) — Linux
pub fn prlimit64(_pid: usize, _resource: usize, _new_limit: usize, old_limit: usize) -> isize {
    // Return RLIM_INFINITY for all resources
    if old_limit != 0 {
        unsafe {
            let rlim_infinity: u64 = !0;
            *(old_limit as *mut u64) = rlim_infinity; // rlim_cur
            *((old_limit + 8) as *mut u64) = rlim_infinity; // rlim_max
        }
    }
    0
}
