/// Trivial applets: true, false, yes, pwd, hostname, basename, dirname, sleep

use rux_rt as rt;

pub fn r#true(_argc: usize, _args: &[&[u8]]) -> i32 { 0 }
pub fn r#false(_argc: usize, _args: &[&[u8]]) -> i32 { 1 }

pub fn yes(_argc: usize, _args: &[&[u8]]) -> i32 {
    loop { rt::println("y"); }
}

pub fn pwd(_argc: usize, _args: &[&[u8]]) -> i32 {
    rt::println("/"); // ramfs has no cwd tracking yet
    0
}

pub fn hostname(_argc: usize, _args: &[&[u8]]) -> i32 {
    let fd = rt::open(b"/etc/hostname\0");
    if fd >= 0 {
        let mut buf = [0u8; 64];
        let n = rt::read(fd as u32, &mut buf);
        if n > 0 { rt::write(1, &buf[..n as usize]); }
        rt::close(fd as u32);
    } else {
        rt::println("rux");
    }
    0
}

pub fn basename(argc: usize, args: &[&[u8]]) -> i32 {
    if argc < 2 { rt::println("usage: basename <path>"); return 1; }
    let name = rt::basename(args[1]);
    rt::print_bytes(name);
    rt::println("");
    0
}

pub fn dirname(argc: usize, args: &[&[u8]]) -> i32 {
    if argc < 2 { rt::println("usage: dirname <path>"); return 1; }
    let path = args[1];
    // Find last '/'
    let mut last = 0;
    for i in 0..path.len() {
        if path[i] == b'/' { last = i; }
    }
    if last == 0 && !path.is_empty() && path[0] == b'/' {
        rt::println("/");
    } else if last == 0 {
        rt::println(".");
    } else {
        rt::write(1, &path[..last]);
        rt::println("");
    }
    0
}

pub fn sleep(argc: usize, _args: &[&[u8]]) -> i32 {
    if argc < 2 { rt::println("usage: sleep <seconds>"); return 1; }
    // Busy-wait based on ticks (1000 Hz)
    // Parse simple integer from args[1]
    // For now, just print a message since we lack a real sleep syscall
    rt::println("(sleep not implemented)");
    0
}
