use rux_rt as rt;

pub fn main(argc: usize, args: &[&[u8]]) -> i32 {
    if argc < 2 {
        rt::println("usage: cat <path>");
        return 1;
    }

    // Build null-terminated path
    let name = args[1];
    let mut path = [0u8; 64];
    let len = build_absolute_path(&mut path, name);

    let fd = rt::open(&path[..len + 1]);
    if fd < 0 {
        rt::println("not found");
        return 1;
    }

    let mut buf = [0u8; 512];
    loop {
        let n = rt::read(fd as u32, &mut buf);
        if n <= 0 { break; }
        rt::write(1, &buf[..n as usize]);
    }
    rt::close(fd as u32);
    0
}

/// If path doesn't start with '/', prepend '/'. Always null-terminate.
fn build_absolute_path(out: &mut [u8], name: &[u8]) -> usize {
    let mut p = 0;
    if name.is_empty() || name[0] != b'/' {
        out[0] = b'/';
        p = 1;
    }
    for &b in name {
        if p < out.len() - 1 { out[p] = b; p += 1; }
    }
    out[p] = 0;
    p
}
