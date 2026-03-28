use rux_rt as rt;

pub fn main(argc: usize, args: &[&[u8]]) -> i32 {
    if argc < 2 {
        rt::println("usage: stat <path>");
        return 1;
    }

    let name = args[1];
    let mut path = [0u8; 64];
    let mut p = 0;
    if name.is_empty() || name[0] != b'/' { path[0] = b'/'; p = 1; }
    for &b in name { if p < 63 { path[p] = b; p += 1; } }
    path[p] = 0;

    let fd = rt::open(&path[..p + 1]);
    if fd < 0 {
        rt::println("not found");
        return 1;
    }

    let mut total: u64 = 0;
    let mut buf = [0u8; 512];
    loop {
        let n = rt::read(fd as u32, &mut buf);
        if n <= 0 { break; }
        total += n as u64;
    }
    rt::close(fd as u32);

    rt::print_bytes(name);
    rt::print(": ");
    rt::print_u64(total);
    rt::println(" bytes");
    0
}
