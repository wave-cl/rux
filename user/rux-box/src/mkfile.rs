use rux_rt as rt;

pub fn main(argc: usize, args: &[&[u8]]) -> i32 {
    if argc < 2 {
        rt::println("usage: mkfile <path>");
        return 1;
    }

    let name = args[1];
    let mut path = [0u8; 64];
    let mut p = 0;
    if name.is_empty() || name[0] != b'/' { path[0] = b'/'; p = 1; }
    for &b in name { if p < 63 { path[p] = b; p += 1; } }
    path[p] = 0;

    let fd = rt::creat(&path[..p + 1]);
    if fd < 0 {
        rt::println("error");
        return 1;
    }

    rt::print("content: ");
    let mut content = [0u8; 256];
    let n = rt::read_line(&mut content);
    // Add newline
    if n < 256 {
        content[n] = b'\n';
        rt::write(fd as u32, &content[..n + 1]);
    } else {
        rt::write(fd as u32, &content[..n]);
    }

    rt::close(fd as u32);
    rt::println("ok");
    0
}
