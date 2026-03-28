use rux_rt as rt;

pub fn main(argc: usize, args: &[&[u8]]) -> i32 {
    if argc < 2 {
        rt::println("usage: wc <path>");
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

    let mut bytes: u64 = 0;
    let mut lines: u64 = 0;
    let mut words: u64 = 0;
    let mut in_word = false;
    let mut buf = [0u8; 512];

    loop {
        let n = rt::read(fd as u32, &mut buf);
        if n <= 0 { break; }
        for i in 0..n as usize {
            bytes += 1;
            match buf[i] {
                b'\n' => { lines += 1; in_word = false; }
                b' ' | b'\t' | b'\r' => { in_word = false; }
                _ => {
                    if !in_word { words += 1; in_word = true; }
                }
            }
        }
    }
    rt::close(fd as u32);

    rt::print_u64(lines);
    rt::print(" ");
    rt::print_u64(words);
    rt::print(" ");
    rt::print_u64(bytes);
    rt::print(" ");
    rt::print_bytes(name);
    rt::println("");
    0
}
