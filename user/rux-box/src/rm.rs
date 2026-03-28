use rux_rt as rt;

pub fn main(argc: usize, args: &[&[u8]]) -> i32 {
    if argc < 2 {
        rt::println("usage: rm <path>");
        return 1;
    }

    let name = args[1];
    let mut path = [0u8; 64];
    let mut p = 0;
    if name.is_empty() || name[0] != b'/' { path[0] = b'/'; p = 1; }
    for &b in name { if p < 63 { path[p] = b; p += 1; } }
    path[p] = 0;

    if rt::unlink(&path[..p + 1]) < 0 {
        rt::println("not found");
        return 1;
    }
    0
}
