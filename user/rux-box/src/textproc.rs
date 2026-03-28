/// Text processing applets: head, tail, grep, sort, uniq

use rux_rt as rt;

pub fn head(argc: usize, args: &[&[u8]]) -> i32 {
    if argc < 2 { rt::println("usage: head <path>"); return 1; }
    let fd = open_arg(args[1]);
    if fd < 0 { rt::println("not found"); return 1; }

    let mut lines = 0u32;
    let mut buf = [0u8; 512];
    'outer: loop {
        let n = rt::read(fd as u32, &mut buf);
        if n <= 0 { break; }
        for i in 0..n as usize {
            rt::write(1, &buf[i..i+1]);
            if buf[i] == b'\n' {
                lines += 1;
                if lines >= 10 { break 'outer; }
            }
        }
    }
    rt::close(fd as u32);
    0
}

pub fn tail(argc: usize, args: &[&[u8]]) -> i32 {
    if argc < 2 { rt::println("usage: tail <path>"); return 1; }
    let fd = open_arg(args[1]);
    if fd < 0 { rt::println("not found"); return 1; }

    // Read entire file, then print last 10 lines
    let mut data = [0u8; 4096];
    let mut total = 0usize;
    loop {
        let n = rt::read(fd as u32, &mut data[total..]);
        if n <= 0 { break; }
        total += n as usize;
        if total >= data.len() { break; }
    }
    rt::close(fd as u32);

    // Count lines from end
    let mut lines_found = 0u32;
    let mut start = total;
    while start > 0 && lines_found < 10 {
        start -= 1;
        if data[start] == b'\n' { lines_found += 1; }
    }
    if start > 0 { start += 1; } // skip the newline we stopped at
    rt::write(1, &data[start..total]);
    0
}

pub fn grep(argc: usize, args: &[&[u8]]) -> i32 {
    if argc < 3 { rt::println("usage: grep <pattern> <path>"); return 1; }
    let pattern = args[1];
    let fd = open_arg(args[2]);
    if fd < 0 { rt::println("not found"); return 1; }

    // Read file and print lines containing pattern
    let mut data = [0u8; 4096];
    let mut total = 0usize;
    loop {
        let n = rt::read(fd as u32, &mut data[total..]);
        if n <= 0 { break; }
        total += n as usize;
        if total >= data.len() { break; }
    }
    rt::close(fd as u32);

    // Scan lines
    let mut line_start = 0;
    for i in 0..total {
        if data[i] == b'\n' || i == total - 1 {
            let line_end = if data[i] == b'\n' { i } else { i + 1 };
            let line = &data[line_start..line_end];
            if contains(line, pattern) {
                rt::write(1, line);
                rt::write(1, b"\n");
            }
            line_start = i + 1;
        }
    }
    0
}

pub fn sort(_argc: usize, _args: &[&[u8]]) -> i32 {
    rt::println("sort: not yet implemented");
    1
}

pub fn uniq(_argc: usize, _args: &[&[u8]]) -> i32 {
    rt::println("uniq: not yet implemented");
    1
}

fn open_arg(name: &[u8]) -> isize {
    let mut path = [0u8; 64];
    let mut p = 0;
    if name.is_empty() || name[0] != b'/' { path[0] = b'/'; p = 1; }
    for &b in name { if p < 63 { path[p] = b; p += 1; } }
    path[p] = 0;
    rt::open(&path[..p + 1])
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() { return true; }
    if needle.len() > haystack.len() { return false; }
    for i in 0..=haystack.len() - needle.len() {
        if &haystack[i..i + needle.len()] == needle { return true; }
    }
    false
}
