/// Filesystem operation applets: mkdir, rmdir, touch, ln, cp, mv

use rux_rt as rt;

pub fn mkdir(argc: usize, args: &[&[u8]]) -> i32 {
    if argc < 2 { rt::println("usage: mkdir <path>"); return 1; }
    let mut path = [0u8; 64];
    let len = make_path(&mut path, args[1]);
    if rt::mkdir(&path[..len + 1]) < 0 {
        rt::println("mkdir: failed");
        return 1;
    }
    0
}

pub fn rmdir(argc: usize, args: &[&[u8]]) -> i32 {
    if argc < 2 { rt::println("usage: rmdir <path>"); return 1; }
    // rmdir not yet in rustrt — use unlink for now
    rt::println("rmdir: not yet implemented");
    1
}

pub fn touch(argc: usize, args: &[&[u8]]) -> i32 {
    if argc < 2 { rt::println("usage: touch <path>"); return 1; }
    let mut path = [0u8; 64];
    let len = make_path(&mut path, args[1]);
    let fd = rt::creat(&path[..len + 1]);
    if fd >= 0 {
        rt::close(fd as u32);
        0
    } else {
        // File might already exist — try to open it
        let fd = rt::open(&path[..len + 1]);
        if fd >= 0 { rt::close(fd as u32); 0 }
        else { rt::println("touch: failed"); 1 }
    }
}

pub fn ln(_argc: usize, _args: &[&[u8]]) -> i32 {
    rt::println("ln: not yet implemented");
    1
}

pub fn cp(_argc: usize, _args: &[&[u8]]) -> i32 {
    rt::println("cp: not yet implemented");
    1
}

pub fn mv(_argc: usize, _args: &[&[u8]]) -> i32 {
    rt::println("mv: not yet implemented");
    1
}

fn make_path(out: &mut [u8], name: &[u8]) -> usize {
    let mut p = 0;
    if name.is_empty() || name[0] != b'/' { out[0] = b'/'; p = 1; }
    for &b in name { if p < out.len() - 1 { out[p] = b; p += 1; } }
    out[p] = 0;
    p
}
