/// The rux interactive shell.
/// Reads commands, resolves via PATH, execs via vfork+exec+wait.

use rux_rt as rt;

const PATH: &[&[u8]] = &[b"/bin/", b"/sbin/", b"/usr/bin/", b"/usr/sbin/"];

pub fn main(_argc: usize, _args: &[&[u8]]) -> i32 {
    loop {
        rt::print("/ # ");

        let mut line = [0u8; 64];
        let len = rt::read_line(&mut line);
        if len == 0 { continue; }

        // Check for quit
        if len == 1 && line[0] == b'q' {
            break;
        }
        if len == 4 && &line[..4] == b"exit" {
            break;
        }

        // Split into command and argument at first space
        let mut cmd_end = len;
        let mut arg_start = len;
        for i in 0..len {
            if line[i] == b' ' {
                cmd_end = i;
                arg_start = i + 1;
                break;
            }
        }
        let cmd = &line[..cmd_end];
        let arg = if arg_start < len { &line[arg_start..len] } else { &[] as &[u8] };

        // Resolve command path
        let mut path = [0u8; 64];
        let plen;

        if !cmd.is_empty() && cmd[0] == b'/' {
            // Absolute path — use directly
            let mut p = 0;
            for &b in cmd { if p < 63 { path[p] = b; p += 1; } }
            path[p] = 0;
            plen = p;
        } else {
            // Search PATH
            match resolve_cmd(cmd) {
                Some((p, l)) => { path = p; plen = l; }
                None => {
                    rt::print_bytes(cmd);
                    rt::println(": not found");
                    continue;
                }
            }
        }

        // Build null-terminated arg
        let mut arg_buf = [0u8; 64];
        let mut alen = 0;
        for &b in arg {
            if alen < 63 { arg_buf[alen] = b; alen += 1; }
        }
        arg_buf[alen] = 0;

        // vfork + exec + wait
        let pid = rt::vfork();
        if pid == 0 {
            if alen > 0 {
                rt::execve(&path[..plen + 1], &arg_buf[..alen + 1]);
            } else {
                rt::execve(&path[..plen + 1], &[]);
            }
            rt::println("exec failed");
            rt::exit(127);
        }
        rt::wait();
    }
    rt::exit(0);
}

/// Search PATH for a command. Returns (path_buf, len) or None.
fn resolve_cmd(cmd: &[u8]) -> Option<([u8; 64], usize)> {
    for &dir in PATH {
        let mut path = [0u8; 64];
        let mut p = 0;
        for &b in dir { if p < 63 { path[p] = b; p += 1; } }
        for &b in cmd { if p < 63 { path[p] = b; p += 1; } }
        path[p] = 0;

        // Try to open — if it succeeds, this path exists
        let fd = rt::open(&path[..p + 1]);
        if fd >= 0 {
            rt::close(fd as u32);
            return Some((path, p));
        }
    }
    None
}
