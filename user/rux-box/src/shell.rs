use rux_rt as rt;

/// The rux interactive shell.
/// Reads commands, parses "cmd [arg]", execs /bin/cmd via vfork+exec+wait.
pub fn main(_argc: usize, _args: &[&[u8]]) -> ! {
    loop {
        rt::print("rux$ ");

        // Read command line
        let mut line = [0u8; 64];
        let len = rt::read_line(&mut line);
        if len == 0 { continue; }

        // Check for quit
        if len == 1 && line[0] == b'q' {
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

        // Build exec path: "/bin/" + cmd + "\0"
        let mut path = [0u8; 64];
        let plen = rt::build_path(&mut path, b"/bin/", cmd);
        path[plen] = 0;

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
            // Child
            if alen > 0 {
                rt::execve(&path[..plen + 1], &arg_buf[..alen + 1]);
            } else {
                rt::execve(&path[..plen + 1], &[]);
            }
            // exec failed
            rt::println("not found");
            rt::exit(1);
        }
        // Parent
        rt::wait();
    }
    rt::exit(0);
}
