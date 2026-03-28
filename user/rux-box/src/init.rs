/// /sbin/init — minimal init process.
///
/// Prints boot message, displays /etc/motd, then execs /bin/sh.

use rux_rt as rt;

pub fn main(_argc: usize, _args: &[&[u8]]) -> i32 {
    rt::println("rux init");

    // Print /etc/motd
    let fd = rt::open(b"/etc/motd\0");
    if fd >= 0 {
        let mut buf = [0u8; 512];
        loop {
            let n = rt::read(fd as u32, &mut buf);
            if n <= 0 { break; }
            rt::write(1, &buf[..n as usize]);
        }
        rt::close(fd as u32);
    }

    // Spawn /bin/sh (replaces this process)
    rt::execve(b"/bin/sh\0", &[]);
    rt::println("init: failed to exec /bin/sh");
    rt::exit(1);
}
