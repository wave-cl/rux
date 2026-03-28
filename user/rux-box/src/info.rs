/// Info applets: id/whoami, env/printenv, date

use rux_rt as rt;

pub fn id(_argc: usize, _args: &[&[u8]]) -> i32 {
    rt::println("uid=0(root) gid=0(root)");
    0
}

pub fn whoami(_argc: usize, _args: &[&[u8]]) -> i32 {
    rt::println("root");
    0
}

pub fn env(_argc: usize, _args: &[&[u8]]) -> i32 {
    // No real environment yet — print defaults
    rt::println("PATH=/bin:/sbin:/usr/bin:/usr/sbin");
    rt::println("HOME=/root");
    rt::println("SHELL=/bin/sh");
    rt::println("USER=root");
    0
}

pub fn date(_argc: usize, _args: &[&[u8]]) -> i32 {
    let t = rt::ticks() / 1000;
    rt::print("up ");
    rt::print_u64(t);
    rt::println("s (no RTC)");
    0
}
