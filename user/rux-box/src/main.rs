//! rux-box: busybox-style multi-call binary for rux userspace.
//!
//! Dispatches to applets based on argv[0] basename.

#![no_std]
#![no_main]

mod init;
mod shell;
mod ls;
mod cat;
mod echo;
mod wc;
mod stat;
mod rm;
mod mkfile;
mod uname;
mod uptime;
mod hello;
mod count;
mod trivial;
mod fsops;
mod textproc;
mod info;

use rux_rt as rt;

// ── Applet dispatch table ───────────────────────────────────────────

type AppletFn = fn(usize, &[&[u8]]) -> i32;

const APPLETS: &[(&[u8], AppletFn)] = &[
    // Shell & init
    (b"sh",        |a, v| shell::main(a, v)),
    (b"ash",       |a, v| shell::main(a, v)),
    (b"init",      |a, v| init::main(a, v)),

    // Core utilities (fully implemented)
    (b"ls",        |a, v| ls::main(a, v)),
    (b"cat",       |a, v| cat::main(a, v)),
    (b"echo",      |a, v| echo::main(a, v)),
    (b"wc",        |a, v| wc::main(a, v)),
    (b"stat",      |a, v| stat::main(a, v)),
    (b"rm",        |a, v| rm::main(a, v)),
    (b"mkfile",    |a, v| mkfile::main(a, v)),
    (b"uname",     |_, _| uname::main()),
    (b"uptime",    |_, _| uptime::main()),
    (b"hello",     |_, _| hello::main()),
    (b"count",     |_, _| count::main()),

    // Trivial applets
    (b"true",      |a, v| trivial::r#true(a, v)),
    (b"false",     |a, v| trivial::r#false(a, v)),
    (b"yes",       |a, v| trivial::yes(a, v)),
    (b"pwd",       |a, v| trivial::pwd(a, v)),
    (b"hostname",  |a, v| trivial::hostname(a, v)),
    (b"basename",  |a, v| trivial::basename(a, v)),
    (b"dirname",   |a, v| trivial::dirname(a, v)),
    (b"sleep",     |a, v| trivial::sleep(a, v)),

    // Filesystem ops
    (b"mkdir",     |a, v| fsops::mkdir(a, v)),
    (b"rmdir",     |a, v| fsops::rmdir(a, v)),
    (b"touch",     |a, v| fsops::touch(a, v)),
    (b"ln",        |a, v| fsops::ln(a, v)),
    (b"cp",        |a, v| fsops::cp(a, v)),
    (b"mv",        |a, v| fsops::mv(a, v)),

    // Text processing
    (b"head",      |a, v| textproc::head(a, v)),
    (b"tail",      |a, v| textproc::tail(a, v)),
    (b"grep",      |a, v| textproc::grep(a, v)),
    (b"egrep",     |a, v| textproc::grep(a, v)),
    (b"fgrep",     |a, v| textproc::grep(a, v)),
    (b"sort",      |a, v| textproc::sort(a, v)),
    (b"uniq",      |a, v| textproc::uniq(a, v)),

    // Info
    (b"id",        |a, v| info::id(a, v)),
    (b"whoami",    |a, v| info::whoami(a, v)),
    (b"env",       |a, v| info::env(a, v)),
    (b"printenv",  |a, v| info::env(a, v)),
    (b"date",      |a, v| info::date(a, v)),
];

// ── Entry point ─────────────────────────────────────────────────────

/// Convert raw argv into safe slices.
unsafe fn argv_slice(argc: usize, argv: *const *const u8) -> [&'static [u8]; 4] {
    let mut out: [&[u8]; 4] = [b""; 4];
    for i in 0..argc.min(4) {
        let ptr = *argv.add(i);
        if !ptr.is_null() {
            let mut len = 0;
            while *ptr.add(len) != 0 { len += 1; }
            out[i] = core::slice::from_raw_parts(ptr, len);
        }
    }
    out
}

#[unsafe(no_mangle)]
extern "C" fn main(argc: usize, argv: *const *const u8) -> i32 {
    let args = unsafe { argv_slice(argc, argv) };
    let name = rt::basename(args[0]);

    // Look up in applet table
    for &(applet_name, applet_fn) in APPLETS {
        if name == applet_name {
            return applet_fn(argc, &args);
        }
    }

    // Unknown applet — stub handler (exit 127 = POSIX "command not found")
    rt::print_bytes(name);
    rt::println(": applet not yet implemented");
    127
}
