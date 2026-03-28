//! rux-box: multi-call binary for rux userspace.
//!
//! Dispatches to applets based on argv[0] basename, like busybox.

#![no_std]
#![no_main]

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

use rux_rt as rt;

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

    match name {
        b"sh" | b"shell" => shell::main(argc, &args),
        b"ls" => ls::main(argc, &args),
        b"cat" => cat::main(argc, &args),
        b"echo" => echo::main(argc, &args),
        b"wc" => wc::main(argc, &args),
        b"stat" => stat::main(argc, &args),
        b"rm" => rm::main(argc, &args),
        b"mkfile" => mkfile::main(argc, &args),
        b"uname" => uname::main(),
        b"uptime" => uptime::main(),
        b"hello" => hello::main(),
        b"count" => count::main(),
        _ => {
            rt::print("rux-box: unknown applet: ");
            rt::print_bytes(name);
            rt::println("");
            1
        }
    }
}
