use rux_rt as rt;

pub fn main() -> i32 {
    #[cfg(target_arch = "x86_64")]
    rt::println("rux 0.3.0 x86_64");
    #[cfg(target_arch = "aarch64")]
    rt::println("rux 0.3.0 aarch64");
    0
}
