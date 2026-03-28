use rux_rt as rt;

pub fn main() -> i32 {
    let t = rt::ticks();
    let secs = t / 1000;
    rt::print("up ");
    rt::print_u64(secs);
    rt::println("s");
    0
}
