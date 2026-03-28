use rux_rt as rt;

pub fn main(argc: usize, args: &[&[u8]]) -> i32 {
    if argc >= 2 {
        rt::print_bytes(args[1]);
    }
    rt::println("");
    0
}
