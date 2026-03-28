use rux_rt as rt;

pub fn main(_argc: usize, _args: &[&[u8]]) -> i32 {
    let mut buf = [0u8; 4096];
    let n = rt::getdents(&mut buf);
    if n > 0 {
        rt::write(1, &buf[..n as usize]);
    }
    0
}
