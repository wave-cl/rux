/// Minimal no_std number formatting utilities.
///
/// These are kernel-wide helpers for debug output — the equivalent
/// of printk's number formatting in Linux.

/// Format a u32 as decimal into a buffer. Returns the formatted &str.
pub fn u32_to_str(buf: &mut [u8; 10], mut n: u32) -> &str {
    if n == 0 {
        buf[0] = b'0';
        return unsafe { core::str::from_utf8_unchecked(&buf[..1]) };
    }
    let mut i = 10;
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    unsafe { core::str::from_utf8_unchecked(&buf[i..]) }
}

/// Format a usize as hex into a buffer. Returns the formatted bytes.
pub fn usize_to_hex(buf: &mut [u8; 16], mut n: usize) -> &[u8] {
    if n == 0 {
        buf[0] = b'0';
        return &buf[..1];
    }
    let mut i = 16;
    while n > 0 && i > 0 {
        i -= 1;
        let digit = (n & 0xF) as u8;
        buf[i] = if digit < 10 { b'0' + digit } else { b'a' + digit - 10 };
        n >>= 4;
    }
    &buf[i..]
}
