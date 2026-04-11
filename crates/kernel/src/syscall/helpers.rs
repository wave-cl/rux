/// Shared helpers for syscall implementations.

/// Read a Linux `struct timespec` from user pointer and convert to milliseconds.
/// Caps the result at `cap_ms`. Returns `cap_ms` if the pointer is invalid.
///
/// Layout: `{ tv_sec: i64, tv_nsec: i64 }` at 16 bytes.
pub fn timespec_to_ms(ptr: usize, cap_ms: usize) -> usize {
    if ptr < 0x10000 || ptr >= 0x8000_0000_0000 {
        return cap_ms; // NULL or invalid → use cap as default
    }
    if crate::uaccess::validate_user_ptr(ptr, 16).is_err() {
        return cap_ms;
    }
    unsafe {
        let sec: u64 = crate::uaccess::get_user(ptr);
        let nsec: u64 = crate::uaccess::get_user(ptr + 8);
        let ms = sec * 1000 + nsec / 1_000_000;
        if ms > cap_ms as u64 { cap_ms } else { ms as usize }
    }
}
