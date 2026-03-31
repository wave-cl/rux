//! User-space memory access helpers.
//!
//! Centralizes unsafe user-pointer reading so syscall handlers don't
//! duplicate the pattern. Future multi-process support would add page
//! table permission checks here.

/// Read a null-terminated C string from user memory.
/// Returns a slice of up to 256 bytes (excluding the null terminator).
///
/// # Safety
/// Caller must ensure `ptr` points to valid user-mapped memory.
pub unsafe fn read_user_cstr(ptr: usize) -> &'static [u8] {
    let cstr = ptr as *const u8;
    let mut len = 0usize;
    while *cstr.add(len) != 0 && len < 256 {
        len += 1;
    }
    core::slice::from_raw_parts(cstr, len)
}
