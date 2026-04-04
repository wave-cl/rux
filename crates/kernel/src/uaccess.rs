//! User-space memory access helpers with supervisor access protection.
//!
//! On x86_64 with CR4.SMAP enabled, the kernel cannot read/write user pages
//! unless RFLAGS.AC is set (via STAC). On aarch64, PAN is similar but deferred.
//! The arch-specific protection is provided by the UserAccessOps trait.

use rux_arch::UserAccessOps;

// ── Pointer validation ──────────────────────────────────────────────

/// Validate that a user pointer + length is entirely within user address space.
/// Returns EFAULT if the pointer is in the null guard page, in kernel space,
/// or if ptr+len overflows the user limit.
#[inline]
pub fn validate_user_ptr(ptr: usize, len: usize) -> Result<(), isize> {
    use rux_arch::MemoryLayout;
    let limit = crate::arch::Arch::USER_ADDR_LIMIT as usize;
    if ptr < 0x1000 || ptr >= limit || ptr.wrapping_add(len) > limit {
        Err(crate::errno::EFAULT)
    } else {
        Ok(())
    }
}

// ── SMAP/PAN primitives ─────────────────────────────────────────────

/// Begin user memory access (arch-specific: STAC on x86_64, no-op on aarch64).
#[inline(always)]
pub unsafe fn stac() {
    crate::arch::Arch::user_access_begin();
}

/// End user memory access (arch-specific: CLAC on x86_64, no-op on aarch64).
#[inline(always)]
pub unsafe fn clac() {
    crate::arch::Arch::user_access_end();
}

/// Enable the user access protection mechanism.
/// Called once during boot after the relevant CPU feature is enabled.
#[allow(dead_code)]
pub unsafe fn enable_smap_guards() {
    crate::arch::Arch::enable_user_access_protection();
}

// ── Typed user access helpers ───────────────────────────────────────

/// Read a single value from user memory.
#[inline(always)]
pub unsafe fn get_user<T: Copy>(addr: usize) -> T {
    stac();
    let val = core::ptr::read(addr as *const T);
    clac();
    val
}

/// Write a single value to user memory.
#[inline(always)]
pub unsafe fn put_user<T: Copy>(addr: usize, val: T) {
    stac();
    core::ptr::write(addr as *mut T, val);
    clac();
}

// ── Buffer access helpers ───────────────────────────────────────────

/// Copy bytes from user memory to kernel buffer.
#[allow(dead_code)]
pub unsafe fn copy_from_user(dst: *mut u8, src: usize, len: usize) {
    stac();
    core::ptr::copy_nonoverlapping(src as *const u8, dst, len);
    clac();
}

/// Copy bytes from kernel buffer to user memory.
#[allow(dead_code)]
pub unsafe fn copy_to_user(dst: usize, src: *const u8, len: usize) {
    stac();
    core::ptr::copy_nonoverlapping(src, dst as *mut u8, len);
    clac();
}

// ── String access ───────────────────────────────────────────────────

/// Kernel buffer for read_user_cstr (single-threaded syscall path).
static mut USTR_BUF: [u8; 257] = [0; 257];

/// Read a null-terminated C string from user memory into a kernel buffer.
/// Returns a slice of up to 256 bytes (excluding the null terminator).
///
/// The returned slice points to kernel memory (USTR_BUF), safe to use
/// after clac. Only valid until the next call to read_user_cstr.
///
/// # Safety
/// Caller must ensure `ptr` points to valid user-mapped memory.
pub unsafe fn read_user_cstr(ptr: usize) -> &'static [u8] {
    stac();
    let cstr = ptr as *const u8;
    let mut len = 0usize;
    while *cstr.add(len) != 0 && len < 256 {
        USTR_BUF[len] = *cstr.add(len);
        len += 1;
    }
    clac();
    &USTR_BUF[..len]
}
