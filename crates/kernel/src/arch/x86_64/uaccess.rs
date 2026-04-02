/// x86_64 SMAP user access protection (STAC/CLAC).

/// Whether SMAP is active (CR4.SMAP set). Checked at runtime to avoid
/// executing stac/clac when SMAP is not enabled (QEMU TCG lacks SMAP).
static mut SMAP_ACTIVE: bool = false;

unsafe impl rux_arch::UserAccessOps for super::X86_64 {
    #[inline(always)]
    unsafe fn user_access_begin() {
        if SMAP_ACTIVE {
            core::arch::asm!("stac", options(nostack));
        }
    }

    #[inline(always)]
    unsafe fn user_access_end() {
        if SMAP_ACTIVE {
            core::arch::asm!("clac", options(nostack));
        }
    }

    unsafe fn enable_user_access_protection() {
        SMAP_ACTIVE = true;
    }
}
