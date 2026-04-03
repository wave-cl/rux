/// x86_64 SMAP user access protection.
///
/// Uses stac/clac to toggle EFLAGS.AC for SMAP exemption.
/// On KVM/real hardware with CR4.SMAP enabled, stac allows supervisor
/// access to user pages. On QEMU TCG, CR4.SMAP is not set (deferred)
/// but the guards still run as no-ops for code correctness.
///
/// SMAP_ACTIVE is read with read_volatile to prevent LLVM from
/// constant-folding it to false.

static mut SMAP_ACTIVE: bool = false;

unsafe impl rux_arch::UserAccessOps for super::X86_64 {
    #[inline(always)]
    unsafe fn user_access_begin() {
        if core::ptr::read_volatile(&raw const SMAP_ACTIVE) {
            core::arch::asm!("stac", options(nostack));
        }
    }

    #[inline(always)]
    unsafe fn user_access_end() {
        if core::ptr::read_volatile(&raw const SMAP_ACTIVE) {
            core::arch::asm!("clac", options(nostack));
        }
    }

    unsafe fn enable_user_access_protection() {
        core::ptr::write_volatile(&raw mut SMAP_ACTIVE, true);
    }
}
