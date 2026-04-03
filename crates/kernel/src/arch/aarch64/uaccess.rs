/// aarch64 user access protection via PAN (Privileged Access Never).

static mut PAN_ACTIVE: bool = false;

unsafe impl rux_arch::UserAccessOps for super::Aarch64 {
    #[inline(always)]
    unsafe fn user_access_begin() {
        if PAN_ACTIVE {
            core::arch::asm!(".inst 0xd500409f", options(nostack)); // MSR PAN, #0
        }
    }

    #[inline(always)]
    unsafe fn user_access_end() {
        if PAN_ACTIVE {
            core::arch::asm!(".inst 0xd500419f", options(nostack)); // MSR PAN, #1
        }
    }

    unsafe fn enable_user_access_protection() {
        PAN_ACTIVE = true;
    }
}
