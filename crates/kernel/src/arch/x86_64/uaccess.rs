/// x86_64 SMAP user access protection via EFLAGS.AC bit manipulation.
///
/// Uses pushfq/popfq instead of stac/clac so it works on QEMU TCG
/// (which does not emulate the stac/clac instructions).

static mut SMAP_ACTIVE: bool = false;

unsafe impl rux_arch::UserAccessOps for super::X86_64 {
    #[inline(always)]
    unsafe fn user_access_begin() {
        if SMAP_ACTIVE {
            // Set EFLAGS.AC to allow supervisor access to user pages.
            core::arch::asm!(
                "pushfq",
                "or qword ptr [rsp], 0x40000",
                "popfq",
            );
        }
    }

    #[inline(always)]
    unsafe fn user_access_end() {
        if SMAP_ACTIVE {
            core::arch::asm!(
                "pushfq",
                "and qword ptr [rsp], {mask}",
                "popfq",
                mask = const !0x40000u64,
            );
        }
    }

    unsafe fn enable_user_access_protection() {
        SMAP_ACTIVE = true;
    }
}
