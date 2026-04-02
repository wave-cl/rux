/// aarch64 user access protection (PAN — deferred, currently no-ops).

unsafe impl rux_arch::UserAccessOps for super::Aarch64 {
    #[inline(always)]
    unsafe fn user_access_begin() {}

    #[inline(always)]
    unsafe fn user_access_end() {}
}
