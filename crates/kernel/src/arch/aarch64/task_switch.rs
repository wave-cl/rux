/// aarch64 task switch: save/restore hardware state around context switches.

unsafe impl rux_arch::TaskSwitchOps for super::Aarch64 {
    unsafe fn pid1_kstack_top() -> usize {
        crate::task_table::KSTACKS[0].as_ptr() as usize + crate::task_table::KSTACK_SIZE
    }

    unsafe fn init_pid1_hw(_kstack_top: usize) {
        // No arch-specific init needed for aarch64 PID 1
    }

    #[inline(always)]
    unsafe fn save_task_hw(saved_user_sp: &mut usize, tls: &mut u64) {
        let sp: u64;
        core::arch::asm!("mrs {}, sp_el0", out(reg) sp, options(nostack));
        *saved_user_sp = sp as usize;
        let tls_val: u64;
        core::arch::asm!("mrs {}, tpidr_el0", out(reg) tls_val, options(nostack));
        *tls = tls_val;
    }

    #[inline(always)]
    unsafe fn restore_task_hw(saved_user_sp: usize, tls: u64, _kstack_top: usize) {
        core::arch::asm!("msr sp_el0, {}", in(reg) saved_user_sp as u64, options(nostack));
        core::arch::asm!("msr tpidr_el0, {}", in(reg) tls, options(nostack));
    }

    unsafe fn switch_page_table(new_root: u64, asid: u16) {
        // ASID-tagged TTBR0: no TLB flush needed. User pages have nG=1
        // so they're ASID-tagged in the TLB. Kernel pages are Global (nG=0).
        let ttbr = (new_root & 0x0000_FFFF_FFFF_FFFF) | ((asid as u64) << 48);
        core::arch::asm!(
            "msr ttbr0_el1, {}",
            "isb",
            in(reg) ttbr,
            options(nostack),
        );
    }

    unsafe fn save_fpu(buf: *mut u8) {
        core::arch::asm!(
            "stp q0,  q1,  [{buf}]",
            "stp q2,  q3,  [{buf}, #32]",
            "stp q4,  q5,  [{buf}, #64]",
            "stp q6,  q7,  [{buf}, #96]",
            "stp q8,  q9,  [{buf}, #128]",
            "stp q10, q11, [{buf}, #160]",
            "stp q12, q13, [{buf}, #192]",
            "stp q14, q15, [{buf}, #224]",
            "stp q16, q17, [{buf}, #256]",
            "stp q18, q19, [{buf}, #288]",
            "stp q20, q21, [{buf}, #320]",
            "stp q22, q23, [{buf}, #352]",
            "stp q24, q25, [{buf}, #384]",
            "stp q26, q27, [{buf}, #416]",
            "stp q28, q29, [{buf}, #448]",
            "stp q30, q31, [{buf}, #480]",
            "mrs {tmp1}, fpcr",
            "mrs {tmp2}, fpsr",
            "str {tmp1}, [{buf}, #512]",
            "str {tmp2}, [{buf}, #520]",
            buf = in(reg) buf,
            tmp1 = out(reg) _,
            tmp2 = out(reg) _,
            options(nostack),
        );
    }

    unsafe fn restore_fpu(buf: *const u8) {
        core::arch::asm!(
            "ldp q0,  q1,  [{buf}]",
            "ldp q2,  q3,  [{buf}, #32]",
            "ldp q4,  q5,  [{buf}, #64]",
            "ldp q6,  q7,  [{buf}, #96]",
            "ldp q8,  q9,  [{buf}, #128]",
            "ldp q10, q11, [{buf}, #160]",
            "ldp q12, q13, [{buf}, #192]",
            "ldp q14, q15, [{buf}, #224]",
            "ldp q16, q17, [{buf}, #256]",
            "ldp q18, q19, [{buf}, #288]",
            "ldp q20, q21, [{buf}, #320]",
            "ldp q22, q23, [{buf}, #352]",
            "ldp q24, q25, [{buf}, #384]",
            "ldp q26, q27, [{buf}, #416]",
            "ldp q28, q29, [{buf}, #448]",
            "ldp q30, q31, [{buf}, #480]",
            "ldr {tmp1}, [{buf}, #512]",
            "ldr {tmp2}, [{buf}, #520]",
            "msr fpcr, {tmp1}",
            "msr fpsr, {tmp2}",
            buf = in(reg) buf,
            tmp1 = out(reg) _,
            tmp2 = out(reg) _,
            options(nostack),
        );
    }
}
