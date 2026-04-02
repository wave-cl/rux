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
}
