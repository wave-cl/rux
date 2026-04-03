/// x86_64 task switch: save/restore hardware state around context switches.

unsafe impl rux_arch::TaskSwitchOps for super::X86_64 {
    unsafe fn pid1_kstack_top() -> usize {
        super::syscall::syscall_stack_top() as usize
    }

    unsafe fn init_pid1_hw(kstack_top: usize) {
        super::syscall::CURRENT_KSTACK_TOP = kstack_top as u64;
        crate::percpu::this_cpu().syscall_kstack_top = kstack_top as u64;
    }

    #[inline(always)]
    unsafe fn save_task_hw(saved_user_sp: &mut usize, tls: &mut u64) {
        *saved_user_sp = super::syscall::SAVED_USER_RSP as usize;
        // Read IA32_FS_BASE (0xC0000100) — user TLS register
        let lo: u32;
        let hi: u32;
        core::arch::asm!(
            "rdmsr",
            in("ecx") 0xC0000100u32,
            out("eax") lo,
            out("edx") hi,
            options(nostack),
        );
        *tls = (hi as u64) << 32 | lo as u64;
    }

    #[inline(always)]
    unsafe fn restore_task_hw(saved_user_sp: usize, tls: u64, kstack_top: usize) {
        // Update per-CPU syscall state
        let pc = crate::percpu::this_cpu();
        pc.saved_user_rsp = saved_user_sp as u64;
        pc.syscall_kstack_top = kstack_top as u64;
        // Keep legacy globals in sync for compatibility
        super::syscall::SAVED_USER_RSP = saved_user_sp as u64;
        super::syscall::CURRENT_KSTACK_TOP = kstack_top as u64;
        // Write IA32_FS_BASE (0xC0000100) — user TLS register
        let lo = tls as u32;
        let hi = (tls >> 32) as u32;
        core::arch::asm!(
            "wrmsr",
            in("ecx") 0xC0000100u32,
            in("eax") lo,
            in("edx") hi,
            options(nostack),
        );
    }

    unsafe fn switch_page_table(new_root: u64, asid: u16) {
        // If PCID is enabled (CR4 bit 17), use no-flush CR3 write.
        // Otherwise, fall back to plain CR3 write (flushes TLB).
        let cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nostack));
        if cr4 & (1u64 << 17) != 0 {
            let cr3 = new_root | ((asid as u64) & 0xFFF) | (1u64 << 63);
            core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack));
        } else {
            core::arch::asm!("mov cr3, {}", in(reg) new_root, options(nostack));
        }
    }

    unsafe fn save_fpu(buf: *mut u8) {
        core::arch::asm!("fxsave64 [{}]", in(reg) buf, options(nostack));
    }

    unsafe fn restore_fpu(buf: *const u8) {
        core::arch::asm!("fxrstor64 [{}]", in(reg) buf, options(nostack));
    }
}
