/// aarch64 fork: child kernel stack setup and hardware state snapshot.

unsafe impl rux_arch::ForkOps for super::Aarch64 {
    unsafe fn snapshot_hw_state(
        saved_user_sp: &mut usize,
        tls: &mut u64,
        pt_root: &mut u64,
    ) {
        let sp: u64;
        core::arch::asm!("mrs {}, sp_el0", out(reg) sp, options(nostack));
        *saved_user_sp = sp as usize;
        let tls_val: u64;
        core::arch::asm!("mrs {}, tpidr_el0", out(reg) tls_val, options(nostack));
        *tls = tls_val;
        let ttbr: u64;
        core::arch::asm!("mrs {}, ttbr0_el1", out(reg) ttbr, options(nostack));
        *pt_root = ttbr & 0x0000_FFFF_FFFF_FFFF; // mask out ASID bits [63:48]
    }

    unsafe fn setup_child_kstack(kstack_top: usize) -> usize {
        // The parent's exception frame (34 u64s = 272 bytes) is on the current
        // kernel stack. CURRENT_REGS_PTR points to the base of this frame.
        let parent_regs = super::syscall::CURRENT_REGS_PTR_PERCPU[crate::percpu::cpu_id()];

        let mut sp = kstack_top & !0xF; // 16-byte align

        // Push exception frame (272 bytes)
        sp -= 272;
        let frame = sp as *mut u64;
        for i in 0..34 {
            *frame.add(i) = *parent_regs.add(i);
        }
        // x0 = 0 (fork return value for child)
        *frame.add(0) = 0;

        // Push context_switch callee-saved frame (6 pairs = 96 bytes)
        sp -= 96;
        let ctx = sp as *mut usize;
        *ctx.add(0) = 0; // x29 (FP)
        *ctx.add(1) = super::context::fork_child_eret as *const () as usize; // x30 (LR)
        for i in 2..12 {
            *ctx.add(i) = 0;
        } // x27-x20, x19

        sp
    }
}
