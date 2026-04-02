/// x86_64 fork: child kernel stack setup and hardware state snapshot.

unsafe impl rux_arch::ForkOps for super::X86_64 {
    unsafe fn snapshot_hw_state(
        saved_user_sp: &mut usize,
        tls: &mut u64,
        pt_root: &mut u64,
    ) {
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
        // Read CR3 — page table root
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack));
        *pt_root = cr3;
    }

    unsafe fn setup_child_kstack(kstack_top: usize) -> usize {
        let w = core::mem::size_of::<u64>();
        let mut sp = kstack_top;

        // Read parent's saved registers from the current kernel stack.
        // CURRENT_KSTACK_TOP points to the top; the SYSCALL entry pushed
        // 15 values below it: rcx, r11, rbx, rbp, r12, r13, r14, r15,
        // rax, rdi, rsi, rdx, r10, r8, r9
        let parent_top = super::syscall::CURRENT_KSTACK_TOP as *const u64;

        // Push syscall frame so fork_child_sysret can pop it correctly.
        // fork_child_sysret pops: r9, r8, r10, rdx, rsi, rdi, rax, r15..rbx, r11, rcx
        // Stack grows DOWN; pops go UP.
        for i in 1..=15u64 {
            sp -= w;
            let val = *parent_top.sub(i as usize);
            if i == 9 {
                // rax slot (sub(9)): set to 0 for child fork return value
                *(sp as *mut u64) = 0;
            } else {
                *(sp as *mut u64) = val;
            }
        }

        // Push context_switch frame: r15, r14, r13, r12, rbx, rbp, rip
        // Select gs-based trampoline on KVM for correct swapgs sequencing
        sp -= w;
        let sysret_fn = if super::syscall::GS_PERCPU_ACTIVE {
            super::syscall::fork_child_sysret_gs as *const () as usize
        } else {
            super::syscall::fork_child_sysret as *const () as usize
        };
        *(sp as *mut usize) = sysret_fn; // rip
        sp -= w; *(sp as *mut usize) = 0; // rbp
        sp -= w; *(sp as *mut usize) = 0; // rbx
        sp -= w; *(sp as *mut usize) = 0; // r12
        sp -= w; *(sp as *mut usize) = 0; // r13
        sp -= w; *(sp as *mut usize) = 0; // r14
        sp -= w; *(sp as *mut usize) = 0; // r15

        sp
    }
}
