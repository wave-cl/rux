use rux_klib::VirtAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Interrupt {
    Timer = 32,
    Keyboard = 33,
    Cascade = 34,
    Com2 = 35,
    Com1 = 36,
    Lpt2 = 37,
    Floppy = 38,
    Lpt1 = 39,
    RtcTimer = 40,
    Acpi = 41,
    Mouse = 44,
    CoProcessor = 45,
    PrimaryAta = 46,
    SecondaryAta = 47,
}

#[derive(Debug, Default, Clone)]
#[cfg_attr(target_arch = "x86_64", repr(C, align(64)))]
#[cfg_attr(target_arch = "aarch64", repr(C, align(128)))]
pub struct CpuContext {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub cs: u64,
    pub ss: u64,
}

// ── Compile-time layout assertions ──────────────────────────────────────
// 20 × u64 = 160 bytes of data, padded to 192 by align(64).
const _: () = {
    assert!(core::mem::size_of::<CpuContext>() == 192);
    assert!(core::mem::align_of::<CpuContext>() >= 64);
};

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PageFaultInfo {
    pub addr: VirtAddr,
    pub present: bool,
    pub write: bool,
    pub user: bool,
    pub instruction_fetch: bool,
}

/// Save the current interrupt state and disable interrupts.
/// Returns true if interrupts were enabled before disabling.
#[inline(always)]
pub fn save_irqs_and_disable() -> bool {
    let flags: u64;
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {}",
            "cli",
            out(reg) flags,
            options(preserves_flags)
        );
    }
    flags & (1 << 9) != 0 // bit 9 = IF (interrupt flag)
}

/// Restore interrupt state. Re-enables interrupts if `was_enabled` is true.
#[inline(always)]
pub fn restore_irqs(was_enabled: bool) {
    if was_enabled {
        unsafe { core::arch::asm!("sti", options(nostack, preserves_flags)); }
    }
}
