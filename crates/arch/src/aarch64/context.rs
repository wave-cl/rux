use rux_klib::VirtAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interrupt {
    Sgi(u8),
    Ppi(u8),
    Spi(u16),
}

#[derive(Debug, Default, Clone)]
#[cfg_attr(target_arch = "x86_64", repr(C, align(64)))]
#[cfg_attr(target_arch = "aarch64", repr(C, align(128)))]
pub struct CpuContext {
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
    pub x4: u64,
    pub x5: u64,
    pub x6: u64,
    pub x7: u64,
    pub x8: u64,
    pub x9: u64,
    pub x10: u64,
    pub x11: u64,
    pub x12: u64,
    pub x13: u64,
    pub x14: u64,
    pub x15: u64,
    pub x16: u64,
    pub x17: u64,
    pub x18: u64,
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub x29: u64,
    pub x30: u64,
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

// 34 × u64 = 272 bytes of data, padded to 384 by align(128).
#[cfg(target_arch = "aarch64")]
const _: () = {
    assert!(core::mem::size_of::<CpuContext>() == 384);
    assert!(core::mem::align_of::<CpuContext>() >= 128);
};

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PageFaultInfo {
    pub addr: VirtAddr,
    pub is_write: bool,
    pub is_translation_fault: bool,
    pub is_permission_fault: bool,
    pub el: u8,
}

#[derive(Clone, Copy)]
#[repr(C, align(16))]
pub struct FpuState {
    pub vregs: [u128; 32],
    pub fpcr: u64,
    pub fpsr: u64,
}
impl FpuState {
    pub const fn new() -> Self { Self { vregs: [0u128; 32], fpcr: 0, fpsr: 0 } }
}

/// Save the current interrupt state and disable IRQs.
/// Returns true if IRQs were enabled before disabling.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub fn save_irqs_and_disable() -> bool {
    let daif: u64;
    unsafe {
        core::arch::asm!("mrs {}, daif", out(reg) daif, options(nostack));
        core::arch::asm!("msr daifset, #2", options(nostack)); // mask IRQ
    }
    daif & (1 << 7) == 0 // bit 7 = I (IRQ mask). 0 = enabled, 1 = masked
}

/// Restore interrupt state. Unmasks IRQs if `was_enabled` is true.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub fn restore_irqs(was_enabled: bool) {
    if was_enabled {
        unsafe { core::arch::asm!("msr daifclr, #2", options(nostack)); }
    }
}
