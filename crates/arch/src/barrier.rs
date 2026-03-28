/// Memory barrier operations. Implemented per-architecture with
/// inline assembly (mfence/lfence/sfence on x86_64, dsb/isb on aarch64).
pub trait BarrierOps {
    /// Full memory barrier (read + write ordering).
    /// x86_64: mfence. aarch64: dsb sy.
    fn mb();

    /// Read memory barrier.
    /// x86_64: lfence. aarch64: dsb ld.
    fn rmb();

    /// Write memory barrier.
    /// x86_64: sfence. aarch64: dsb st.
    fn wmb();

    /// Instruction synchronization barrier.
    /// x86_64: no direct equivalent (serializing instruction like cpuid).
    /// aarch64: isb.
    fn isb();
}

/// System register read/write. Architecture-specific:
/// x86_64: rdmsr/wrmsr. aarch64: mrs/msr.
///
/// # Safety
/// Reading/writing system registers can change CPU behavior, enable/disable
/// features, or cause faults if the register doesn't exist.
pub unsafe trait SystemRegOps {
    /// Read a system register by index.
    /// x86_64: `reg` is the MSR number. aarch64: `reg` is an encoded sysreg.
    unsafe fn read_reg(reg: u32) -> u64;

    /// Write a system register.
    unsafe fn write_reg(reg: u32, val: u64);
}
