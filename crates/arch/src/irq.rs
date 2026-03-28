/// Interrupt handler function type.
/// Called with the vector number when an IRQ fires.
pub type InterruptHandler = unsafe extern "C" fn(vector: u32);

/// Exception handler function type.
/// Called with the vector number, error code (0 if none), and a pointer
/// to the saved CPU context on the kernel stack.
pub type ExceptionHandler = unsafe extern "C" fn(
    vector: u32,
    error_code: u64,
    frame: *mut u8, // opaque — cast to arch-specific CpuContext
);

/// Interrupt controller and vector table operations.
///
/// # Safety
/// `init` sets up the GDT/IDT/TSS (x86_64) or VBAR_EL1 (aarch64).
/// `enable`/`disable` toggle hardware interrupt delivery.
/// `register_irq`/`register_exception` modify the interrupt dispatch table.
pub unsafe trait InterruptOps {
    /// One-time initialization: set up interrupt descriptor table,
    /// configure the interrupt controller (APIC on x86_64, GIC on aarch64).
    unsafe fn init();

    /// Register a handler for a hardware IRQ vector.
    unsafe fn register_irq(vector: u32, handler: InterruptHandler);

    /// Register a handler for a CPU exception vector.
    unsafe fn register_exception(vector: u32, handler: ExceptionHandler);

    /// Enable hardware interrupts (sti on x86_64, msr daifclr on aarch64).
    unsafe fn enable();

    /// Disable hardware interrupts (cli on x86_64, msr daifset on aarch64).
    unsafe fn disable();

    /// Check if interrupts are currently enabled.
    fn is_enabled() -> bool;

    /// Send end-of-interrupt for the given vector.
    /// x86_64: write APIC EOI register. aarch64: write ICC_EOIR1_EL1.
    unsafe fn eoi(vector: u32);
}
