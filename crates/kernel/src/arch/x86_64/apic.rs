/// Local APIC (LAPIC) initialization and inter-processor interrupts.
///
/// The LAPIC is the per-CPU interrupt controller on x86_64. Each CPU has
/// its own LAPIC at MMIO base 0xFEE00000 (default, from MSR 0x1B).
/// Used for: timer interrupts, IPI (inter-processor interrupts), AP startup.

/// LAPIC register offsets (MMIO, 4-byte aligned).
const LAPIC_ID: usize      = 0x020; // Local APIC ID
#[allow(dead_code)]
const LAPIC_VERSION: usize  = 0x030;
const LAPIC_TPR: usize      = 0x080; // Task Priority Register
const LAPIC_EOI: usize      = 0x0B0; // End of Interrupt
const LAPIC_SVR: usize      = 0x0F0; // Spurious Interrupt Vector Register
const LAPIC_ICR_LO: usize   = 0x300; // Interrupt Command Register (low)
const LAPIC_ICR_HI: usize   = 0x310; // Interrupt Command Register (high)
const LAPIC_TIMER_LVT: usize = 0x320; // Timer LVT
const LAPIC_TIMER_ICR: usize = 0x380; // Timer Initial Count
#[allow(dead_code)]
const LAPIC_TIMER_CCR: usize = 0x390; // Timer Current Count
const LAPIC_TIMER_DCR: usize = 0x3E0; // Timer Divide Configuration

/// LAPIC base address (default, overridable via MSR 0x1B).
static mut LAPIC_BASE: usize = 0xFEE00000;

unsafe fn lapic_read(reg: usize) -> u32 {
    core::ptr::read_volatile((LAPIC_BASE + reg) as *const u32)
}

unsafe fn lapic_write(reg: usize, val: u32) {
    core::ptr::write_volatile((LAPIC_BASE + reg) as *mut u32, val);
}

/// Read the BSP's LAPIC ID.
pub unsafe fn bsp_id() -> u32 {
    lapic_read(LAPIC_ID) >> 24
}

/// Initialize the BSP's local APIC.
///
/// # Safety
/// Must be called after the LAPIC MMIO region is identity-mapped.
pub unsafe fn init_bsp() {
    // Read LAPIC base from MSR 0x1B
    let lo: u32;
    let hi: u32;
    core::arch::asm!("rdmsr", in("ecx") 0x1Bu32, out("eax") lo, out("edx") hi, options(nostack));
    LAPIC_BASE = ((hi as usize) << 32 | lo as usize) & !0xFFF;

    // Enable LAPIC: set SVR bit 8 (APIC Software Enable), vector 0xFF (spurious)
    let svr = lapic_read(LAPIC_SVR);
    lapic_write(LAPIC_SVR, svr | (1 << 8) | 0xFF);

    // Set task priority to 0 (accept all interrupts)
    lapic_write(LAPIC_TPR, 0);
}

/// Send End-of-Interrupt to the LAPIC.
pub unsafe fn eoi() {
    lapic_write(LAPIC_EOI, 0);
}

/// Send an IPI (Inter-Processor Interrupt) to a specific CPU.
#[allow(dead_code)]
pub unsafe fn send_ipi(target_apic_id: u32, vector: u8) {
    // Set target in ICR high
    lapic_write(LAPIC_ICR_HI, target_apic_id << 24);
    // Send fixed delivery, vector
    lapic_write(LAPIC_ICR_LO, vector as u32);
}

/// Send INIT IPI to a target CPU (for AP startup).
pub unsafe fn send_init(target_apic_id: u32) {
    lapic_write(LAPIC_ICR_HI, target_apic_id << 24);
    lapic_write(LAPIC_ICR_LO, 0x4500); // INIT, level, assert
    // Wait for delivery
    while lapic_read(LAPIC_ICR_LO) & (1 << 12) != 0 {
        core::hint::spin_loop();
    }
}

/// Send SIPI (Startup IPI) to a target CPU.
/// `vector_page` is the physical page number (address >> 12) of the AP trampoline.
pub unsafe fn send_sipi(target_apic_id: u32, vector_page: u8) {
    lapic_write(LAPIC_ICR_HI, target_apic_id << 24);
    lapic_write(LAPIC_ICR_LO, 0x4600 | vector_page as u32); // SIPI, vector
    while lapic_read(LAPIC_ICR_LO) & (1 << 12) != 0 {
        core::hint::spin_loop();
    }
}

/// Configure the LAPIC timer in periodic mode.
///
/// `vector`: interrupt vector to fire (e.g., 32 for timer)
/// `initial_count`: timer countdown value (determines frequency)
///
/// # Safety
/// Must be called after `init_bsp()`.
pub unsafe fn init_timer(vector: u8, initial_count: u32) {
    // Divide configuration: divide by 16
    lapic_write(LAPIC_TIMER_DCR, 0x03);
    // LVT Timer: vector + periodic mode (bit 17)
    lapic_write(LAPIC_TIMER_LVT, vector as u32 | (1 << 17));
    // Initial count — starts the timer
    lapic_write(LAPIC_TIMER_ICR, initial_count);
}

/// Number of CPUs detected (from ACPI MADT or CPUID, simplified for now).
/// Returns 1 for single-CPU QEMU, will be extended with MADT parsing.
#[allow(dead_code)]
pub fn cpu_count() -> usize {
    1 // TODO: parse ACPI MADT for LAPIC entries
}
