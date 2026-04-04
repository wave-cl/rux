/// GIC-400 interrupt controller driver for QEMU virt machine.
///
/// Distributor: 0x0800_0000
/// CPU interface: 0x0801_0000

const GICD_BASE: usize = 0x0800_0000;
const GICC_BASE: usize = 0x0801_0000;

// Distributor registers
const GICD_CTLR: usize     = GICD_BASE + 0x000;  // Distributor control
const GICD_ISENABLER: usize = GICD_BASE + 0x100;  // Interrupt set-enable (32 per reg)
const GICD_IPRIORITYR: usize = GICD_BASE + 0x400; // Priority (4 per reg)
const GICD_ITARGETSR: usize = GICD_BASE + 0x800;  // Target CPU (4 per reg)

// CPU interface registers
const GICC_CTLR: usize = GICC_BASE + 0x000;  // CPU interface control
const GICC_PMR: usize  = GICC_BASE + 0x004;  // Priority mask
const GICC_IAR: usize  = GICC_BASE + 0x00C;  // Interrupt acknowledge
const GICC_EOIR: usize = GICC_BASE + 0x010;  // End of interrupt

/// Timer PPI interrupt ID (physical timer = PPI 14 = IRQ ID 30).
pub const TIMER_IRQ: u32 = 30;

#[inline(always)]
unsafe fn mmio_write(addr: usize, val: u32) {
    core::ptr::write_volatile(addr as *mut u32, val);
}

#[inline(always)]
unsafe fn mmio_read(addr: usize) -> u32 {
    core::ptr::read_volatile(addr as *const u32)
}

/// Initialize the GIC: enable distributor + CPU interface, unmask timer IRQ.
pub unsafe fn init() {
    // Enable distributor
    mmio_write(GICD_CTLR, 1);

    // Enable CPU interface, priority mask = 0xFF (accept all)
    mmio_write(GICC_PMR, 0xFF);
    mmio_write(GICC_CTLR, 1);

    // Enable timer IRQ (ID 30): set-enable bit
    let reg_idx = (TIMER_IRQ / 32) as usize;
    let bit = 1u32 << (TIMER_IRQ % 32);
    mmio_write(GICD_ISENABLER + reg_idx * 4, bit);

    // Set priority for timer IRQ to 0 (highest)
    let pri_reg = (TIMER_IRQ / 4) as usize;
    let pri_shift = (TIMER_IRQ % 4) * 8;
    let pri = mmio_read(GICD_IPRIORITYR + pri_reg * 4);
    mmio_write(GICD_IPRIORITYR + pri_reg * 4, pri & !(0xFF << pri_shift));

    // Target timer IRQ to CPU 0
    let tgt_reg = (TIMER_IRQ / 4) as usize;
    let tgt_shift = (TIMER_IRQ % 4) * 8;
    let tgt = mmio_read(GICD_ITARGETSR + tgt_reg * 4);
    mmio_write(GICD_ITARGETSR + tgt_reg * 4, tgt | (1 << tgt_shift));
}

/// Initialize the GIC CPU interface for an AP (secondary CPU).
/// The distributor is already configured by the BSP's init().
/// Each AP needs its own CPU interface enabled to receive interrupts.
pub unsafe fn init_cpu() {
    mmio_write(GICC_PMR, 0xFF);   // Accept all priorities
    mmio_write(GICC_CTLR, 1);     // Enable CPU interface
}

/// Handle an IRQ: read GICC_IAR, dispatch, write GICC_EOIR.
pub fn handle_irq() {
    unsafe {
        let irq_id = mmio_read(GICC_IAR) & 0x3FF; // bits 9:0 = interrupt ID

        if irq_id == TIMER_IRQ {
            super::timer::handle_tick();
        } else if irq_id < 1020 {
            // Spurious or unhandled
            super::console::write_str("IRQ: ");
            super::console::write_byte(b'0' + (irq_id / 10) as u8);
            super::console::write_byte(b'0' + (irq_id % 10) as u8);
            super::console::write_byte(b'\n');
        }

        // EOI
        if irq_id < 1020 {
            mmio_write(GICC_EOIR, irq_id);
        }
    }
}

/// Enable IRQs (unmask).
pub unsafe fn enable_irqs() {
    core::arch::asm!("msr daifclr, #2", options(nostack)); // clear IRQ mask
}

/// Disable IRQs (mask).
#[allow(dead_code)]
pub unsafe fn disable_irqs() {
    core::arch::asm!("msr daifset, #2", options(nostack)); // set IRQ mask
}
