/// Programmable Interval Timer (8254 PIT) — the simplest x86 timer.
/// Channel 0, mode 2 (rate generator), connected to IRQ 0 (vector 32).
///
/// We use the PIT for initial timer ticks. APIC timer can replace it later.

const PIT_CHANNEL0: u16 = 0x40;
const PIT_COMMAND: u16  = 0x43;
const PIT_FREQUENCY: u32 = 1_193_182; // base oscillator frequency in Hz

/// Current tick count (incremented by timer ISR).
static mut TICKS: u64 = 0;

/// PIT ticks per timer interrupt.
static mut DIVISOR: u32 = 0;

#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nostack, preserves_flags));
}

/// Initialize the PIT at approximately `hz` frequency.
/// Also sets up the legacy PIC to unmask IRQ 0.
pub unsafe fn init(hz: u32) {
    let div = PIT_FREQUENCY / hz;
    DIVISOR = div;

    // Channel 0, access mode lobyte/hibyte, mode 2 (rate generator)
    outb(PIT_COMMAND, 0x34);
    outb(PIT_CHANNEL0, (div & 0xFF) as u8);
    outb(PIT_CHANNEL0, ((div >> 8) & 0xFF) as u8);

    // Initialize the legacy 8259 PIC
    // ICW1: init + ICW4 needed
    outb(0x20, 0x11); // master
    outb(0xA0, 0x11); // slave
    // ICW2: vector offsets (master=32, slave=40)
    outb(0x21, 32);
    outb(0xA1, 40);
    // ICW3: master has slave on IRQ2, slave ID=2
    outb(0x21, 4);
    outb(0xA1, 2);
    // ICW4: 8086 mode
    outb(0x21, 0x01);
    outb(0xA1, 0x01);
    // Mask all IRQs except IRQ0 (timer)
    outb(0x21, 0xFE); // master: unmask IRQ0 only
    outb(0xA1, 0xFF); // slave: mask all
}

/// Send EOI to the PIC for IRQ 0.
pub unsafe fn ack() {
    outb(0x20, 0x20); // EOI to master PIC
}

/// Get the current tick count.
#[inline(always)]
pub fn ticks() -> u64 {
    unsafe { TICKS }
}

/// Increment the tick counter. Called from the timer ISR.
pub fn tick() {
    unsafe { TICKS += 1; }
}

/// Approximate nanoseconds since PIT init.
/// Accuracy: ±1ms at 1000 Hz.
pub fn now_ns() -> u64 {
    let t = ticks();
    let div = unsafe { DIVISOR } as u64;
    if div == 0 { return 0; }
    // ns = ticks * (1_000_000_000 / hz) = ticks * (divisor * 1_000_000_000 / PIT_FREQUENCY)
    t * div * 1_000_000_000 / PIT_FREQUENCY as u64
}
