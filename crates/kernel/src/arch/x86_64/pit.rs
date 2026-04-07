/// Programmable Interval Timer (8254 PIT) — the simplest x86 timer.

use core::sync::atomic::{AtomicU64, AtomicU32, Ordering};

const PIT_CHANNEL0: u16 = 0x40;
const PIT_COMMAND: u16  = 0x43;
const PIT_FREQUENCY: u32 = 1_193_182;

static TICKS: AtomicU64 = AtomicU64::new(0);
static DIVISOR: AtomicU32 = AtomicU32::new(0);

#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nostack, preserves_flags));
}

pub unsafe fn init(hz: u32) {
    let div = PIT_FREQUENCY / hz;
    DIVISOR.store(div, Ordering::Relaxed);

    outb(PIT_COMMAND, 0x34);
    outb(PIT_CHANNEL0, (div & 0xFF) as u8);
    outb(PIT_CHANNEL0, ((div >> 8) & 0xFF) as u8);

    outb(0x20, 0x11);
    outb(0xA0, 0x11);
    outb(0x21, 32);
    outb(0xA1, 40);
    outb(0x21, 4);
    outb(0xA1, 2);
    outb(0x21, 0x01);
    outb(0xA1, 0x01);
    outb(0x21, 0xFE);
    outb(0xA1, 0xFF);
}

pub unsafe fn ack() {
    outb(0x20, 0x20);
}

#[inline(always)]
pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

pub fn tick() {
    TICKS.fetch_add(1, Ordering::Relaxed);
}

/// Stop the PIT timer by masking IRQ0 at the PIC.
pub unsafe fn stop_timer() {
    let mask: u8;
    core::arch::asm!("in al, dx", out("al") mask, in("dx") 0x21u16, options(nostack, preserves_flags));
    outb(0x21, mask | 0x01);
}

/// Restart the PIT timer by unmasking IRQ0 at the PIC.
pub unsafe fn start_timer() {
    let mask: u8;
    core::arch::asm!("in al, dx", out("al") mask, in("dx") 0x21u16, options(nostack, preserves_flags));
    outb(0x21, mask & !0x01);
}

#[allow(dead_code)]
pub fn now_ns() -> u64 {
    let t = ticks();
    let div = DIVISOR.load(Ordering::Relaxed) as u64;
    if div == 0 { return 0; }
    t * div * 1_000_000_000 / PIT_FREQUENCY as u64
}
