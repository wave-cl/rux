/// 8250 UART serial output on x86_64 (I/O port 0x3F8).
const COM1: u16 = 0x3F8;

#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nostack, preserves_flags));
}

#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nostack, preserves_flags));
    val
}

/// Initialize COM1 serial port at 115200 baud, 8N1.
pub unsafe fn init() {
    outb(COM1 + 1, 0x00); // Disable interrupts
    outb(COM1 + 3, 0x80); // Enable DLAB (set baud rate divisor)
    outb(COM1 + 0, 0x01); // Divisor low byte: 115200 baud
    outb(COM1 + 1, 0x00); // Divisor high byte
    outb(COM1 + 3, 0x03); // 8 bits, no parity, 1 stop bit (8N1)
    outb(COM1 + 2, 0xC7); // Enable FIFO, clear, 14-byte threshold
    outb(COM1 + 4, 0x0B); // IRQs enabled, RTS/DSR set
}

/// Write a single byte, blocking until the transmit buffer is ready.
pub fn write_byte(b: u8) {
    unsafe {
        // Wait for transmitter holding register empty (bit 5 of LSR)
        while inb(COM1 + 5) & 0x20 == 0 {
            core::hint::spin_loop();
        }
        outb(COM1, b);
    }
}

/// Write a byte slice.
pub fn write_bytes(buf: &[u8]) {
    for &b in buf {
        if b == b'\n' {
            write_byte(b'\r'); // CRLF for serial terminals
        }
        write_byte(b);
    }
}

/// Write a string.
pub fn write_str(s: &str) {
    write_bytes(s.as_bytes());
}

/// Read a single byte, blocking until data is available.
/// Uses HLT to sleep the CPU between checks — woken by any interrupt.
pub fn read_byte() -> u8 {
    unsafe {
        loop {
            // Check if data is ready (bit 0 of LSR)
            if inb(COM1 + 5) & 0x01 != 0 {
                return inb(COM1);
            }
            // Enable interrupts and halt atomically — STI + HLT
            // guarantees the CPU sleeps until the next interrupt.
            // (SYSCALL disables IF via SFMASK, so we must re-enable.)
            core::arch::asm!("sti; hlt; cli", options(nostack, nomem));
        }
    }
}

// ── Trait implementation ────────────────────────────────────────────

unsafe impl rux_arch::ConsoleOps for super::X86_64 {
    unsafe fn init() { init() }
    fn write_byte(b: u8) { write_byte(b) }
    fn read_byte() -> u8 { read_byte() }
    fn write_bytes(buf: &[u8]) { write_bytes(buf) }
    fn write_str(s: &str) { write_str(s) }
}
