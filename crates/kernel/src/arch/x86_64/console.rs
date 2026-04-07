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

/// Initialize COM1 serial port at 115200 baud, 8N1, with receive interrupts.
pub unsafe fn init() {
    outb(COM1 + 1, 0x00); // Disable interrupts during setup
    outb(COM1 + 3, 0x80); // Enable DLAB (set baud rate divisor)
    outb(COM1 + 0, 0x01); // Divisor low byte: 115200 baud
    outb(COM1 + 1, 0x00); // Divisor high byte
    outb(COM1 + 3, 0x03); // 8 bits, no parity, 1 stop bit (8N1)
    outb(COM1 + 2, 0xC7); // Enable FIFO, clear, 14-byte threshold
    outb(COM1 + 4, 0x0B); // IRQs enabled, RTS/DSR set
    // Drain any stale bytes from the FIFO before enabling RX interrupts.
    // QEMU may have leftover data from initialization or terminal setup.
    while inb(COM1 + 5) & 0x01 != 0 { let _ = inb(COM1); }
    outb(COM1 + 1, 0x01); // Enable receive data available interrupt (IER bit 0)
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

/// Read a single byte from the serial ring buffer, blocking until data arrives.
/// The ring buffer is filled by the serial IRQ handler (vector 36).
pub fn read_byte() -> u8 {
    loop {
        if let Some(b) = crate::tty::serial_pop() {
            return b;
        }
        unsafe { use rux_arch::HaltOps; super::X86_64::halt_until_interrupt(); }
    }
}

/// Serial IRQ handler — drain hardware FIFO into the ring buffer.
/// Called from interrupt_dispatch for vector 36 (IRQ 4 = COM1).
pub unsafe fn serial_irq() {
    while inb(COM1 + 5) & 0x01 != 0 {
        crate::tty::serial_push(inb(COM1));
    }
}

// ── Trait implementation ────────────────────────────────────────────

unsafe impl rux_arch::ConsoleOps for super::X86_64 {
    unsafe fn init() { init() }
    fn write_byte(b: u8) { write_byte(b) }
    fn read_byte() -> u8 { read_byte() }
    fn has_byte() -> bool { crate::tty::serial_has_data() }
    // write_bytes and write_str use trait defaults (identical to standalone fns)
}
