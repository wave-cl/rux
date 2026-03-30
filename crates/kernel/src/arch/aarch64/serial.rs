/// PL011 UART serial output on aarch64 (QEMU virt machine).
/// MMIO base: 0x0900_0000.

const PL011_BASE: usize = 0x0900_0000;
const UARTDR: usize = PL011_BASE + 0x00;   // Data register
const UARTFR: usize = PL011_BASE + 0x18;   // Flag register
const UARTFR_TXFF: u32 = 1 << 5;           // Transmit FIFO full
const UARTFR_RXFE: u32 = 1 << 4;           // Receive FIFO empty

#[inline(always)]
unsafe fn mmio_write(addr: usize, val: u32) {
    core::ptr::write_volatile(addr as *mut u32, val);
}

#[inline(always)]
unsafe fn mmio_read(addr: usize) -> u32 {
    core::ptr::read_volatile(addr as *const u32)
}

/// Initialize PL011. On QEMU virt, the UART is already configured
/// by the firmware — we just need to start writing.
pub unsafe fn init() {
    // PL011 on QEMU virt is pre-initialized at 115200 baud.
    // No explicit init needed.
}

/// Write a single byte, blocking until the transmit FIFO has space.
pub fn write_byte(b: u8) {
    unsafe {
        // Wait for TXFF (transmit FIFO full) to clear
        while mmio_read(UARTFR) & UARTFR_TXFF != 0 {
            core::hint::spin_loop();
        }
        mmio_write(UARTDR, b as u32);
    }
}

/// Write a byte slice.
pub fn write_bytes(buf: &[u8]) {
    for &b in buf {
        if b == b'\n' {
            write_byte(b'\r');
        }
        write_byte(b);
    }
}

/// Write a string.
pub fn write_str(s: &str) {
    write_bytes(s.as_bytes());
}

/// Read a single byte, blocking until data is available.
pub fn read_byte() -> u8 {
    unsafe {
        // Wait for RXFE (receive FIFO empty) to clear
        while mmio_read(UARTFR) & UARTFR_RXFE != 0 {
            core::hint::spin_loop();
        }
        mmio_read(UARTDR) as u8
    }
}
