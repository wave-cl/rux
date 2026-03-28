/// Serial port (UART) operations for early console output.
///
/// # Safety
/// `init` programs hardware I/O ports (x86_64: 8250 UART at 0x3F8)
/// or MMIO registers (aarch64: PL011 at 0x0900_0000 for QEMU virt).
pub unsafe trait SerialOps {
    /// Initialize the serial port hardware.
    unsafe fn init();

    /// Write a single byte. Blocks until the transmit buffer is ready.
    fn write_byte(b: u8);

    /// Write a byte slice. Default implementation loops over `write_byte`.
    fn write_bytes(buf: &[u8]) {
        for &b in buf {
            Self::write_byte(b);
        }
    }
}
