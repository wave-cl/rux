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
        // Check ring buffer first (filled by serial IRQ)
        if let Some(b) = crate::tty::serial_pop() {
            return b;
        }
        // No data — sleep until serial IRQ wakes us
        loop {
            // Try direct port read (in case IRQ missed)
            if inb(COM1 + 5) & 0x01 != 0 {
                return inb(COM1);
            }
            // Check ring buffer again
            if let Some(b) = crate::tty::serial_pop() {
                return b;
            }
            // Sleep: put task in WaitingForPoll, woken by serial IRQ or timer
            let task_idx = crate::task_table::current_task_idx();
            crate::task_table::TASK_TABLE[task_idx].state =
                crate::task_table::TaskState::WaitingForPoll;
            use rux_arch::TimerOps;
            crate::task_table::TASK_TABLE[task_idx].wake_at =
                super::X86_64::ticks() + 1000; // 1s timeout (re-check)
            crate::task_table::poll_wait_register(task_idx);
            let sched = crate::scheduler::get();
            sched.tasks[task_idx].entity.state = rux_sched::TaskState::Interruptible;
            sched.dequeue_current();
            sched.need_resched |= 1u64 << crate::percpu::cpu_id() as u32;
            sched.schedule();
        }
    }
}

/// Serial IRQ handler — drain hardware FIFO into the ring buffer.
/// Called from interrupt_dispatch for vector 36 (IRQ 4 = COM1).
pub unsafe fn serial_irq() {
    let mut got_data = false;
    while inb(COM1 + 5) & 0x01 != 0 {
        crate::tty::serial_push(inb(COM1));
        got_data = true;
    }
    // Wake tasks sleeping in read_byte() / poll()
    if got_data && crate::task_table::has_poll_waiters() {
        crate::task_table::poll_wake_all();
    }
}

// ── Trait implementation ────────────────────────────────────────────

unsafe impl rux_arch::ConsoleOps for super::X86_64 {
    unsafe fn init() { init() }
    fn write_byte(b: u8) { write_byte(b) }
    fn read_byte() -> u8 { read_byte() }
    fn has_byte() -> bool { unsafe { inb(COM1 + 5) & 0x01 != 0 } }
    // write_bytes and write_str use trait defaults (identical to standalone fns)
}
