/// PL011 UART serial I/O on aarch64 (QEMU virt machine).
/// MMIO base: 0x0900_0000.

const PL011_BASE: usize = 0x0900_0000;
const UARTDR: usize   = PL011_BASE + 0x00;   // Data register
const UARTFR: usize   = PL011_BASE + 0x18;   // Flag register
const UARTIMSC: usize = PL011_BASE + 0x38;   // Interrupt mask set/clear
const UARTCR: usize   = PL011_BASE + 0x30;   // Control register
const UARTICR: usize  = PL011_BASE + 0x44;   // Interrupt clear register
const UARTFR_TXFF: u32 = 1 << 5;             // Transmit FIFO full
const UARTFR_RXFE: u32 = 1 << 4;             // Receive FIFO empty

#[inline(always)]
unsafe fn mmio_write(addr: usize, val: u32) {
    core::ptr::write_volatile(addr as *mut u32, val);
}

#[inline(always)]
unsafe fn mmio_read(addr: usize) -> u32 {
    core::ptr::read_volatile(addr as *const u32)
}

/// Initialize PL011: enable RX interrupt so serial_irq() fires on input.
pub unsafe fn init() {
    // Enable PL011 RX interrupt (RXIM = bit 4 of UARTIMSC).
    // The GIC already has UART_IRQ 33 enabled and routed to CPU 0.
    let imsc = mmio_read(UARTIMSC);
    // Enable RX interrupt (bit 4) and RX timeout interrupt (bit 6)
    mmio_write(UARTIMSC, imsc | (1 << 4) | (1 << 6));
}

/// Spinlock for serializing UART output across CPUs.
static UART_LOCK: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn uart_lock() {
    while UART_LOCK.compare_exchange_weak(
        false, true,
        core::sync::atomic::Ordering::Acquire,
        core::sync::atomic::Ordering::Relaxed,
    ).is_err() {
        core::hint::spin_loop();
    }
}

fn uart_unlock() {
    UART_LOCK.store(false, core::sync::atomic::Ordering::Release);
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

/// Write a byte slice (locked for SMP safety).
pub fn write_bytes(buf: &[u8]) {
    uart_lock();
    for &b in buf {
        if b == b'\n' {
            write_byte(b'\r');
        }
        write_byte(b);
    }
    uart_unlock();
}

/// Write a string.
pub fn write_str(s: &str) {
    write_bytes(s.as_bytes());
}

/// Check PL011 hardware FIFO for data (non-blocking).
pub unsafe fn hw_has_data() -> bool {
    mmio_read(UARTFR) & UARTFR_RXFE == 0
}

/// Read a single byte, blocking until data is available.
/// Uses the serial ring buffer (filled by UART RX interrupt) with fallback
/// to direct FIFO read. Sleeps in WaitingForPoll state between checks,
/// matching the x86_64 pattern for efficient serial input.
pub fn read_byte() -> u8 {
    unsafe {
        // Check ring buffer first (filled by serial IRQ)
        if let Some(b) = crate::tty::serial_pop() {
            return b;
        }
        loop {
            // Direct hardware FIFO check (safety net for missed IRQ)
            if mmio_read(UARTFR) & UARTFR_RXFE == 0 {
                return mmio_read(UARTDR) as u8;
            }
            // Check ring buffer again (IRQ may have fired between checks)
            if let Some(b) = crate::tty::serial_pop() {
                return b;
            }
            // Sleep until serial IRQ wakes us via poll_wake_all()
            let task_idx = crate::task_table::current_task_idx();
            crate::task_table::TASK_TABLE[task_idx].state =
                crate::task_table::TaskState::WaitingForPoll;
            use rux_arch::TimerOps;
            let deadline = crate::arch::Arch::ticks() + 1000; // 1s safety timeout
            crate::task_table::TASK_TABLE[task_idx].wake_at = deadline;
            crate::deadline_queue::DEADLINE_QUEUE.insert(
                deadline, task_idx as u16, crate::deadline_queue::KIND_WAKE,
            );
            crate::task_table::poll_wait_register(task_idx);
            let sched = crate::scheduler::get();
            sched.tasks[task_idx].entity.state = rux_sched::TaskState::Interruptible;
            sched.dequeue_current();
            sched.need_resched |= 1u64 << crate::percpu::cpu_id() as u32;
            crate::task_table::set_current_need_resched();
            sched.schedule();
        }
    }
}

/// UART RX interrupt handler — drain hardware FIFO into the ring buffer.
/// Called from GIC handle_irq for UART_IRQ (33).
pub unsafe fn serial_irq() {
    let mut got_data = false;
    while mmio_read(UARTFR) & UARTFR_RXFE == 0 {
        crate::tty::serial_push(mmio_read(UARTDR) as u8);
        got_data = true;
    }
    mmio_write(UARTICR, (1 << 4) | (1 << 6)); // clear RX + RT interrupts
    // Wake tasks sleeping in read_byte() / poll()
    if got_data && crate::task_table::has_poll_waiters() {
        crate::task_table::poll_wake_all();
    }
}

unsafe impl rux_arch::ConsoleOps for super::Aarch64 {
    unsafe fn init() { init() }
    fn write_byte(b: u8) { write_byte(b) }
    fn read_byte() -> u8 { read_byte() }
    fn has_byte() -> bool { unsafe { mmio_read(UARTFR) & UARTFR_RXFE == 0 } }
    // write_bytes and write_str use trait defaults (identical to standalone fns)
}
