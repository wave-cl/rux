//! virtio-pci transport (legacy/transitional).
//!
//! Legacy virtio-pci uses BAR0 as an I/O port region with a flat register
//! layout. This avoids the complexity of modern virtio-pci capabilities.
//! QEMU's virtio-blk-pci device supports both legacy and modern modes.

use core::ptr;

// ── Legacy virtio-pci I/O port offsets ─────────────────────────────
// (relative to BAR0 I/O port base)

const DEVICE_FEATURES: u16 = 0x00;   // 32-bit, read
const DRIVER_FEATURES: u16 = 0x04;   // 32-bit, write
const QUEUE_ADDR: u16 = 0x08;        // 32-bit, write (PFN of queue, guest page size = 4096)
const QUEUE_SIZE: u16 = 0x0C;        // 16-bit, read
const QUEUE_SELECT: u16 = 0x0E;      // 16-bit, write
const QUEUE_NOTIFY: u16 = 0x10;      // 16-bit, write
const DEVICE_STATUS: u16 = 0x12;     // 8-bit, read/write
const ISR_STATUS: u16 = 0x13;        // 8-bit, read
// Device-specific config starts at offset 0x14
const DEVICE_CONFIG: u16 = 0x14;

/// Legacy virtio-pci device accessed via I/O ports (x86 only).
pub struct VirtioPci {
    /// BAR0 I/O port base address.
    io_base: u16,
}

impl VirtioPci {
    pub const fn new(io_base: u16) -> Self {
        Self { io_base }
    }

    // ── Port I/O helpers ───────────────────────────────────────────

    #[inline(always)]
    unsafe fn outb(&self, offset: u16, val: u8) {
        let port = self.io_base + offset;
        core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nostack));
    }

    #[inline(always)]
    unsafe fn outw(&self, offset: u16, val: u16) {
        let port = self.io_base + offset;
        core::arch::asm!("out dx, ax", in("dx") port, in("ax") val, options(nostack));
    }

    #[inline(always)]
    unsafe fn outl(&self, offset: u16, val: u32) {
        let port = self.io_base + offset;
        core::arch::asm!("out dx, eax", in("dx") port, in("eax") val, options(nostack));
    }

    #[inline(always)]
    unsafe fn inb(&self, offset: u16) -> u8 {
        let port = self.io_base + offset;
        let val: u8;
        core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nostack));
        val
    }

    #[inline(always)]
    unsafe fn inw(&self, offset: u16) -> u16 {
        let port = self.io_base + offset;
        let val: u16;
        core::arch::asm!("in ax, dx", out("ax") val, in("dx") port, options(nostack));
        val
    }

    #[inline(always)]
    unsafe fn inl(&self, offset: u16) -> u32 {
        let port = self.io_base + offset;
        let val: u32;
        core::arch::asm!("in eax, dx", out("eax") val, in("dx") port, options(nostack));
        val
    }

    // ── Status ─────────────────────────────────────────────────────

    pub unsafe fn status(&self) -> u8 { self.inb(DEVICE_STATUS) }
    pub unsafe fn set_status(&self, val: u8) { self.outb(DEVICE_STATUS, val); }

    // ── Feature negotiation ────────────────────────────────────────

    pub unsafe fn device_features(&self) -> u32 { self.inl(DEVICE_FEATURES) }
    pub unsafe fn set_driver_features(&self, val: u32) { self.outl(DRIVER_FEATURES, val); }

    // ── Queue setup ────────────────────────────────────────────────

    pub unsafe fn select_queue(&self, idx: u16) { self.outw(QUEUE_SELECT, idx); }
    pub unsafe fn queue_size(&self) -> u16 { self.inw(QUEUE_SIZE) }
    pub unsafe fn set_queue_addr(&self, pfn: u32) { self.outl(QUEUE_ADDR, pfn); }

    // ── Notifications ──────────────────────────────────────────────

    pub unsafe fn notify(&self, queue: u16) { self.outw(QUEUE_NOTIFY, queue); }
    pub unsafe fn isr_status(&self) -> u8 { self.inb(ISR_STATUS) }

    // ── Device-specific config ─────────────────────────────────────

    /// Read virtio-blk capacity (sectors) from device config.
    /// Config offset 0 = capacity (u64 LE).
    pub unsafe fn blk_capacity(&self) -> u64 {
        let lo = self.inl(DEVICE_CONFIG) as u64;
        let hi = self.inl(DEVICE_CONFIG + 4) as u64;
        lo | (hi << 32)
    }
}
