//! virtio MMIO transport (v2).
//!
//! Register layout per virtio spec §4.2.2. All registers are 32-bit
//! little-endian at 4-byte-aligned offsets from the device base address.

use core::ptr;

// ── Register offsets ───────────────────────────────────────────────

const MAGIC_VALUE: usize = 0x000;       // 0x74726976 ("virt")
const VERSION: usize = 0x004;           // 2 for virtio-mmio v2
const DEVICE_ID: usize = 0x008;         // 1=net, 2=blk, ...
const VENDOR_ID: usize = 0x00C;
const GUEST_PAGE_SIZE: usize = 0x028; // legacy (v1) only
const DEVICE_FEATURES: usize = 0x010;
const DEVICE_FEATURES_SEL: usize = 0x014;
const DRIVER_FEATURES: usize = 0x020;
const DRIVER_FEATURES_SEL: usize = 0x024;
const QUEUE_SEL: usize = 0x030;
const QUEUE_NUM_MAX: usize = 0x034;
const QUEUE_NUM: usize = 0x038;
const QUEUE_ALIGN: usize = 0x03C;    // legacy (v1) only
const QUEUE_PFN: usize = 0x040;      // legacy (v1) only
const QUEUE_READY: usize = 0x044;
const QUEUE_NOTIFY: usize = 0x050;
const INTERRUPT_STATUS: usize = 0x060;
const INTERRUPT_ACK: usize = 0x064;
const STATUS: usize = 0x070;
const QUEUE_DESC_LOW: usize = 0x080;
const QUEUE_DESC_HIGH: usize = 0x084;
const QUEUE_AVAIL_LOW: usize = 0x090;
const QUEUE_AVAIL_HIGH: usize = 0x094;
const QUEUE_USED_LOW: usize = 0x0A0;
const QUEUE_USED_HIGH: usize = 0x0A4;
const CONFIG: usize = 0x100;

// ── Device status bits ─────────────────────────────────────────────

pub const STATUS_ACK: u32 = 1;
pub const STATUS_DRIVER: u32 = 2;
pub const STATUS_FEATURES_OK: u32 = 8;
pub const STATUS_DRIVER_OK: u32 = 4;
pub const STATUS_FAILED: u32 = 128;

// ── Magic ──────────────────────────────────────────────────────────

pub const VIRTIO_MAGIC: u32 = 0x74726976;

/// Low-level MMIO register access for a single virtio device.
pub struct VirtioMmio {
    base: usize,
}

impl VirtioMmio {
    /// Create a new MMIO accessor for a device at `base` physical address.
    pub const fn new(base: usize) -> Self {
        Self { base }
    }

    #[inline(always)]
    unsafe fn read32(&self, offset: usize) -> u32 {
        ptr::read_volatile((self.base + offset) as *const u32)
    }

    #[inline(always)]
    unsafe fn write32(&self, offset: usize, val: u32) {
        ptr::write_volatile((self.base + offset) as *mut u32, val);
    }

    // ── Identification ─────────────────────────────────────────────

    pub unsafe fn magic(&self) -> u32 { self.read32(MAGIC_VALUE) }
    pub unsafe fn version(&self) -> u32 { self.read32(VERSION) }
    pub unsafe fn device_id(&self) -> u32 { self.read32(DEVICE_ID) }
    pub unsafe fn vendor_id(&self) -> u32 { self.read32(VENDOR_ID) }

    // ── Status ─────────────────────────────────────────────────────

    pub unsafe fn status(&self) -> u32 { self.read32(STATUS) }
    pub unsafe fn set_status(&self, val: u32) { self.write32(STATUS, val); }

    // ── Feature negotiation ────────────────────────────────────────

    pub unsafe fn device_features(&self, sel: u32) -> u32 {
        self.write32(DEVICE_FEATURES_SEL, sel);
        self.read32(DEVICE_FEATURES)
    }

    pub unsafe fn set_driver_features(&self, sel: u32, val: u32) {
        self.write32(DRIVER_FEATURES_SEL, sel);
        self.write32(DRIVER_FEATURES, val);
    }

    // ── Queue setup ────────────────────────────────────────────────

    pub unsafe fn select_queue(&self, idx: u32) { self.write32(QUEUE_SEL, idx); }
    pub unsafe fn queue_num_max(&self) -> u32 { self.read32(QUEUE_NUM_MAX) }
    pub unsafe fn set_queue_num(&self, num: u32) { self.write32(QUEUE_NUM, num); }
    pub unsafe fn set_queue_ready(&self, ready: u32) { self.write32(QUEUE_READY, ready); }
    pub unsafe fn set_guest_page_size(&self, size: u32) { self.write32(GUEST_PAGE_SIZE, size); }
    pub unsafe fn set_queue_align(&self, align: u32) { self.write32(QUEUE_ALIGN, align); }
    pub unsafe fn set_queue_pfn(&self, pfn: u32) { self.write32(QUEUE_PFN, pfn); }

    pub unsafe fn set_queue_desc(&self, addr: u64) {
        self.write32(QUEUE_DESC_LOW, addr as u32);
        self.write32(QUEUE_DESC_HIGH, (addr >> 32) as u32);
    }

    pub unsafe fn set_queue_avail(&self, addr: u64) {
        self.write32(QUEUE_AVAIL_LOW, addr as u32);
        self.write32(QUEUE_AVAIL_HIGH, (addr >> 32) as u32);
    }

    pub unsafe fn set_queue_used(&self, addr: u64) {
        self.write32(QUEUE_USED_LOW, addr as u32);
        self.write32(QUEUE_USED_HIGH, (addr >> 32) as u32);
    }

    // ── Notifications ──────────────────────────────────────────────

    pub unsafe fn notify(&self, queue: u32) { self.write32(QUEUE_NOTIFY, queue); }
    pub unsafe fn interrupt_status(&self) -> u32 { self.read32(INTERRUPT_STATUS) }
    pub unsafe fn interrupt_ack(&self, val: u32) { self.write32(INTERRUPT_ACK, val); }

    // ── Config space ───────────────────────────────────────────────

    pub unsafe fn config_read8(&self, offset: usize) -> u8 {
        core::ptr::read_volatile((self.base + CONFIG + offset) as *const u8)
    }

    pub unsafe fn config_read32(&self, offset: usize) -> u32 {
        self.read32(CONFIG + offset)
    }

    pub unsafe fn config_read64(&self, offset: usize) -> u64 {
        let lo = self.read32(CONFIG + offset) as u64;
        let hi = self.read32(CONFIG + offset + 4) as u64;
        lo | (hi << 32)
    }
}
