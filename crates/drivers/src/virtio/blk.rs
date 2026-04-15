//! virtio-blk device driver over MMIO transport.
//!
//! Implements the `BlockDevice` trait using a single virtqueue with
//! synchronous polling. Suitable for boot-time disk access.

use crate::{BlockDevice, DriverError};
use super::mmio::{VirtioMmio, VIRTIO_MAGIC, STATUS_ACK, STATUS_DRIVER, STATUS_FEATURES_OK, STATUS_DRIVER_OK};
use super::queue::{Virtqueue, QUEUE_SIZE, DESC_F_NEXT, DESC_F_WRITE};

// ── virtio-blk request types ───────────────────────────────────────

const VIRTIO_BLK_T_IN: u32 = 0;   // read
const VIRTIO_BLK_T_OUT: u32 = 1;  // write
const VIRTIO_BLK_S_OK: u8 = 0;

/// virtio-blk request header (16 bytes).
#[repr(C)]
struct BlkReqHeader {
    typ: u32,
    _reserved: u32,
    sector: u64,
}

/// virtio-blk device over MMIO.
pub struct VirtioBlk {
    mmio: VirtioMmio,
    vq: Virtqueue,
    /// Disk capacity in 512-byte sectors.
    capacity: u64,
    /// Statically allocated request header (reused for each I/O).
    req_header: BlkReqHeader,
    /// Status byte from device.
    status_byte: u8,
}

impl VirtioBlk {
    /// Probe and initialize a virtio-blk device at the given MMIO base.
    ///
    /// `vq_pages` must point to zeroed, page-aligned memory for the virtqueue
    /// (at least `Virtqueue::total_size()` bytes, typically 2 pages = 8KB).
    ///
    /// # Safety
    /// `base` must be a valid virtio-mmio device address. `vq_pages` must be
    /// valid zeroed memory.
    pub unsafe fn new(base: usize, vq_pages: usize) -> Result<Self, DriverError> {
        let mmio = VirtioMmio::new(base);

        // Verify magic + version + device type
        let magic = mmio.magic();
        if magic != VIRTIO_MAGIC {
            return Err(DriverError::ProbeFailure);
        }
        let version = mmio.version();
        if version != 1 && version != 2 {
            return Err(DriverError::Unsupported);
        }
        let dev_id = mmio.device_id();
        if dev_id != 2 {
            return Err(DriverError::ProbeFailure);
        }

        let is_legacy = version == 1;

        // Reset device
        mmio.set_status(0);

        // Legacy: set guest page size before anything else
        if is_legacy {
            mmio.set_guest_page_size(4096);
        }

        // Acknowledge + driver
        mmio.set_status(STATUS_ACK);
        mmio.set_status(STATUS_ACK | STATUS_DRIVER);

        // Feature negotiation: accept no special features (basic read/write only)
        mmio.set_driver_features(0, 0);
        if !is_legacy {
            mmio.set_driver_features(1, 0);
        }

        if !is_legacy {
            mmio.set_status(STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK);
            if mmio.status() & STATUS_FEATURES_OK == 0 {
                mmio.set_status(STATUS_ACK | STATUS_DRIVER | 128); // FAILED
                return Err(DriverError::Unsupported);
            }
        }

        // Set up virtqueue 0
        mmio.select_queue(0);
        let max_queue = mmio.queue_num_max();
        if max_queue == 0 {
            return Err(DriverError::ProbeFailure);
        }
        let qsize = QUEUE_SIZE.min(max_queue as u16);
        mmio.set_queue_num(qsize as u32);

        let vq = Virtqueue::init(vq_pages);

        if is_legacy {
            // Legacy (v1): set queue PFN (page frame number of the descriptor table)
            let page_size = 4096u32;
            mmio.set_queue_align(page_size);
            mmio.set_queue_pfn((vq.desc_addr() / page_size as u64) as u32);
        } else {
            // Modern (v2): set individual addresses
            mmio.set_queue_desc(vq.desc_addr());
            mmio.set_queue_avail(vq.avail_addr());
            mmio.set_queue_used(vq.used_addr());
            mmio.set_queue_ready(1);
        }

        // Driver OK
        if is_legacy {
            mmio.set_status(STATUS_ACK | STATUS_DRIVER | STATUS_DRIVER_OK);
        } else {
            mmio.set_status(STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);
        }

        // Read capacity from config space (offset 0, u64 little-endian)
        let capacity = mmio.config_read64(0);

        Ok(Self {
            mmio,
            vq,
            capacity,
            req_header: BlkReqHeader { typ: 0, _reserved: 0, sector: 0 },
            status_byte: 0xFF,
        })
    }

    /// Disk capacity in 512-byte sectors.
    pub fn capacity_sectors(&self) -> u64 { self.capacity }

    /// Read a single 512-byte sector.
    ///
    /// # Safety
    /// `buf` must point to at least 512 bytes of writable memory.
    pub unsafe fn read_sector(&mut self, sector: u64, buf: *mut u8) -> Result<(), DriverError> {
        // Set up request header
        self.req_header.typ = VIRTIO_BLK_T_IN;
        self.req_header.sector = sector;
        self.status_byte = 0xFF;

        // Allocate 3-descriptor chain: header → data → status
        let head = self.vq.alloc_chain(3).ok_or(DriverError::ResourceBusy)?;

        // Descriptor 0: request header (device reads)
        let d0 = &mut *self.vq.desc.add(head as usize);
        d0.addr = crate::kva_to_phys(&self.req_header as *const BlkReqHeader as u64);
        d0.len = 16;
        d0.flags = DESC_F_NEXT;
        let d1_idx = d0.next;

        // Descriptor 1: data buffer (device writes)
        let d1 = &mut *self.vq.desc.add(d1_idx as usize);
        d1.addr = crate::kva_to_phys(buf as u64);
        d1.len = 512;
        d1.flags = DESC_F_WRITE | DESC_F_NEXT;
        let d2_idx = d1.next;

        // Descriptor 2: status byte (device writes)
        let d2 = &mut *self.vq.desc.add(d2_idx as usize);
        d2.addr = crate::kva_to_phys(&self.status_byte as *const u8 as u64);
        d2.len = 1;
        d2.flags = DESC_F_WRITE;

        // Submit and poll
        self.vq.submit(head);
        self.mmio.notify(0);
        if !self.vq.poll_used() {
            self.vq.free_chain(head);
            return Err(DriverError::Timeout);
        }
        self.vq.free_chain(head);

        if self.status_byte == VIRTIO_BLK_S_OK {
            Ok(())
        } else {
            Err(DriverError::IoError)
        }
    }
}

impl BlockDevice for VirtioBlk {
    fn block_size(&self) -> usize { 512 }
    fn block_count(&self) -> u64 { self.capacity }

    unsafe fn read_block(&self, block: u64, buf: *mut u8) -> Result<(), DriverError> {
        // Single-threaded boot-time access: use raw pointer to get mutability
        // for the request header and status byte fields.
        let this = (self as *const Self as *mut Self).as_mut().unwrap();
        this.read_sector(block, buf)
    }

    unsafe fn write_block(&mut self, block: u64, buf: *const u8) -> Result<(), DriverError> {
        self.req_header.typ = VIRTIO_BLK_T_OUT;
        self.req_header.sector = block;
        self.status_byte = 0xFF;

        let head = self.vq.alloc_chain(3).ok_or(DriverError::ResourceBusy)?;

        let d0 = &mut *self.vq.desc.add(head as usize);
        d0.addr = crate::kva_to_phys(&self.req_header as *const BlkReqHeader as u64);
        d0.len = 16;
        d0.flags = DESC_F_NEXT;
        let d1_idx = d0.next;

        let d1 = &mut *self.vq.desc.add(d1_idx as usize);
        d1.addr = crate::kva_to_phys(buf as u64);
        d1.len = 512;
        d1.flags = DESC_F_NEXT; // device reads (no WRITE flag)
        let d2_idx = d1.next;

        let d2 = &mut *self.vq.desc.add(d2_idx as usize);
        d2.addr = crate::kva_to_phys(&self.status_byte as *const u8 as u64);
        d2.len = 1;
        d2.flags = DESC_F_WRITE;

        self.vq.submit(head);
        self.mmio.notify(0);
        if !self.vq.poll_used() {
            self.vq.free_chain(head);
            return Err(DriverError::Timeout);
        }
        self.vq.free_chain(head);

        if self.status_byte == VIRTIO_BLK_S_OK { Ok(()) } else { Err(DriverError::IoError) }
    }
}

// ── Device discovery ───────────────────────────────────────────────

/// QEMU aarch64 `virt` machine: virtio-mmio devices at 0x0a000000 + i*0x200
const VIRTIO_MMIO_BASE: usize = 0x0a000000;
const VIRTIO_MMIO_STRIDE: usize = 0x200;
const VIRTIO_MMIO_COUNT: usize = 32;

/// Probe for a virtio-blk device on the MMIO bus.
/// Returns the MMIO base address of the first block device found, or None.
pub unsafe fn probe_virtio_blk() -> Option<usize> {
    for i in 0..VIRTIO_MMIO_COUNT {
        let base = VIRTIO_MMIO_BASE + i * VIRTIO_MMIO_STRIDE;
        let mmio = VirtioMmio::new(base);
        if mmio.magic() == VIRTIO_MAGIC && mmio.device_id() == 2 {
            return Some(base);
        }
    }
    None
}
