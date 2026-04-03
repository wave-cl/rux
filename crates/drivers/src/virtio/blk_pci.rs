//! virtio-blk over PCI transport (legacy/transitional).
//!
//! Uses I/O port-based config space from BAR0. For x86_64 QEMU `pc` machine.

use crate::{BlockDevice, DriverError};
use crate::pci;
use super::pci::VirtioPci;
use super::queue::{Virtqueue, Descriptor, QUEUE_SIZE, DESC_F_NEXT, DESC_F_WRITE};

const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_S_OK: u8 = 0;

const STATUS_ACK: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;

/// virtio-blk request header (16 bytes).
#[repr(C)]
struct BlkReqHeader {
    typ: u32,
    _reserved: u32,
    sector: u64,
}

/// virtio-blk device over PCI transport.
pub struct VirtioBlkPci {
    pci_dev: VirtioPci,
    vq: Virtqueue,
    capacity: u64,
    req_header: BlkReqHeader,
    status_byte: u8,
}

impl VirtioBlkPci {
    /// Probe PCI bus for a virtio-blk device and initialize it.
    ///
    /// `vq_pages` must point to zeroed, page-aligned memory for the virtqueue.
    ///
    /// # Safety
    /// Must be called during boot with valid memory.
    pub unsafe fn probe(vq_pages: usize) -> Result<Self, DriverError> {
        // Find virtio-blk on PCI bus (try legacy ID first, then modern)
        let dev = pci::find_device(pci::VIRTIO_VENDOR, pci::VIRTIO_BLK_LEGACY)
            .or_else(|| pci::find_device(pci::VIRTIO_VENDOR, pci::VIRTIO_BLK_MODERN))
            .ok_or(DriverError::ProbeFailure)?;

        // BAR0 should be an I/O port region (bit 0 = 1 for I/O space)
        if dev.bar0 & 1 == 0 {
            return Err(DriverError::Unsupported); // MMIO BAR, not I/O port
        }
        let io_base = (dev.bar0 & 0xFFFC) as u16;

        // Enable bus mastering for DMA
        pci::enable_bus_master(dev.addr);

        let pci_dev = VirtioPci::new(io_base);

        // Reset
        pci_dev.set_status(0);

        // Acknowledge + driver
        pci_dev.set_status(STATUS_ACK);
        pci_dev.set_status(STATUS_ACK | STATUS_DRIVER);

        // Feature negotiation: accept no special features
        let _features = pci_dev.device_features();
        pci_dev.set_driver_features(0);

        // Set up virtqueue 0
        pci_dev.select_queue(0);
        let dev_queue_size = pci_dev.queue_size();
        if dev_queue_size == 0 {
            return Err(DriverError::ProbeFailure);
        }
        // Use device's queue size (legacy PCI: fixed by device, can't change)
        let vq = Virtqueue::init_with_size(vq_pages, dev_queue_size);
        // Legacy PCI: write PFN of queue (page frame number, 4096-byte pages)
        pci_dev.set_queue_addr((vq.desc_addr() / 4096) as u32);

        // Driver OK
        pci_dev.set_status(STATUS_ACK | STATUS_DRIVER | STATUS_DRIVER_OK);

        // Read capacity
        let capacity = pci_dev.blk_capacity();

        Ok(Self {
            pci_dev,
            vq,
            capacity,
            req_header: BlkReqHeader { typ: 0, _reserved: 0, sector: 0 },
            status_byte: 0xFF,
        })
    }

    pub fn capacity_sectors(&self) -> u64 { self.capacity }

    pub unsafe fn read_sector(&mut self, sector: u64, buf: *mut u8) -> Result<(), DriverError> {
        self.req_header.typ = VIRTIO_BLK_T_IN;
        self.req_header.sector = sector;
        self.status_byte = 0xFF;

        let head = self.vq.alloc_chain(3).ok_or(DriverError::ResourceBusy)?;

        // Descriptor 0: request header
        let d0 = &mut *self.vq.desc.add(head as usize);
        d0.addr = &self.req_header as *const BlkReqHeader as u64;
        d0.len = 16;
        d0.flags = DESC_F_NEXT;
        let d1_idx = d0.next;

        // Descriptor 1: data buffer (device writes)
        let d1 = &mut *self.vq.desc.add(d1_idx as usize);
        d1.addr = buf as u64;
        d1.len = 512;
        d1.flags = DESC_F_WRITE | DESC_F_NEXT;
        let d2_idx = d1.next;

        // Descriptor 2: status byte (device writes)
        let d2 = &mut *self.vq.desc.add(d2_idx as usize);
        d2.addr = &self.status_byte as *const u8 as u64;
        d2.len = 1;
        d2.flags = DESC_F_WRITE;

        self.vq.submit(head);
        self.pci_dev.notify(0);
        self.vq.poll_used();
        self.vq.free_chain(head);

        if self.status_byte == VIRTIO_BLK_S_OK {
            Ok(())
        } else {
            Err(DriverError::IoError)
        }
    }
}

impl BlockDevice for VirtioBlkPci {
    fn block_size(&self) -> usize { 512 }
    fn block_count(&self) -> u64 { self.capacity }

    unsafe fn read_block(&self, block: u64, buf: *mut u8) -> Result<(), DriverError> {
        let this = (self as *const Self as *mut Self).as_mut().unwrap();
        this.read_sector(block, buf)
    }

    unsafe fn write_block(&mut self, _block: u64, _buf: *const u8) -> Result<(), DriverError> {
        Err(DriverError::Unsupported)
    }
}
