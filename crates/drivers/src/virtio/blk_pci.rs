//! virtio-blk over PCI transport (legacy/transitional).
//!
//! All mutable state lives in a global static (PCI_STATE) to avoid
//! issues with struct moves invalidating interior pointers. The
//! VirtioBlkPci struct is a thin handle.

use crate::{BlockDevice, DriverError};
use crate::pci;
use super::pci::VirtioPci;
use super::queue::{Descriptor, DESC_F_NEXT, DESC_F_WRITE};
use core::sync::atomic::{fence, Ordering};

const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_S_OK: u8 = 0;

const STATUS_ACK: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;

#[repr(C)]
struct BlkReqHeader {
    typ: u32,
    _reserved: u32,
    sector: u64,
}

/// All mutable state for the PCI virtio-blk device.
struct PciState {
    io_base: u16,
    capacity: u64,
    // Virtqueue state (inline, no separate struct)
    desc_base: usize,       // physical addr of descriptor table
    avail_base: usize,      // physical addr of available ring
    used_base: usize,       // physical addr of used ring
    queue_size: u16,
    free_head: u16,
    num_free: u16,
    avail_idx: u16,
    last_used_idx: u16,
    // Per-request buffers
    req_header: BlkReqHeader,
    status_byte: u8,
    initialized: bool,
}

static mut STATE: PciState = PciState {
    io_base: 0, capacity: 0,
    desc_base: 0, avail_base: 0, used_base: 0,
    queue_size: 0, free_head: 0, num_free: 0,
    avail_idx: 0, last_used_idx: 0,
    req_header: BlkReqHeader { typ: 0, _reserved: 0, sector: 0 },
    status_byte: 0xFF, initialized: false,
};

/// Thin handle to the PCI virtio-blk device. All state is in a static.
pub struct VirtioBlkPci {
    _dummy: (),
}

impl VirtioBlkPci {
    pub unsafe fn probe(vq_pages: usize) -> Result<Self, DriverError> {
        let dev = pci::find_device(pci::VIRTIO_VENDOR, pci::VIRTIO_BLK_LEGACY)
            .or_else(|| pci::find_device(pci::VIRTIO_VENDOR, pci::VIRTIO_BLK_MODERN))
            .ok_or(DriverError::ProbeFailure)?;

        if dev.bar0 & 1 == 0 { return Err(DriverError::Unsupported); }
        let io_base = (dev.bar0 & 0xFFFC) as u16;
        pci::enable_bus_master(dev.addr);

        let pci_dev = VirtioPci::new(io_base);

        // Reset + init
        pci_dev.set_status(0);
        pci_dev.set_status(STATUS_ACK);
        pci_dev.set_status(STATUS_ACK | STATUS_DRIVER);
        let _features = pci_dev.device_features();
        pci_dev.set_driver_features(0);

        // Queue setup
        pci_dev.select_queue(0);
        let qsize = pci_dev.queue_size();
        if qsize == 0 { return Err(DriverError::ProbeFailure); }

        // Initialize descriptor chain in vq_pages memory
        let desc_base = vq_pages;
        let avail_off = 16 * qsize as usize;
        let avail_base = vq_pages + avail_off;
        let avail_end = avail_off + 4 + 2 * qsize as usize + 2;
        let used_off = (avail_end + 0xFFF) & !0xFFF;
        let used_base = vq_pages + used_off;

        // Chain free descriptors
        let desc = desc_base as *mut Descriptor;
        for i in 0..qsize {
            let d = &mut *desc.add(i as usize);
            d.next = if i + 1 < qsize { i + 1 } else { 0 };
            d.flags = 0;
            d.addr = 0;
            d.len = 0;
        }

        // Write PFN to device
        pci_dev.set_queue_addr((desc_base / 4096) as u32);

        // Driver OK
        pci_dev.set_status(STATUS_ACK | STATUS_DRIVER | STATUS_DRIVER_OK);

        let capacity = pci_dev.blk_capacity();

        // Store all state in the global
        STATE.io_base = io_base;
        STATE.capacity = capacity;
        STATE.desc_base = desc_base;
        STATE.avail_base = avail_base;
        STATE.used_base = used_base;
        STATE.queue_size = qsize;
        STATE.free_head = 0;
        STATE.num_free = qsize;
        STATE.avail_idx = 0;
        STATE.last_used_idx = 0;
        STATE.initialized = true;

        Ok(Self { _dummy: () })
    }

    pub fn capacity_sectors(&self) -> u64 {
        unsafe { STATE.capacity }
    }
}

/// Read a single sector using the global PCI state.
unsafe fn pci_read_sector(sector: u64, buf: *mut u8) -> Result<(), DriverError> {
    if !STATE.initialized { return Err(DriverError::InvalidState); }
    if STATE.num_free < 3 { return Err(DriverError::ResourceBusy); }

    STATE.req_header.typ = VIRTIO_BLK_T_IN;
    STATE.req_header.sector = sector;
    STATE.status_byte = 0xFF;

    let desc = STATE.desc_base as *mut Descriptor;
    let qsize = STATE.queue_size;

    // Alloc 3 descriptors from free list
    let head = STATE.free_head;
    let mut idx = head;
    for i in 0..3u16 {
        let d = &mut *desc.add(idx as usize);
        if i < 2 {
            d.flags |= DESC_F_NEXT;
            idx = d.next;
        } else {
            d.flags &= !DESC_F_NEXT;
            STATE.free_head = d.next;
        }
    }
    STATE.num_free -= 3;

    // Set up descriptors
    let d0 = &mut *desc.add(head as usize);
    d0.addr = &raw const STATE.req_header as u64;
    d0.len = 16;
    d0.flags = DESC_F_NEXT;
    let d1_idx = d0.next;

    let d1 = &mut *desc.add(d1_idx as usize);
    d1.addr = buf as u64;
    d1.len = 512;
    d1.flags = DESC_F_WRITE | DESC_F_NEXT;
    let d2_idx = d1.next;

    let d2 = &mut *desc.add(d2_idx as usize);
    d2.addr = &raw const STATE.status_byte as u64;
    d2.len = 1;
    d2.flags = DESC_F_WRITE;

    // Submit to available ring
    let avail_flags = STATE.avail_base as *mut u16;
    let avail_idx_ptr = (STATE.avail_base + 2) as *mut u16;
    let avail_ring = (STATE.avail_base + 4) as *mut u16;

    let ai = STATE.avail_idx;
    *avail_ring.add((ai % qsize) as usize) = head;
    fence(Ordering::Release);
    STATE.avail_idx = ai.wrapping_add(1);
    *avail_idx_ptr = STATE.avail_idx;
    fence(Ordering::Release);

    // Notify device
    let pci = VirtioPci::new(STATE.io_base);
    pci.notify(0);

    // Poll used ring
    let used_idx_ptr = (STATE.used_base + 2) as *const u16;
    let mut timeout = 100_000_000u32;
    loop {
        fence(Ordering::Acquire);
        if core::ptr::read_volatile(used_idx_ptr) != STATE.last_used_idx {
            STATE.last_used_idx = core::ptr::read_volatile(used_idx_ptr);
            break;
        }
        timeout -= 1;
        if timeout == 0 {
            // Free chain on timeout
            free_chain_3(head);
            return Err(DriverError::Timeout);
        }
        core::hint::spin_loop();
    }

    // Free the 3 descriptors
    free_chain_3(head);

    if STATE.status_byte == VIRTIO_BLK_S_OK {
        Ok(())
    } else {
        Err(DriverError::IoError)
    }
}

/// Free a 3-descriptor chain back to the free list.
unsafe fn free_chain_3(head: u16) {
    let desc = STATE.desc_base as *mut Descriptor;
    let d0 = &*desc.add(head as usize);
    let idx1 = d0.next;
    let d1 = &*desc.add(idx1 as usize);
    let idx2 = d1.next;

    // Push back in reverse: 2, 1, 0
    let d2 = &mut *desc.add(idx2 as usize);
    d2.next = STATE.free_head;
    STATE.free_head = idx2;

    let d1 = &mut *desc.add(idx1 as usize);
    d1.next = STATE.free_head;
    STATE.free_head = idx1;

    let d0 = &mut *desc.add(head as usize);
    d0.next = STATE.free_head;
    STATE.free_head = head;

    STATE.num_free += 3;
}

impl BlockDevice for VirtioBlkPci {
    fn block_size(&self) -> usize { 512 }
    fn block_count(&self) -> u64 { unsafe { STATE.capacity } }

    unsafe fn read_block(&self, block: u64, buf: *mut u8) -> Result<(), DriverError> {
        pci_read_sector(block, buf)
    }

    unsafe fn write_block(&mut self, _block: u64, _buf: *const u8) -> Result<(), DriverError> {
        Err(DriverError::Unsupported)
    }
}
