//! virtio-net over PCI transport (legacy/transitional) for x86_64.
//!
//! Static state like blk_pci.rs. Two queues: RX (0) and TX (1).

use crate::pci;
use super::pci::VirtioPci;
use super::queue::{Descriptor, DESC_F_NEXT, DESC_F_WRITE};
use core::sync::atomic::{fence, Ordering};

const VIRTIO_NET_HDR_SIZE: usize = 10;
const MAX_FRAME: usize = 1514;
const BUF_SIZE: usize = VIRTIO_NET_HDR_SIZE + MAX_FRAME;

/// virtio_net_hdr (legacy, 10 bytes)
#[repr(C)]
struct NetHdr {
    flags: u8, gso_type: u8, hdr_len: u16, gso_size: u16,
    csum_start: u16, csum_offset: u16,
}

struct NetPciState {
    io_base: u16,
    mac: [u8; 6],
    initialized: bool,
    // RX queue state (dev_*_qsize = device's actual queue size for ring arithmetic)
    rx_desc: usize, rx_avail: usize, rx_used: usize,
    rx_avail_idx: u16, rx_last_used: u16, dev_rx_qsize: u16,
    // TX queue state
    tx_desc: usize, tx_avail: usize, tx_used: usize,
    tx_avail_idx: u16, tx_last_used: u16, dev_tx_qsize: u16,
    // Buffers (16 pre-allocated; only these descriptors go in avail ring)
    rx_bufs: [[u8; BUF_SIZE]; 16],
    tx_hdr: NetHdr,
}

static mut STATE: NetPciState = NetPciState {
    io_base: 0, mac: [0; 6], initialized: false,
    rx_desc: 0, rx_avail: 0, rx_used: 0,
    rx_avail_idx: 0, rx_last_used: 0, dev_rx_qsize: 0,
    tx_desc: 0, tx_avail: 0, tx_used: 0,
    tx_avail_idx: 0, tx_last_used: 0, dev_tx_qsize: 0,
    rx_bufs: [[0; BUF_SIZE]; 16],
    tx_hdr: NetHdr { flags: 0, gso_type: 0, hdr_len: 0, gso_size: 0, csum_start: 0, csum_offset: 0 },
};

fn queue_addrs(base: usize, qsize: u16) -> (usize, usize, usize) {
    let desc = base;
    let avail = base + 16 * qsize as usize;
    let avail_end = avail + 4 + 2 * qsize as usize + 2;
    let used = (avail_end + 0xFFF) & !0xFFF;
    (desc, avail, used)
}

/// Initialize virtio-net via PCI. Needs two page-aligned memory regions for RX+TX queues.
pub unsafe fn init(rx_pages: usize, tx_pages: usize) -> bool {
    // Find virtio-net device (vendor 0x1AF4, device 0x1000 = legacy net)
    let dev = match pci::find_device(pci::VIRTIO_VENDOR, 0x1000) {
        Some(d) => d,
        None => return false,
    };
    // Verify it's a net device (subsystem device ID or class)
    // Legacy virtio: device 0x1000 = net, 0x1001 = block
    // But 0x1000 is also the transitional net device ID

    if dev.bar0 & 1 == 0 { return false; } // not I/O port
    let io_base = (dev.bar0 & 0xFFFC) as u16;
    pci::enable_bus_master(dev.addr);

    let pci = VirtioPci::new(io_base);

    // Reset + init
    pci.set_status(0);
    pci.set_status(1); // ACK
    pci.set_status(1 | 2); // DRIVER

    // Accept MAC feature
    let features = pci.device_features();
    pci.set_driver_features(features & (1 << 5)); // VIRTIO_NET_F_MAC

    // Setup RX queue (queue 0)
    // Legacy PCI: queue size is fixed by device. We allocate memory for
    // the full device queue size. We only use 16 buffers, but ring index
    // arithmetic MUST use the device's queue size.
    pci.select_queue(0);
    let dev_rx_qsize = pci.queue_size();
    if dev_rx_qsize == 0 { return false; }

    let (rx_d, rx_a, rx_u) = queue_addrs(rx_pages, dev_rx_qsize);
    // Initialize descriptors: 0-15 get buffers, 16+ are zeroed
    let desc = rx_d as *mut Descriptor;
    for i in 0..dev_rx_qsize {
        let d = &mut *desc.add(i as usize);
        if (i as usize) < 16 {
            d.addr = crate::kva_to_phys(STATE.rx_bufs[i as usize].as_ptr() as u64);
            d.len = BUF_SIZE as u32;
            d.flags = DESC_F_WRITE;
        } else {
            d.addr = 0; d.len = 0; d.flags = 0;
        }
        d.next = 0;
    }
    pci.set_queue_addr((rx_d / 4096) as u32);

    STATE.rx_desc = rx_d; STATE.rx_avail = rx_a; STATE.rx_used = rx_u;
    STATE.dev_rx_qsize = dev_rx_qsize;

    // Pre-fill avail ring with descriptors 0-15 (the ones with buffers).
    // Ring indices wrap at dev_rx_qsize, not 16.
    let avail_ring = (rx_a + 4) as *mut u16;
    for i in 0..16u16.min(dev_rx_qsize) {
        *avail_ring.add(i as usize) = i;
    }
    STATE.rx_avail_idx = 16u16.min(dev_rx_qsize);
    *((rx_a + 2) as *mut u16) = STATE.rx_avail_idx;

    // Setup TX queue (queue 1)
    pci.select_queue(1);
    let dev_tx_qsize = pci.queue_size();
    if dev_tx_qsize == 0 { return false; }

    let (tx_d, tx_a, tx_u) = queue_addrs(tx_pages, dev_tx_qsize);
    let tdesc = tx_d as *mut Descriptor;
    for i in 0..dev_tx_qsize {
        let d = &mut *tdesc.add(i as usize);
        d.addr = 0; d.len = 0; d.flags = 0; d.next = 0;
    }
    pci.set_queue_addr((tx_d / 4096) as u32);

    STATE.tx_desc = tx_d; STATE.tx_avail = tx_a; STATE.tx_used = tx_u;
    STATE.dev_tx_qsize = dev_tx_qsize;

    // Driver OK
    pci.set_status(1 | 2 | 4);

    // Read MAC from config space (offset 0x14 for legacy PCI virtio-net)
    for i in 0..6 {
        STATE.mac[i] = pci.inb_config(i as u16);
    }

    STATE.io_base = io_base;
    STATE.initialized = true;

    // Notify RX queue
    pci.notify(0);
    true
}

pub unsafe fn send(frame: &[u8]) -> bool {
    if !STATE.initialized || frame.len() > MAX_FRAME { return false; }

    STATE.tx_hdr = NetHdr { flags: 0, gso_type: 0, hdr_len: 0, gso_size: 0, csum_start: 0, csum_offset: 0 };

    let desc = STATE.tx_desc as *mut Descriptor;
    let d0 = &mut *desc.add(0);
    d0.addr = crate::kva_to_phys(&raw const (*(&raw const STATE)).tx_hdr as *const NetHdr as u64);
    d0.len = VIRTIO_NET_HDR_SIZE as u32;
    d0.flags = DESC_F_NEXT;
    d0.next = 1;

    let d1 = &mut *desc.add(1);
    d1.addr = crate::kva_to_phys(frame.as_ptr() as u64);
    d1.len = frame.len() as u32;
    d1.flags = 0;

    let avail_ring = (STATE.tx_avail + 4) as *mut u16;
    *avail_ring.add((STATE.tx_avail_idx % STATE.dev_tx_qsize) as usize) = 0;
    STATE.tx_avail_idx = STATE.tx_avail_idx.wrapping_add(1);
    fence(Ordering::Release);
    *((STATE.tx_avail + 2) as *mut u16) = STATE.tx_avail_idx;
    fence(Ordering::Release);

    let pci = VirtioPci::new(STATE.io_base);
    pci.notify(1);

    // Poll TX completion — must wait for device to DMA the frame before
    // returning, since the caller reuses the descriptor for the next send.
    let used_idx_ptr = (STATE.tx_used + 2) as *const u16;
    for _ in 0..10_000_000u32 {
        fence(Ordering::Acquire);
        if core::ptr::read_volatile(used_idx_ptr) != STATE.tx_last_used {
            STATE.tx_last_used = core::ptr::read_volatile(used_idx_ptr);
            return true;
        }
        core::hint::spin_loop();
    }
    // TX failed — should not happen in practice
    false
}

pub unsafe fn recv(buf: &mut [u8]) -> Option<usize> {
    if !STATE.initialized { return None; }

    let used_idx_ptr = (STATE.rx_used + 2) as *const u16;
    fence(Ordering::Acquire);
    let current = core::ptr::read_volatile(used_idx_ptr);
    if current == STATE.rx_last_used { return None; }

    let used_ring = (STATE.rx_used + 4) as *const u32;
    let idx = STATE.rx_last_used % STATE.dev_rx_qsize;
    let elem_id = core::ptr::read_volatile(used_ring.add(idx as usize * 2)) as usize;
    let elem_len = core::ptr::read_volatile(used_ring.add(idx as usize * 2 + 1)) as usize;
    STATE.rx_last_used = STATE.rx_last_used.wrapping_add(1);

    if elem_len > VIRTIO_NET_HDR_SIZE && elem_id < 16 {
        let frame_len = elem_len - VIRTIO_NET_HDR_SIZE;
        let copy_len = frame_len.min(buf.len());
        let src = STATE.rx_bufs[elem_id].as_ptr().add(VIRTIO_NET_HDR_SIZE);
        core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), copy_len);

        // Re-add to RX available ring
        let avail_ring = (STATE.rx_avail + 4) as *mut u16;
        *avail_ring.add((STATE.rx_avail_idx % STATE.dev_rx_qsize) as usize) = elem_id as u16;
        STATE.rx_avail_idx = STATE.rx_avail_idx.wrapping_add(1);
        fence(Ordering::Release);
        *((STATE.rx_avail + 2) as *mut u16) = STATE.rx_avail_idx;

        let pci = VirtioPci::new(STATE.io_base);
        pci.notify(0);

        Some(copy_len)
    } else {
        None
    }
}

pub fn mac() -> [u8; 6] { unsafe { STATE.mac } }
pub fn is_up() -> bool { unsafe { STATE.initialized } }
