//! virtio-net device driver.
//!
//! Uses two virtqueues: RX (queue 0) and TX (queue 1).
//! Each packet has a virtio_net_hdr prefix (10 bytes for legacy).
//! Polling-based — no interrupts.

use super::queue::{Descriptor, DESC_F_NEXT, DESC_F_WRITE};
use super::mmio::{VirtioMmio, VIRTIO_MAGIC};
use core::sync::atomic::{fence, Ordering};

/// virtio_net_hdr (legacy, 10 bytes).
#[repr(C)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}

impl VirtioNetHdr {
    pub const SIZE: usize = 10;
    pub const fn empty() -> Self {
        Self { flags: 0, gso_type: 0, hdr_len: 0, gso_size: 0, csum_start: 0, csum_offset: 0 }
    }
}

/// Maximum ethernet frame size (MTU 1500 + eth header 14).
const MAX_FRAME: usize = 1514;
/// Buffer size including virtio header.
const BUF_SIZE: usize = VirtioNetHdr::SIZE + MAX_FRAME;

/// Static state for the network device (avoids struct move issues).
pub struct NetState {
    pub mac: [u8; 6],
    pub initialized: bool,
    // MMIO base (aarch64) or I/O port (x86_64)
    mmio_base: usize,
    // RX queue
    rx_desc: usize,
    rx_avail: usize,
    rx_used: usize,
    rx_avail_idx: u16,
    rx_last_used: u16,
    rx_qsize: u16,
    // TX queue
    tx_desc: usize,
    tx_avail: usize,
    tx_used: usize,
    tx_avail_idx: u16,
    tx_last_used: u16,
    tx_qsize: u16,
    // RX buffers (pre-allocated, one per RX descriptor)
    rx_bufs: [[u8; BUF_SIZE]; 16],
    // TX header + buffer
    tx_hdr: VirtioNetHdr,
}

static mut NET: NetState = NetState {
    mac: [0; 6],
    initialized: false,
    mmio_base: 0,
    rx_desc: 0, rx_avail: 0, rx_used: 0,
    rx_avail_idx: 0, rx_last_used: 0, rx_qsize: 0,
    tx_desc: 0, tx_avail: 0, tx_used: 0,
    tx_avail_idx: 0, tx_last_used: 0, tx_qsize: 0,
    rx_bufs: [[0; BUF_SIZE]; 16],
    tx_hdr: VirtioNetHdr::empty(),
};

/// Initialize the virtio-net device via MMIO.
/// `base` = MMIO address, `rx_pages`/`tx_pages` = zeroed page-aligned memory for queues.
///
/// # Safety
/// Must be called once during boot.
pub unsafe fn init_mmio(base: usize, rx_pages: usize, tx_pages: usize) -> bool {
    let mmio = VirtioMmio::new(base);
    if mmio.magic() != VIRTIO_MAGIC { return false; }
    if mmio.device_id() != 1 { return false; } // 1 = net

    let is_legacy = mmio.version() == 1;

    // Reset + negotiate
    mmio.set_status(0);
    if is_legacy { mmio.set_guest_page_size(4096); }
    mmio.set_status(1); // ACK
    mmio.set_status(1 | 2); // DRIVER

    // Accept MAC address feature (bit 5)
    let features = mmio.device_features(0);
    mmio.set_driver_features(0, features & (1 << 5)); // VIRTIO_NET_F_MAC

    if !is_legacy {
        mmio.set_status(1 | 2 | 8); // FEATURES_OK
        if mmio.status() & 8 == 0 { return false; }
    }

    // Setup RX queue (queue 0)
    mmio.select_queue(0);
    let rx_max = mmio.queue_num_max();
    let rx_qsize = rx_max.min(16) as u16;
    mmio.set_queue_num(rx_qsize as u32);

    setup_queue_mmio(&mmio, is_legacy, rx_pages, rx_qsize);
    NET.rx_qsize = rx_qsize;
    let (d, a, u) = queue_addrs(rx_pages, rx_qsize);
    NET.rx_desc = d; NET.rx_avail = a; NET.rx_used = u;

    // Setup TX queue (queue 1)
    mmio.select_queue(1);
    let tx_max = mmio.queue_num_max();
    let tx_qsize = tx_max.min(16) as u16;
    mmio.set_queue_num(tx_qsize as u32);

    setup_queue_mmio(&mmio, is_legacy, tx_pages, tx_qsize);
    NET.tx_qsize = tx_qsize;
    let (d, a, u) = queue_addrs(tx_pages, tx_qsize);
    NET.tx_desc = d; NET.tx_avail = a; NET.tx_used = u;

    // Driver OK
    if is_legacy {
        mmio.set_status(1 | 2 | 4);
    } else {
        mmio.set_status(1 | 2 | 8 | 4);
    }

    // Read MAC from config space (byte-by-byte — not 32-bit aligned)
    for i in 0..6 {
        NET.mac[i] = mmio.config_read8(i);
    }

    NET.mmio_base = base;
    NET.initialized = true;

    // Pre-fill RX queue with buffers
    for i in 0..rx_qsize.min(16) {
        let desc = NET.rx_desc as *mut Descriptor;
        let d = &mut *desc.add(i as usize);
        d.addr = NET.rx_bufs[i as usize].as_ptr() as u64;
        d.len = BUF_SIZE as u32;
        d.flags = DESC_F_WRITE; // device writes to this buffer
        d.next = 0;

        // Add to available ring
        let avail_ring = (NET.rx_avail + 4) as *mut u16;
        *avail_ring.add((NET.rx_avail_idx % rx_qsize) as usize) = i;
        NET.rx_avail_idx += 1;
    }
    // Publish available
    let avail_idx_ptr = (NET.rx_avail + 2) as *mut u16;
    *avail_idx_ptr = NET.rx_avail_idx;
    fence(Ordering::Release);
    mmio.notify(0); // notify RX queue

    true
}

unsafe fn setup_queue_mmio(mmio: &VirtioMmio, is_legacy: bool, pages: usize, qsize: u16) {
    if is_legacy {
        mmio.set_queue_align(4096);
        mmio.set_queue_pfn((pages / 4096) as u32);
    } else {
        let (d, a, u) = queue_addrs(pages, qsize);
        mmio.set_queue_desc(d as u64);
        mmio.set_queue_avail(a as u64);
        mmio.set_queue_used(u as u64);
        mmio.set_queue_ready(1);
    }
}

fn queue_addrs(base: usize, qsize: u16) -> (usize, usize, usize) {
    let desc = base;
    let avail = base + 16 * qsize as usize;
    let avail_end = avail + 4 + 2 * qsize as usize + 2;
    let used = (avail_end + 0xFFF) & !0xFFF;
    (desc, avail, used)
}

/// Send an ethernet frame (without virtio header — we add it).
/// `frame` must be a complete ethernet frame (dest MAC + src MAC + ethertype + payload).
///
/// # Safety
/// NET must be initialized.
pub unsafe fn send(frame: &[u8]) -> bool {
    if !NET.initialized || frame.len() > MAX_FRAME { return false; }

    // Build TX buffer: virtio_net_hdr + frame
    NET.tx_hdr = VirtioNetHdr::empty();

    let desc = NET.tx_desc as *mut Descriptor;
    // Use descriptor 0 for header, 1 for data
    let d0 = &mut *desc.add(0);
    d0.addr = &NET.tx_hdr as *const VirtioNetHdr as u64;
    d0.len = VirtioNetHdr::SIZE as u32;
    d0.flags = DESC_F_NEXT;
    d0.next = 1;

    let d1 = &mut *desc.add(1);
    d1.addr = frame.as_ptr() as u64;
    d1.len = frame.len() as u32;
    d1.flags = 0; // device reads

    // Submit to TX available ring
    let avail_ring = (NET.tx_avail + 4) as *mut u16;
    let avail_idx_ptr = (NET.tx_avail + 2) as *mut u16;
    *avail_ring.add((NET.tx_avail_idx % NET.tx_qsize) as usize) = 0; // head = desc 0
    NET.tx_avail_idx += 1;
    fence(Ordering::Release);
    *avail_idx_ptr = NET.tx_avail_idx;
    fence(Ordering::Release);

    let mmio = VirtioMmio::new(NET.mmio_base);
    mmio.notify(1); // TX queue

    // Poll for completion
    let used_idx_ptr = (NET.tx_used + 2) as *const u16;
    for _ in 0..10_000_000u32 {
        fence(Ordering::Acquire);
        if core::ptr::read_volatile(used_idx_ptr) != NET.tx_last_used {
            NET.tx_last_used = core::ptr::read_volatile(used_idx_ptr);
            return true;
        }
        core::hint::spin_loop();
    }
    false // timeout
}

/// Receive an ethernet frame. Returns the frame data (without virtio header)
/// or None if no packet available.
///
/// # Safety
/// NET must be initialized.
pub unsafe fn recv(buf: &mut [u8]) -> Option<usize> {
    if !NET.initialized { return None; }

    let used_idx_ptr = (NET.rx_used + 2) as *const u16;
    fence(Ordering::Acquire);
    let current = core::ptr::read_volatile(used_idx_ptr);
    if current == NET.rx_last_used { return None; }

    // Read used element
    let used_ring = (NET.rx_used + 4) as *const u32;
    let idx = NET.rx_last_used % NET.rx_qsize;
    let elem_id = core::ptr::read_volatile(used_ring.add(idx as usize * 2)) as usize;
    let elem_len = core::ptr::read_volatile(used_ring.add(idx as usize * 2 + 1)) as usize;
    NET.rx_last_used += 1;

    // Copy frame data (skip virtio header)
    if elem_len > VirtioNetHdr::SIZE && elem_id < 16 {
        let frame_len = elem_len - VirtioNetHdr::SIZE;
        let copy_len = frame_len.min(buf.len());
        let src = NET.rx_bufs[elem_id].as_ptr().add(VirtioNetHdr::SIZE);
        core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), copy_len);

        // Re-add buffer to RX available ring
        let avail_ring = (NET.rx_avail + 4) as *mut u16;
        let avail_idx_ptr = (NET.rx_avail + 2) as *mut u16;
        *avail_ring.add((NET.rx_avail_idx % NET.rx_qsize) as usize) = elem_id as u16;
        NET.rx_avail_idx += 1;
        fence(Ordering::Release);
        *avail_idx_ptr = NET.rx_avail_idx;

        let mmio = VirtioMmio::new(NET.mmio_base);
        mmio.notify(0);

        Some(copy_len)
    } else {
        None
    }
}

/// Get the MAC address.
pub fn mac() -> [u8; 6] {
    unsafe { NET.mac }
}

/// Check if the network device is initialized.
pub fn is_up() -> bool {
    unsafe { NET.initialized }
}

/// Probe for a virtio-net device on the MMIO bus (aarch64 virt machine).
pub unsafe fn probe_mmio() -> Option<usize> {
    const BASE: usize = 0x0a000000;
    const STRIDE: usize = 0x200;
    for i in 0..32 {
        let addr = BASE + i * STRIDE;
        let mmio = VirtioMmio::new(addr);
        if mmio.magic() == VIRTIO_MAGIC && mmio.device_id() == 1 {
            return Some(addr);
        }
    }
    None
}
