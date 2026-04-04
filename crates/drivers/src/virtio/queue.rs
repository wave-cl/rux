//! Split virtqueue implementation.
//!
//! Descriptor table + available ring + used ring laid out in physically
//! contiguous memory. Uses synchronous polling (no interrupts).

use core::sync::atomic::{fence, Ordering};

/// Maximum queue size. 16 is plenty for a boot-time block driver.
pub const QUEUE_SIZE: u16 = 16;

// ── Descriptor ─────────────────────────────────────────────────────

/// virtio descriptor (16 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Descriptor {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

pub const DESC_F_NEXT: u16 = 1;
pub const DESC_F_WRITE: u16 = 2; // device writes (buffer is device-writable)

// ── Available ring ─────────────────────────────────────────────────

/// Available ring header (4 bytes) + ring entries.
#[repr(C)]
pub struct AvailRing {
    pub flags: u16,
    pub idx: u16,
    pub ring: [u16; QUEUE_SIZE as usize],
}

// ── Used ring ──────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UsedElem {
    pub id: u32,
    pub len: u32,
}

#[repr(C)]
pub struct UsedRing {
    pub flags: u16,
    pub idx: u16,
    pub ring: [UsedElem; QUEUE_SIZE as usize],
}

// ── Virtqueue ──────────────────────────────────────────────────────

/// A single virtqueue backed by caller-provided memory.
pub struct Virtqueue {
    pub desc: *mut Descriptor,
    pub avail: *mut AvailRing,
    pub used: *mut UsedRing,
    /// Next descriptor index to allocate.
    pub free_head: u16,
    /// Number of free descriptors.
    pub num_free: u16,
    /// Last seen used index (for polling).
    pub last_used_idx: u16,
}

impl Virtqueue {
    /// Initialize a virtqueue with the default QUEUE_SIZE (16 entries).
    pub unsafe fn init(base: usize) -> Self {
        Self::init_with_size(base, QUEUE_SIZE)
    }

    /// Initialize a virtqueue with a specific size (for PCI legacy where
    /// the device dictates queue size).
    ///
    /// # Safety
    /// `base` must point to zeroed, page-aligned memory large enough for
    /// the given queue size.
    pub unsafe fn init_with_size(base: usize, size: u16) -> Self {
        let desc = base as *mut Descriptor;
        let avail_off = 16 * size as usize; // sizeof(Descriptor) * size
        let avail = (base + avail_off) as *mut AvailRing;
        // Used ring: align to 4096 after avail ring
        let avail_end = avail_off + 4 + 2 * size as usize + 2;
        let used_off = (avail_end + 0xFFF) & !0xFFF;
        let used = (base + used_off) as *mut UsedRing;

        // Chain free descriptors: 0→1→2→...→(N-1)
        for i in 0..size {
            let d = &mut *desc.add(i as usize);
            d.addr = 0;
            d.len = 0;
            d.flags = 0;
            d.next = if i + 1 < size { i + 1 } else { 0 };
        }

        Self {
            desc,
            avail,
            used,
            free_head: 0,
            num_free: size,
            last_used_idx: 0,
        }
    }

    /// Byte offset of the available ring from base.
    pub const fn avail_offset() -> usize {
        16 * QUEUE_SIZE as usize // sizeof(Descriptor) * QUEUE_SIZE
    }

    /// Byte offset of the used ring from base (aligned to 4 bytes).
    pub const fn used_offset() -> usize {
        // avail ring: 2 (flags) + 2 (idx) + 2*QUEUE_SIZE (ring) + 2 (used_event)
        let avail_end = Self::avail_offset() + 4 + 2 * QUEUE_SIZE as usize + 2;
        // Align up to page boundary for used ring (virtio spec requirement)
        (avail_end + 0xFFF) & !0xFFF
    }

    /// Total memory needed for the virtqueue.
    pub const fn total_size() -> usize {
        // used ring: 2 (flags) + 2 (idx) + 8*QUEUE_SIZE (ring) + 2 (avail_event)
        Self::used_offset() + 4 + 8 * QUEUE_SIZE as usize + 2
    }

    /// Physical addresses of the three regions.
    pub fn desc_addr(&self) -> u64 { self.desc as u64 }
    pub fn avail_addr(&self) -> u64 { self.avail as u64 }
    pub fn used_addr(&self) -> u64 { self.used as u64 }

    /// Allocate a chain of `n` descriptors. Returns the head index.
    pub unsafe fn alloc_chain(&mut self, n: u16) -> Option<u16> {
        if self.num_free < n {
            return None;
        }
        let head = self.free_head;
        let mut idx = head;
        for i in 0..n {
            let d = &mut *self.desc.add(idx as usize);
            if i + 1 < n {
                d.flags |= DESC_F_NEXT;
                idx = d.next;
            } else {
                d.flags &= !DESC_F_NEXT;
                self.free_head = d.next;
            }
        }
        self.num_free -= n;
        Some(head)
    }

    /// Submit a descriptor chain head to the available ring and notify.
    pub unsafe fn submit(&mut self, head: u16) {
        let avail = &mut *self.avail;
        let idx = avail.idx;
        avail.ring[(idx % QUEUE_SIZE) as usize] = head;
        fence(Ordering::Release);
        avail.idx = idx.wrapping_add(1);
        fence(Ordering::Release);
    }

    /// Poll for completion. Returns true if device responded, false on timeout.
    pub unsafe fn poll_used(&mut self) -> bool {
        for _ in 0..100_000_000u32 {
            fence(Ordering::Acquire);
            let used = &*self.used;
            if used.idx != self.last_used_idx {
                self.last_used_idx = used.idx;
                return true;
            }
            core::hint::spin_loop();
        }
        false // timeout
    }

    /// Free a chain of descriptors starting at `head`.
    pub unsafe fn free_chain(&mut self, head: u16) {
        let mut idx = head;
        loop {
            let d = &*self.desc.add(idx as usize);
            let has_next = d.flags & DESC_F_NEXT != 0;
            let next = d.next;
            // Return to free list
            let d = &mut *self.desc.add(idx as usize);
            d.next = self.free_head;
            self.free_head = idx;
            self.num_free += 1;
            if !has_next { break; }
            idx = next;
        }
    }
}
