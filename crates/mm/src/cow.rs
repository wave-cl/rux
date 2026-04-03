use rux_klib::PhysAddr;
use crate::MemoryError;

/// Frame reference count table for copy-on-write.
///
/// Tracks how many address spaces share each physical frame.
/// When a COW fault occurs:
/// 1. If refcount == 1 → just remap as writable (sole owner)
/// 2. If refcount > 1 → allocate new frame, copy contents, decrement old refcount
#[repr(C)]
pub struct FrameRefTable {
    /// Reference counts indexed by frame number.
    /// Frame number = (phys_addr - base) / PAGE_SIZE.
    pub counts: *mut u32,
    /// Base physical address of the tracked region.
    pub base: PhysAddr,
    /// Total number of frames tracked.
    pub max_frames: usize,
}

// SAFETY: FrameRefTable contains a raw pointer to the counts array.
// Accessed under mm locks in the kernel.
unsafe impl Send for FrameRefTable {}
unsafe impl Sync for FrameRefTable {}

impl FrameRefTable {
    /// Increment reference count for a frame.
    ///
    /// # Safety
    /// `frame` must be within the tracked region and `counts` must be valid.
    #[inline]
    pub unsafe fn inc(&mut self, frame: PhysAddr) {
        let idx = self.frame_index(frame);
        if idx < self.max_frames {
            *self.counts.add(idx) += 1;
        }
    }

    /// Decrement reference count. Returns true if count reached zero
    /// (frame can be freed).
    ///
    /// # Safety
    /// Same as `inc`.
    #[inline]
    pub unsafe fn dec(&mut self, frame: PhysAddr) -> bool {
        let idx = self.frame_index(frame);
        if idx < self.max_frames {
            let count = &mut *self.counts.add(idx);
            *count = count.saturating_sub(1);
            return *count == 0;
        }
        false
    }

    /// Get the current reference count for a frame.
    ///
    /// # Safety
    /// Same as `inc`.
    #[inline]
    pub unsafe fn count(&self, frame: PhysAddr) -> u32 {
        let idx = self.frame_index(frame);
        if idx < self.max_frames {
            *self.counts.add(idx)
        } else {
            0
        }
    }

    #[inline(always)]
    fn frame_index(&self, frame: PhysAddr) -> usize {
        (frame.as_usize() - self.base.as_usize()) / 4096
    }
}

/// Copy-on-write operations.
pub trait CowOps {
    /// Handle a COW fault on a page. If the page has refcount > 1,
    /// allocates a new frame, copies the contents, and remaps.
    /// If refcount == 1, just removes the COW flag and makes writable.
    fn handle_cow(&mut self, vaddr: rux_klib::VirtAddr) -> Result<(), MemoryError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a FrameRefTable backed by a Vec.
    fn make_table(n: usize, base: usize) -> (FrameRefTable, Vec<u32>) {
        let mut counts = vec![0u32; n];
        let table = FrameRefTable {
            counts: counts.as_mut_ptr(),
            base: PhysAddr(base),
            max_frames: n,
        };
        (table, counts)
    }

    #[test]
    fn test_inc_dec_roundtrip() {
        let (mut table, mut counts) = make_table(16, 0x1000_0000);
        // Keep counts alive; reassign pointer after moves.
        table.counts = counts.as_mut_ptr();

        let frame = PhysAddr(0x1000_0000 + 4096 * 3); // frame index 3
        unsafe {
            assert_eq!(table.count(frame), 0);
            table.inc(frame);
            assert_eq!(table.count(frame), 1);
            table.inc(frame);
            assert_eq!(table.count(frame), 2);
            let freed = table.dec(frame);
            assert!(!freed, "count is 1, should not be freed yet");
            assert_eq!(table.count(frame), 1);
            let freed = table.dec(frame);
            assert!(freed, "count reached 0, should be freed");
            assert_eq!(table.count(frame), 0);
        }
        drop(counts);
    }

    #[test]
    fn test_dec_saturates_at_zero() {
        let (mut table, mut counts) = make_table(4, 0);
        table.counts = counts.as_mut_ptr();

        let frame = PhysAddr(0);
        unsafe {
            // Already 0, dec should stay at 0 and return true (count == 0).
            let freed = table.dec(frame);
            assert!(freed);
            assert_eq!(table.count(frame), 0);
        }
        drop(counts);
    }

    #[test]
    fn test_out_of_range_frame() {
        let (mut table, mut counts) = make_table(4, 0);
        table.counts = counts.as_mut_ptr();

        // Frame beyond max_frames — should be no-ops / return 0.
        let oob = PhysAddr(4096 * 100);
        unsafe {
            assert_eq!(table.count(oob), 0);
            table.inc(oob); // should be a no-op
            assert_eq!(table.count(oob), 0);
            let freed = table.dec(oob);
            assert!(!freed);
        }
        drop(counts);
    }

    #[test]
    fn test_multiple_frames_independent() {
        let (mut table, mut counts) = make_table(8, 0);
        table.counts = counts.as_mut_ptr();

        let f0 = PhysAddr(0);
        let f3 = PhysAddr(4096 * 3);
        let f7 = PhysAddr(4096 * 7);
        unsafe {
            table.inc(f0);
            table.inc(f0);
            table.inc(f3);
            table.inc(f7);
            table.inc(f7);
            table.inc(f7);

            assert_eq!(table.count(f0), 2);
            assert_eq!(table.count(f3), 1);
            assert_eq!(table.count(f7), 3);

            // Decrement f7 once
            table.dec(f7);
            assert_eq!(table.count(f7), 2);
            // f0 and f3 unaffected
            assert_eq!(table.count(f0), 2);
            assert_eq!(table.count(f3), 1);
        }
        drop(counts);
    }
}
