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
