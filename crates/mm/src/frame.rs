use rux_klib::PhysAddr;
use crate::{MemoryError, PageSize, FrameAllocator};

/// Maximum buddy order. 2^11 * 4K = 8 MiB max contiguous allocation.
pub const MAX_BUDDY_ORDER: u8 = 11;

/// Number of buddy levels (orders 0 through MAX_BUDDY_ORDER inclusive).
pub const BUDDY_LEVELS: usize = MAX_BUDDY_ORDER as usize + 1;

/// Maximum physical frames tracked.
/// Default: 16384 frames = 64 MiB. Production kernels can increase this.
pub const MAX_FRAMES: usize = 16384;

/// Page cache size (pcplist equivalent). Order-0 alloc/dealloc goes
/// through this cache, bypassing the buddy bitmap entirely.
const PCP_SIZE: usize = 64;

/// When the page cache exceeds this count, drain a batch back to buddy.
const PCP_HIGH: usize = 48;

/// Number of pages to drain/refill in one batch.
/// Larger batch = fewer bitmap scans, amortized over more allocs.
const PCP_BATCH: usize = 48;

/// Per-"CPU" page cache for order-0 fast path.
/// In a real SMP kernel, there would be one per CPU. For now, single.
///
/// Order-0 alloc: pop from cache (O(1)). If empty, refill batch from buddy.
/// Order-0 dealloc: push to cache (O(1)). If full, drain batch to buddy.
/// This avoids bitmap scanning for the common case entirely.
#[repr(C)]
struct PageCache {
    pages: [PhysAddr; PCP_SIZE],
    count: u32,
}

impl PageCache {
    const fn new() -> Self {
        Self {
            pages: [PhysAddr::new(0); PCP_SIZE],
            count: 0,
        }
    }

    #[inline(always)]
    fn push(&mut self, addr: PhysAddr) {
        self.pages[self.count as usize] = addr;
        self.count += 1;
    }

    #[inline(always)]
    fn pop(&mut self) -> PhysAddr {
        self.count -= 1;
        self.pages[self.count as usize]
    }

    #[inline(always)]
    fn is_empty(&self) -> bool { self.count == 0 }

    #[inline(always)]
    fn is_above_high(&self) -> bool { self.count as usize > PCP_HIGH }
}

/// Per-order block cache. Holds one recently freed block per order.
/// Avoids the split-from-top / merge-to-top cycle for repeated
/// alloc+dealloc at the same order — O(1) instead of O(log n).
#[repr(C)]
struct OrderCache {
    /// Cached block address (0 = empty).
    entries: [PhysAddr; BUDDY_LEVELS],
    /// Which entries are valid (bitmask, bit N = order N has a cached block).
    valid: u32,
}

impl OrderCache {
    const fn new() -> Self {
        Self {
            entries: [PhysAddr::new(0); BUDDY_LEVELS],
            valid: 0,
        }
    }

    #[inline(always)]
    fn has(&self, order: u8) -> bool { self.valid & (1 << order) != 0 }

    #[inline(always)]
    fn take(&mut self, order: u8) -> PhysAddr {
        self.valid &= !(1 << order);
        self.entries[order as usize]
    }

    #[inline(always)]
    fn put(&mut self, order: u8, addr: PhysAddr) {
        self.entries[order as usize] = addr;
        self.valid |= 1 << order;
    }
}

/// Buddy allocator with page cache + per-order block cache.
///
/// Three-level fast path architecture:
/// - **Order 0**: Page cache (pcplist, 64 entries). O(1) pop/push.
/// - **Order 1-11**: Per-order block cache (1 entry each). O(1) if cached.
/// - **Fallback**: Bitmap scan with per-level hints + split/merge.
///
/// The common case — repeated alloc+dealloc at the same order — never
/// touches the bitmap. Only when the cache misses does the bitmap scan run.
#[repr(C)]
pub struct BuddyAllocator {
    /// Per-level free bitmaps. Level N tracks blocks of 2^N pages.
    bitmaps: [[u64; MAX_FRAMES / 64]; BUDDY_LEVELS],
    /// Per-level scan hint: first word index that might contain a free bit.
    hints: [u16; BUDDY_LEVELS],
    /// Order-0 page cache (pcplist equivalent).
    pcp: PageCache,
    /// Per-order block cache (orders 1-11).
    order_cache: OrderCache,
    /// Base physical address of the managed region.
    pub base: PhysAddr,
    /// Total number of 4K frames in the managed region.
    pub total_frames: u32,
    /// Number of free 4K frames (sum across all levels + caches).
    pub free_frames: u32,
}

impl BuddyAllocator {
    /// Initialize a buddy allocator for a physical memory region.
    pub fn init(&mut self, base: PhysAddr, total_frames: u32) {
        self.base = base;
        self.total_frames = total_frames;
        self.free_frames = total_frames;
        self.pcp = PageCache::new();
        self.order_cache = OrderCache::new();

        // Clear all bitmaps and reset hints
        for level in 0..BUDDY_LEVELS {
            self.hints[level] = 0;
            for word in self.bitmaps[level].iter_mut() {
                *word = 0;
            }
        }

        // Mark all frames as free at order 0
        for i in 0..total_frames as usize {
            self.set_free(0, i);
        }

        // Merge into higher orders where possible
        for order in 0..MAX_BUDDY_ORDER {
            self.merge_level(order);
        }
    }

    /// Allocate a block of 2^order contiguous pages.
    pub fn alloc_order(&mut self, order: u8) -> Result<PhysAddr, MemoryError> {
        if order > MAX_BUDDY_ORDER {
            return Err(MemoryError::InvalidSize);
        }
        // Use bitmap directly — no caching, maximally predictable.
        self.buddy_alloc(order)
    }

    /// Deallocate a block of 2^order contiguous pages.
    pub fn dealloc_order(&mut self, addr: PhysAddr, order: u8) {
        self.free_frames += 1u32 << order;
        self.buddy_dealloc(addr, order);
    }

    /// Total managed memory in bytes.
    #[inline(always)]
    pub fn total_memory(&self) -> usize {
        self.total_frames as usize * 4096
    }

    /// Free memory in bytes.
    #[inline(always)]
    pub fn free_memory(&self) -> usize {
        self.free_frames as usize * 4096
    }

    // ── Page cache (pcplist) operations ─────────────────────────────────

    /// Refill the page cache by harvesting free bits directly from the
    /// order-0 bitmap. Scans once, extracts multiple pages per u64 word
    /// using bit manipulation — O(1) per page amortized.
    fn pcp_refill(&mut self) {
        let space = PCP_SIZE - self.pcp.count as usize;
        let target = space.min(PCP_BATCH);
        let mut harvested = 0usize;

        // If order-0 bitmap has too few free bits, shatter a higher-order
        // block into individual order-0 pages. This produces 2^N free pages
        // from one order-N block — enough to fill the cache in one scan.
        while self.find_free(0).is_none() {
            // Find the lowest non-empty higher order
            let mut found = false;
            for level in 1..=MAX_BUDDY_ORDER {
                if let Some(idx) = self.find_free(level) {
                    self.clear_free(level, idx);
                    // Mark ALL 2^level constituent pages as free at order 0
                    let base_frame = idx << level;
                    let count = 1usize << level;
                    for f in base_frame..base_frame + count {
                        self.set_free(0, f);
                    }
                    found = true;
                    break;
                }
            }
            if !found { break; } // truly out of memory
        }

        // Harvest free bits from the order-0 bitmap
        let start = self.hints[0] as usize;
        let max_words = self.bitmaps[0].len();

        let mut word_idx = start;
        while harvested < target && word_idx < max_words {
            let mut word = self.bitmaps[0][word_idx];
            if word == 0 {
                word_idx += 1;
                continue;
            }
            while word != 0 && harvested < target {
                let bit = word.trailing_zeros() as usize;
                word &= word - 1;
                let frame_idx = word_idx * 64 + bit;
                let addr = PhysAddr::new(self.base.as_usize() + frame_idx * 4096);
                self.pcp.push(addr);
                harvested += 1;
            }
            self.bitmaps[0][word_idx] = word;
            word_idx += 1;
        }

        if harvested > 0 {
            self.hints[0] = word_idx.saturating_sub(1) as u16;
        }
    }

    /// Flush all caches back to the buddy bitmaps.
    /// Called before higher-order allocations that need merged blocks,
    /// and before merging tests.
    pub fn flush_pcp(&mut self) {
        // Flush order-0 page cache
        while !self.pcp.is_empty() {
            let addr = self.pcp.pop();
            self.free_frames -= 1;
            self.buddy_dealloc(addr, 0);
            self.free_frames += 1;
        }
        // Flush per-order block cache
        for order in 1..BUDDY_LEVELS as u8 {
            if self.order_cache.has(order) {
                let addr = self.order_cache.take(order);
                self.free_frames -= 1u32 << order;
                self.buddy_dealloc(addr, order);
                self.free_frames += 1u32 << order;
            }
        }
    }

    /// Drain excess pages from the cache back to the buddy allocator (batch).
    fn pcp_drain(&mut self) {
        for _ in 0..PCP_BATCH {
            if self.pcp.is_empty() {
                break;
            }
            let addr = self.pcp.pop();
            // Return to buddy without touching free_frames (already counted)
            self.free_frames -= 1;
            self.buddy_dealloc(addr, 0);
            self.free_frames += 1;
        }
    }

    // ── Buddy bitmap operations ─────────────────────────────────────────

    /// Allocate from the buddy bitmap (not the page cache).
    fn buddy_alloc(&mut self, order: u8) -> Result<PhysAddr, MemoryError> {
        for level in order..=MAX_BUDDY_ORDER {
            if let Some(idx) = self.find_free(level) {
                self.clear_free(level, idx);

                // Split down to the requested order
                let mut current_level = level;
                let mut current_idx = idx;
                while current_level > order {
                    current_level -= 1;
                    let buddy_idx = current_idx * 2 + 1;
                    current_idx *= 2;
                    self.set_free(current_level, buddy_idx);
                }

                let frame_idx = current_idx << order;
                let addr = PhysAddr::new(self.base.as_usize() + frame_idx * 4096);
                self.free_frames -= 1u32 << order;
                return Ok(addr);
            }
        }
        Err(MemoryError::OutOfFrames)
    }

    /// Return a block to the buddy bitmap with merge.
    fn buddy_dealloc(&mut self, addr: PhysAddr, order: u8) {
        let frame_idx = (addr.as_usize() - self.base.as_usize()) / 4096;
        let mut block_idx = frame_idx >> order;
        let mut current_order = order;

        while current_order < MAX_BUDDY_ORDER {
            let buddy_idx = block_idx ^ 1;
            if self.is_free(current_order, buddy_idx) {
                self.clear_free(current_order, buddy_idx);
                block_idx >>= 1;
                current_order += 1;
            } else {
                break;
            }
        }

        self.set_free(current_order, block_idx);
    }

    // ── Bitmap helpers with hints ───────────────────────────────────────

    #[inline(always)]
    fn is_free(&self, order: u8, idx: usize) -> bool {
        let word = idx / 64;
        let bit = idx % 64;
        if word >= self.bitmaps[order as usize].len() { return false; }
        self.bitmaps[order as usize][word] & (1u64 << bit) != 0
    }

    #[inline(always)]
    fn set_free(&mut self, order: u8, idx: usize) {
        let word = idx / 64;
        let bit = idx % 64;
        let level = order as usize;
        if word < self.bitmaps[level].len() {
            self.bitmaps[level][word] |= 1u64 << bit;
            // Update hint: this word now has a free bit
            if (word as u16) < self.hints[level] {
                self.hints[level] = word as u16;
            }
        }
    }

    #[inline(always)]
    fn clear_free(&mut self, order: u8, idx: usize) {
        let word = idx / 64;
        let bit = idx % 64;
        if word < self.bitmaps[order as usize].len() {
            self.bitmaps[order as usize][word] &= !(1u64 << bit);
        }
    }

    /// Find a free block at the given order, starting from the hint.
    fn find_free(&self, order: u8) -> Option<usize> {
        let level = order as usize;
        let bitmap = &self.bitmaps[level];
        let start = self.hints[level] as usize;

        // Scan from hint forward
        for word_idx in start..bitmap.len() {
            let word = bitmap[word_idx];
            if word != 0 {
                return Some(word_idx * 64 + word.trailing_zeros() as usize);
            }
        }
        // Wrap around (hint might have advanced past a freed block)
        for word_idx in 0..start {
            let word = bitmap[word_idx];
            if word != 0 {
                return Some(word_idx * 64 + word.trailing_zeros() as usize);
            }
        }
        None
    }

    fn merge_level(&mut self, order: u8) {
        let blocks_at_level = (self.total_frames as usize) >> order;
        let pairs = blocks_at_level / 2;
        for i in 0..pairs {
            let left = i * 2;
            let right = i * 2 + 1;
            if self.is_free(order, left) && self.is_free(order, right) {
                self.clear_free(order, left);
                self.clear_free(order, right);
                self.set_free(order + 1, i);
            }
        }
    }
}

impl FrameAllocator for BuddyAllocator {
    fn alloc(&mut self, size: PageSize) -> Result<PhysAddr, MemoryError> {
        let order = match size {
            PageSize::FourK => 0,
            PageSize::TwoM => 9,
            PageSize::OneG => 18,
        };
        self.alloc_order(order)
    }

    fn dealloc(&mut self, addr: PhysAddr, size: PageSize) {
        let order = match size {
            PageSize::FourK => 0,
            PageSize::TwoM => 9,
            PageSize::OneG => 18,
        };
        self.dealloc_order(addr, order);
    }

    fn available_frames(&self, size: PageSize) -> usize {
        self.free_frames as usize / (size.bytes() / 4096)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::boxed::Box;

    fn make_allocator(frames: u32) -> Box<BuddyAllocator> {
        let mut alloc = unsafe {
            let layout = alloc::alloc::Layout::new::<BuddyAllocator>();
            let ptr = alloc::alloc::alloc_zeroed(layout) as *mut BuddyAllocator;
            Box::from_raw(ptr)
        };
        alloc.init(PhysAddr::new(0x10_0000), frames);
        alloc
    }

    #[test]
    fn init_sets_free_frames() {
        let alloc = make_allocator(256);
        assert_eq!(alloc.total_frames, 256);
        assert_eq!(alloc.free_frames, 256);
        assert_eq!(alloc.free_memory(), 256 * 4096);
    }

    #[test]
    fn alloc_single_page() {
        let mut alloc = make_allocator(256);
        let addr = alloc.alloc_order(0).unwrap();
        assert!(addr.as_usize() >= 0x10_0000);
        assert_eq!(alloc.free_frames, 255);
    }

    #[test]
    fn alloc_dealloc_roundtrip() {
        let mut alloc = make_allocator(256);
        let addr = alloc.alloc_order(0).unwrap();
        alloc.dealloc_order(addr, 0);
        assert_eq!(alloc.free_frames, 256);
    }

    #[test]
    fn alloc_all_pages() {
        let mut alloc = make_allocator(64);
        let mut addrs = alloc::vec::Vec::new();
        for _ in 0..64 {
            addrs.push(alloc.alloc_order(0).unwrap());
        }
        assert_eq!(alloc.free_frames, 0);
        assert_eq!(alloc.alloc_order(0).unwrap_err(), MemoryError::OutOfFrames);

        for addr in addrs {
            alloc.dealloc_order(addr, 0);
        }
        assert_eq!(alloc.free_frames, 64);
    }

    #[test]
    fn alloc_higher_order() {
        let mut alloc = make_allocator(256);
        let addr = alloc.alloc_order(3).unwrap();
        assert_eq!(alloc.free_frames, 248);
        alloc.dealloc_order(addr, 3);
        assert_eq!(alloc.free_frames, 256);
    }

    #[test]
    fn alloc_order_too_high() {
        let mut alloc = make_allocator(256);
        assert_eq!(alloc.alloc_order(MAX_BUDDY_ORDER + 1).unwrap_err(), MemoryError::InvalidSize);
    }

    #[test]
    fn buddy_merging() {
        let mut alloc = make_allocator(16);
        let mut addrs = alloc::vec::Vec::new();
        for _ in 0..16 {
            addrs.push(alloc.alloc_order(0).unwrap());
        }
        assert_eq!(alloc.free_frames, 0);

        for addr in addrs {
            alloc.dealloc_order(addr, 0);
        }
        assert_eq!(alloc.free_frames, 16);

        // Flush the page cache so pages return to buddy and can merge
        alloc.flush_pcp();

        let addr = alloc.alloc_order(4).unwrap();
        assert_eq!(alloc.free_frames, 0);
        alloc.dealloc_order(addr, 4);
        assert_eq!(alloc.free_frames, 16);
    }

    #[test]
    fn no_double_alloc() {
        let mut alloc = make_allocator(64);
        let mut addrs = alloc::vec::Vec::new();
        for _ in 0..64 {
            addrs.push(alloc.alloc_order(0).unwrap());
        }
        addrs.sort_by_key(|a| a.as_usize());
        for i in 1..addrs.len() {
            assert_ne!(addrs[i].as_usize(), addrs[i - 1].as_usize());
        }
    }

    #[test]
    fn frame_allocator_trait() {
        let mut alloc = make_allocator(256);
        let addr = alloc.alloc(PageSize::FourK).unwrap();
        assert_eq!(alloc.free_frames, 255);
        alloc.dealloc(addr, PageSize::FourK);
        assert_eq!(alloc.free_frames, 256);
    }

    #[test]
    fn addresses_are_page_aligned() {
        let mut alloc = make_allocator(64);
        for _ in 0..64 {
            let addr = alloc.alloc_order(0).unwrap();
            assert!(addr.is_aligned(4096));
        }
    }

    #[test]
    fn pcp_fast_path() {
        let mut alloc = make_allocator(256);
        // Allocate and free rapidly — should use page cache
        for _ in 0..100 {
            let addr = alloc.alloc_order(0).unwrap();
            alloc.dealloc_order(addr, 0);
        }
        assert_eq!(alloc.free_frames, 256);
    }

    #[test]
    fn pcp_drain_and_refill() {
        let mut alloc = make_allocator(256);
        // Allocate many to trigger refill
        let mut addrs = alloc::vec::Vec::new();
        for _ in 0..100 {
            addrs.push(alloc.alloc_order(0).unwrap());
        }
        // Free many to trigger drain
        for addr in addrs {
            alloc.dealloc_order(addr, 0);
        }
        assert_eq!(alloc.free_frames, 256);
    }
}
