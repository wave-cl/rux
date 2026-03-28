use crate::MemoryError;

/// A slab cache for fixed-size kernel object allocation.
/// Each cache manages objects of a single size (e.g., 1024-byte Task structs).
///
/// The slab uses page-sized slabs internally. Each slab page contains
/// a freelist of objects. When a slab is exhausted, a new page is
/// allocated from the frame allocator.
#[repr(C)]
pub struct SlabCache {
    /// Size of each object in bytes.
    pub obj_size: u32,
    /// Alignment requirement for each object.
    pub align: u32,
    /// Number of objects that fit in a single slab page.
    pub objs_per_slab: u32,
    pub _pad0: [u8; 4],
    /// Head of the per-object freelist (embedded in free objects).
    pub free_list: *mut u8,
    /// Total number of allocated objects.
    pub allocated: u64,
    /// Total number of slab pages backing this cache.
    pub slab_count: u32,
    pub _pad1: [u8; 4],
}

// SAFETY: SlabCache contains raw pointers for the freelist.
// The kernel accesses slab caches under appropriate locks.
unsafe impl Send for SlabCache {}
unsafe impl Sync for SlabCache {}

impl SlabCache {
    /// Create a new slab cache for objects of `obj_size` bytes
    /// with `align`-byte alignment.
    pub const fn new(obj_size: u32, align: u32) -> Self {
        let effective_size = if obj_size < 8 { 8 } else { obj_size }; // min size for freelist ptr
        let objs_per_slab = 4096 / effective_size;
        Self {
            obj_size: effective_size,
            align,
            objs_per_slab,
            _pad0: [0; 4],
            free_list: core::ptr::null_mut(),
            allocated: 0,
            slab_count: 0,
            _pad1: [0; 4],
        }
    }

    /// Check if the freelist is empty (need to allocate a new slab page).
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.free_list.is_null()
    }
}

/// Slab allocator operations.
pub trait SlabAllocator {
    /// Allocate one object from this cache.
    fn alloc(&mut self) -> Result<*mut u8, MemoryError>;

    /// Return an object to this cache.
    ///
    /// # Safety
    /// `ptr` must have been allocated from this cache.
    unsafe fn dealloc(&mut self, ptr: *mut u8);
}
