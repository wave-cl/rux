/// Concrete slab allocator backed by the buddy frame allocator.
///
/// Each SlabCache manages objects of a single size. A slab is one 4K page
/// divided into fixed-size slots. Free slots are linked via an embedded
/// pointer at the start of each slot (free objects are at least 8 bytes).
///
/// When the freelist is empty, a new slab page is allocated from the
/// buddy allocator.

use crate::FrameAllocator;
use crate::PageSize;

/// A slab cache for fixed-size objects.
pub struct Slab {
    /// Size of each object (must be >= 8 for the freelist pointer).
    obj_size: usize,
    /// Head of the free list (embedded in free objects).
    free_list: *mut u8,
    /// Number of allocated objects.
    pub allocated: u32,
    /// Number of free objects on the list.
    pub free_count: u32,
}

unsafe impl Send for Slab {}
unsafe impl Sync for Slab {}

impl Slab {
    /// Create a new slab cache for objects of `obj_size` bytes.
    pub const fn new(obj_size: usize) -> Self {
        Self {
            obj_size: if obj_size < 8 { 8 } else { obj_size },
            free_list: core::ptr::null_mut(),
            allocated: 0,
            free_count: 0,
        }
    }

    /// Allocate one object. Returns a pointer to the object.
    /// Allocates a new slab page from `frame_alloc` if the freelist is empty.
    pub unsafe fn alloc(&mut self, frame_alloc: &mut dyn FrameAllocator) -> Option<*mut u8> {
        if self.free_list.is_null() {
            self.grow(frame_alloc)?;
        }

        // Pop from freelist
        let obj = self.free_list;
        self.free_list = *(obj as *mut *mut u8); // next = *obj
        self.allocated += 1;
        self.free_count -= 1;
        Some(obj)
    }

    /// Return an object to the slab.
    pub unsafe fn dealloc(&mut self, ptr: *mut u8) {
        // Push onto freelist: *ptr = old_head; head = ptr
        *(ptr as *mut *mut u8) = self.free_list;
        self.free_list = ptr;
        self.allocated -= 1;
        self.free_count += 1;
    }

    /// Allocate a new slab page and carve it into free objects.
    unsafe fn grow(&mut self, frame_alloc: &mut dyn FrameAllocator) -> Option<()> {
        let page = frame_alloc.alloc(PageSize::FourK).ok()?;
        let base = page.as_usize() as *mut u8;
        let objs_per_page = 4096 / self.obj_size;

        // Link all slots into the freelist
        for i in (0..objs_per_page).rev() {
            let slot = base.add(i * self.obj_size);
            *(slot as *mut *mut u8) = self.free_list;
            self.free_list = slot;
            self.free_count += 1;
        }

        Some(())
    }
}
