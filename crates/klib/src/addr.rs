#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PhysAddr(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct VirtAddr(pub usize);

impl PhysAddr {
    #[inline(always)]
    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    #[inline(always)]
    pub const fn as_usize(self) -> usize {
        self.0
    }

    #[inline(always)]
    pub const fn offset(self, offset: usize) -> Self {
        Self(self.0 + offset)
    }

    #[inline(always)]
    pub const fn is_aligned(self, align: usize) -> bool {
        self.0 & (align - 1) == 0
    }
}

impl VirtAddr {
    #[inline(always)]
    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    #[inline(always)]
    pub const fn as_usize(self) -> usize {
        self.0
    }

    #[inline(always)]
    pub const fn offset(self, offset: usize) -> Self {
        Self(self.0 + offset)
    }

    #[inline(always)]
    pub const fn is_aligned(self, align: usize) -> bool {
        self.0 & (align - 1) == 0
    }

    #[inline(always)]
    pub const fn as_ptr<T>(self) -> *const T {
        self.0 as *const T
    }

    #[inline(always)]
    pub const fn as_mut_ptr<T>(self) -> *mut T {
        self.0 as *mut T
    }
}
