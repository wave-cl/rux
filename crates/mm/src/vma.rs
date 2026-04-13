use rux_klib::VirtAddr;
use crate::{MappingFlags, MemoryError};

/// Maximum VMAs per address space.
pub const MAX_VMAS: usize = 16;

/// Kind of virtual memory area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VmaKind {
    /// Anonymous memory (heap, stack, mmap MAP_ANONYMOUS).
    Anonymous = 0,
    /// File-backed memory (mmap of a file).
    FileBacked = 1,
    /// Stack region (grows downward).
    Stack = 2,
    /// Shared memory region (mmap MAP_SHARED).
    Shared = 3,
}

/// A virtual memory area — a contiguous range of virtual addresses
/// with uniform protection and backing.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Vma {
    /// Start of the VMA (inclusive, page-aligned).
    pub start: VirtAddr,
    /// End of the VMA (exclusive, page-aligned).
    pub end: VirtAddr,
    /// Protection and mapping flags.
    pub flags: MappingFlags,
    /// Type of backing.
    pub kind: VmaKind,
    pub _pad: [u8; 3],
    /// Backing file inode (0 for anonymous).
    pub inode: u64,
    /// Offset into the backing file.
    pub offset: u64,
}

const _: () = assert!(core::mem::size_of::<Vma>() == 40);

impl Vma {
    pub const EMPTY: Self = Self {
        start: VirtAddr::new(0),
        end: VirtAddr::new(0),
        flags: MappingFlags::NONE,
        kind: VmaKind::Anonymous,
        _pad: [0; 3],
        inode: 0,
        offset: 0,
    };

    /// Size of this VMA in bytes.
    #[inline(always)]
    pub const fn size(&self) -> usize {
        self.end.as_usize() - self.start.as_usize()
    }

    /// Check if an address falls within this VMA.
    #[inline(always)]
    pub const fn contains(&self, addr: VirtAddr) -> bool {
        addr.as_usize() >= self.start.as_usize() && addr.as_usize() < self.end.as_usize()
    }

    /// Check if this VMA overlaps with a range.
    #[inline(always)]
    pub const fn overlaps(&self, start: VirtAddr, end: VirtAddr) -> bool {
        self.start.as_usize() < end.as_usize() && start.as_usize() < self.end.as_usize()
    }
}

/// Sorted array of VMAs. Entries are sorted by start address.
/// Binary search for lookup, linear shift for insert/remove.
#[repr(C)]
pub struct VmaList {
    pub entries: [Vma; MAX_VMAS],
    pub count: u32,
    pub _pad: [u8; 4],
}

impl VmaList {
    pub const fn new() -> Self {
        Self {
            entries: [Vma::EMPTY; MAX_VMAS],
            count: 0,
            _pad: [0; 4],
        }
    }
}

impl Default for VmaList {
    fn default() -> Self { Self::new() }
}

/// VMA management operations.
pub trait VmaOps {
    /// Insert a VMA. Maintains sorted order. Rejects overlaps.
    fn insert(&mut self, vma: Vma) -> Result<(), MemoryError>;

    /// Remove the VMA containing `addr`. Returns the removed VMA.
    fn remove(&mut self, addr: VirtAddr) -> Result<Vma, MemoryError>;

    /// Find the VMA containing `addr`.
    fn find(&self, addr: VirtAddr) -> Option<&Vma>;

    /// Find the VMA containing `addr` (mutable).
    fn find_mut(&mut self, addr: VirtAddr) -> Option<&mut Vma>;

    /// Split a VMA at `addr` into two VMAs.
    fn split(&mut self, addr: VirtAddr) -> Result<(), MemoryError>;

    /// Change protection flags on a range.
    fn protect(
        &mut self,
        start: VirtAddr,
        end: VirtAddr,
        flags: MappingFlags,
    ) -> Result<(), MemoryError>;
}

impl VmaOps for VmaList {
    fn insert(&mut self, vma: Vma) -> Result<(), MemoryError> {
        if self.count as usize >= MAX_VMAS {
            return Err(MemoryError::OutOfVmas);
        }

        // Check for overlaps
        let n = self.count as usize;
        for i in 0..n {
            if self.entries[i].overlaps(vma.start, vma.end) {
                return Err(MemoryError::OverlappingVma);
            }
        }

        // Find insertion point (sorted by start address)
        let mut pos = n;
        for i in 0..n {
            if vma.start.as_usize() < self.entries[i].start.as_usize() {
                pos = i;
                break;
            }
        }

        // Shift entries right
        let mut i = n;
        while i > pos {
            self.entries[i] = self.entries[i - 1];
            i -= 1;
        }

        self.entries[pos] = vma;
        self.count += 1;
        Ok(())
    }

    fn remove(&mut self, addr: VirtAddr) -> Result<Vma, MemoryError> {
        let n = self.count as usize;
        for i in 0..n {
            if self.entries[i].contains(addr) {
                let removed = self.entries[i];
                // Shift left
                for j in i..n - 1 {
                    self.entries[j] = self.entries[j + 1];
                }
                self.entries[n - 1] = Vma::EMPTY;
                self.count -= 1;
                return Ok(removed);
            }
        }
        Err(MemoryError::NotMapped)
    }

    fn find(&self, addr: VirtAddr) -> Option<&Vma> {
        let n = self.count as usize;
        // Binary search: find the last VMA with start <= addr
        let mut lo = 0usize;
        let mut hi = n;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.entries[mid].start.as_usize() <= addr.as_usize() {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        // lo-1 is the candidate (last VMA with start <= addr)
        if lo > 0 && self.entries[lo - 1].contains(addr) {
            Some(&self.entries[lo - 1])
        } else {
            None
        }
    }

    fn find_mut(&mut self, addr: VirtAddr) -> Option<&mut Vma> {
        let n = self.count as usize;
        let mut lo = 0usize;
        let mut hi = n;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.entries[mid].start.as_usize() <= addr.as_usize() {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo > 0 && self.entries[lo - 1].contains(addr) {
            Some(&mut self.entries[lo - 1])
        } else {
            None
        }
    }

    fn split(&mut self, addr: VirtAddr) -> Result<(), MemoryError> {
        if self.count as usize >= MAX_VMAS {
            return Err(MemoryError::OutOfVmas);
        }

        let n = self.count as usize;
        for i in 0..n {
            if self.entries[i].contains(addr) && addr != self.entries[i].start {
                let original = self.entries[i];
                // Shrink the original to [start, addr)
                self.entries[i].end = addr;
                // Insert new VMA [addr, original.end) after
                let new_vma = Vma {
                    start: addr,
                    end: original.end,
                    flags: original.flags,
                    kind: original.kind,
                    _pad: [0; 3],
                    inode: original.inode,
                    offset: original.offset + (addr.as_usize() - original.start.as_usize()) as u64,
                };
                // Shift right from i+1
                let mut j = n;
                while j > i + 1 {
                    self.entries[j] = self.entries[j - 1];
                    j -= 1;
                }
                self.entries[i + 1] = new_vma;
                self.count += 1;
                return Ok(());
            }
        }
        Err(MemoryError::NotMapped)
    }

    fn protect(
        &mut self,
        start: VirtAddr,
        end: VirtAddr,
        flags: MappingFlags,
    ) -> Result<(), MemoryError> {
        let n = self.count as usize;
        for i in 0..n {
            if self.entries[i].overlaps(start, end) {
                self.entries[i].flags = flags;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vma(start: usize, end: usize) -> Vma {
        Vma {
            start: VirtAddr::new(start),
            end: VirtAddr::new(end),
            flags: MappingFlags::READ.or(MappingFlags::WRITE),
            kind: VmaKind::Anonymous,
            _pad: [0; 3],
            inode: 0,
            offset: 0,
        }
    }

    #[test]
    fn insert_maintains_sorted_order() {
        let mut list = VmaList::new();
        list.insert(make_vma(0x3000, 0x4000)).unwrap();
        list.insert(make_vma(0x1000, 0x2000)).unwrap();
        list.insert(make_vma(0x5000, 0x6000)).unwrap();
        assert_eq!(list.count, 3);
        assert_eq!(list.entries[0].start.as_usize(), 0x1000);
        assert_eq!(list.entries[1].start.as_usize(), 0x3000);
        assert_eq!(list.entries[2].start.as_usize(), 0x5000);
    }

    #[test]
    fn insert_rejects_overlap() {
        let mut list = VmaList::new();
        list.insert(make_vma(0x1000, 0x3000)).unwrap();
        assert_eq!(list.insert(make_vma(0x2000, 0x4000)).unwrap_err(), MemoryError::OverlappingVma);
    }

    #[test]
    fn insert_full_returns_error() {
        let mut list = VmaList::new();
        for i in 0..MAX_VMAS {
            let base = i * 0x1000;
            list.insert(make_vma(base, base + 0x1000)).unwrap();
        }
        assert_eq!(list.insert(make_vma(MAX_VMAS * 0x1000, MAX_VMAS * 0x1000 + 0x1000)).unwrap_err(), MemoryError::OutOfVmas);
    }

    #[test]
    fn find_binary_search() {
        let mut list = VmaList::new();
        list.insert(make_vma(0x1000, 0x2000)).unwrap();
        list.insert(make_vma(0x3000, 0x5000)).unwrap();
        list.insert(make_vma(0x7000, 0x8000)).unwrap();

        assert!(list.find(VirtAddr::new(0x1500)).is_some());
        assert_eq!(list.find(VirtAddr::new(0x1500)).unwrap().start.as_usize(), 0x1000);
        assert!(list.find(VirtAddr::new(0x4000)).is_some());
        assert!(list.find(VirtAddr::new(0x2500)).is_none()); // gap
        assert!(list.find(VirtAddr::new(0x0500)).is_none()); // before all
        assert!(list.find(VirtAddr::new(0x9000)).is_none()); // after all
    }

    #[test]
    fn remove_and_shift() {
        let mut list = VmaList::new();
        list.insert(make_vma(0x1000, 0x2000)).unwrap();
        list.insert(make_vma(0x3000, 0x4000)).unwrap();
        list.insert(make_vma(0x5000, 0x6000)).unwrap();
        let removed = list.remove(VirtAddr::new(0x3500)).unwrap();
        assert_eq!(removed.start.as_usize(), 0x3000);
        assert_eq!(list.count, 2);
        assert_eq!(list.entries[0].start.as_usize(), 0x1000);
        assert_eq!(list.entries[1].start.as_usize(), 0x5000);
    }

    #[test]
    fn split_creates_two_vmas() {
        let mut list = VmaList::new();
        list.insert(make_vma(0x1000, 0x4000)).unwrap();
        list.split(VirtAddr::new(0x2000)).unwrap();
        assert_eq!(list.count, 2);
        assert_eq!(list.entries[0].start.as_usize(), 0x1000);
        assert_eq!(list.entries[0].end.as_usize(), 0x2000);
        assert_eq!(list.entries[1].start.as_usize(), 0x2000);
        assert_eq!(list.entries[1].end.as_usize(), 0x4000);
    }

    #[test]
    fn protect_changes_flags() {
        let mut list = VmaList::new();
        list.insert(make_vma(0x1000, 0x3000)).unwrap();
        list.protect(VirtAddr::new(0x1000), VirtAddr::new(0x3000), MappingFlags::READ).unwrap();
        assert_eq!(list.entries[0].flags, MappingFlags::READ);
    }

    #[test]
    fn vma_contains_and_overlaps() {
        let vma = make_vma(0x1000, 0x3000);
        assert!(vma.contains(VirtAddr::new(0x1000)));
        assert!(vma.contains(VirtAddr::new(0x2FFF)));
        assert!(!vma.contains(VirtAddr::new(0x3000))); // exclusive end
        assert!(!vma.contains(VirtAddr::new(0x0FFF)));

        assert!(vma.overlaps(VirtAddr::new(0x2000), VirtAddr::new(0x4000)));
        assert!(vma.overlaps(VirtAddr::new(0x0000), VirtAddr::new(0x2000)));
        assert!(!vma.overlaps(VirtAddr::new(0x3000), VirtAddr::new(0x4000)));
        assert!(!vma.overlaps(VirtAddr::new(0x0000), VirtAddr::new(0x1000)));
    }
}
