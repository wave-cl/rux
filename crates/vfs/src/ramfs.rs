#![allow(clippy::cast_possible_truncation)]

#[cfg(any(test, feature = "alloc"))]
extern crate alloc;

use crate::{
    DirEntry, FileSystem, FileName, InodeId, InodeStat, InodeType, VfsError,
    S_IFDIR, S_IFLNK, S_IFREG, S_IFMT,
};
use rux_klib::PhysAddr;
use rux_mm::{FrameAllocator, PageSize};

// ── Constants ──────────────────────────────────────────────────────────

pub const MAX_INODES: usize = 4096;
pub const PAGE_SIZE: usize = 4096;

/// Number of direct page pointers per inode.
const DIRECT_PAGES: usize = 12;

/// Sentinel: no page allocated.
const NO_PAGE: u64 = u64::MAX;

/// Maximum file size: 12 direct pages + 512 indirect entries = 524 pages.
const MAX_FILE_PAGES: usize = DIRECT_PAGES + PAGE_SIZE / 8;

/// Directory entry size (packed, on-page).
/// Layout: inode(u32) + name_len(u8) + kind(u8) + pad(2) + name([u8; 256]) = 264 bytes.
const DIR_ENTRY_SIZE: usize = 264;
const DIR_ENTRY_NAME_CAP: usize = 255;
const DIR_ENTRIES_PER_PAGE: usize = PAGE_SIZE / DIR_ENTRY_SIZE; // 15

// ── Inode metadata ─────────────────────────────────────────────────────

#[derive(Clone, Copy)]
#[repr(C)]
pub struct InodeMeta {
    pub active: bool,
    pub kind: InodeType,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    /// Direct page physical addresses (NO_PAGE = unallocated).
    pub direct: [u64; DIRECT_PAGES],
    /// Single-indirect page physical address (NO_PAGE = unallocated).
    /// Points to a page containing up to 512 u64 physical addresses.
    pub indirect: u64,
    pub _pad: [u8; 8],
}

// 1 + 1 + 4 + 4 + 4 + 4 + 8 + 8 + 8 + 8 + 96 + 8 + 8 = 162, padded to 168 with _pad
// Actually let's compute: bool=1, InodeType=1 => 2, then u32=4 (offset 4 after padding??)
// repr(C) so fields laid out in order with alignment padding.
// Let's just ensure it works. Size doesn't need to be exact.

impl InodeMeta {
    const ZERO: Self = Self {
        active: false,
        kind: InodeType::File,
        mode: 0,
        nlink: 0,
        uid: 0,
        gid: 0,
        size: 0,
        atime: 0,
        mtime: 0,
        ctime: 0,
        direct: [NO_PAGE; DIRECT_PAGES],
        indirect: NO_PAGE,
        _pad: [0; 8],
    };
}

// ── RamFs ──────────────────────────────────────────────────────────────

/// In-memory RAM filesystem backed by a frame allocator.
///
/// Inode metadata is stored inline (flat array). File/directory data pages
/// are allocated on demand from the provided `FrameAllocator`.
///
/// Each inode supports up to 12 direct pages (48 KiB) plus one
/// single-indirect page (512 entries x 4K = 2 MiB) for a maximum file
/// size of ~2 MiB.
///
/// Directory entries are stored in data pages (15 entries per 4K page).
pub struct RamFs {
    inodes: [InodeMeta; MAX_INODES],
    alloc: *mut dyn FrameAllocator,
    next_inode: u32,
}

impl RamFs {
    /// Create a new RamFs backed by the given frame allocator.
    ///
    /// Allocates one page for the root directory (inode 0).
    ///
    /// # Safety
    /// The caller must ensure `alloc` remains valid for the lifetime of RamFs
    /// and that the allocated pages are identity-mapped (phys addr = usable pointer).
    pub unsafe fn new(alloc: *mut dyn FrameAllocator) -> Self {
        let mut fs = Self {
            inodes: [InodeMeta::ZERO; MAX_INODES],
            alloc,
            next_inode: 1,
        };

        // Allocate a page for root directory entries first (needs &mut fs).
        let page_addr = fs.alloc_page().expect("RamFs::new: cannot allocate root page");

        // Root inode (0) -- directory with "." and "..".
        let root = &mut fs.inodes[0];
        root.active = true;
        root.kind = InodeType::Directory;
        root.mode = S_IFDIR | 0o755;
        root.nlink = 2;
        root.direct[0] = page_addr;
        root.size = 2; // "." and ".."

        let page = fs.page_mut(page_addr);
        Self::write_dir_entry_raw(page, 0, b".", InodeType::Directory, 0);
        Self::write_dir_entry_raw(page, 1, b"..", InodeType::Directory, 0);

        fs
    }

    /// Create a new RamFs on the heap. Convenience for tests and hosted environments.
    #[cfg(any(test, feature = "alloc"))]
    pub unsafe fn new_boxed(alloc: *mut dyn FrameAllocator) -> alloc::boxed::Box<Self> {
        alloc::boxed::Box::new(Self::new(alloc))
    }

    /// Initialize a pre-zeroed RamFs in place at a fixed memory address.
    /// This avoids creating the ~700 KB struct on the stack.
    ///
    /// # Safety
    /// - `this` must point to a zeroed region of at least `size_of::<RamFs>()` bytes.
    /// - `alloc` must remain valid for the lifetime of the RamFs.
    /// - Identity mapping must be active (phys addr = usable pointer).
    pub unsafe fn init_at(this: *mut Self, alloc: *mut dyn FrameAllocator) {
        // Set fields (inodes are already zeroed = InodeMeta::ZERO since ZERO has all-zero bytes
        // except for direct[] which is [NO_PAGE; 12] = [u64::MAX; 12])
        (*this).alloc = alloc;
        (*this).next_inode = 1;

        // Set all inode direct pages to NO_PAGE (u64::MAX, not 0)
        for i in 0..MAX_INODES {
            for d in 0..12 {
                (*this).inodes[i].direct[d] = NO_PAGE;
            }
            (*this).inodes[i].indirect = NO_PAGE;
        }

        // Allocate a page for root directory entries
        let page_addr = (*this).alloc_page().expect("RamFs::init_at: cannot allocate root page");

        // Root inode (0) -- directory with "." and ".."
        let root = &mut (*this).inodes[0];
        root.active = true;
        root.kind = InodeType::Directory;
        root.mode = S_IFDIR | 0o755;
        root.nlink = 2;
        root.direct[0] = page_addr;
        root.size = 2; // "." and ".."

        let page = (*this).page_mut(page_addr);
        Self::write_dir_entry_raw(page, 0, b".", InodeType::Directory, 0);
        Self::write_dir_entry_raw(page, 1, b"..", InodeType::Directory, 0);
    }

    // ── Page access helpers ──────────────────────────────────────────

    /// Convert a physical address to a mutable page-sized slice.
    /// Assumes identity mapping.
    #[inline(always)]
    fn page_mut(&self, addr: u64) -> &mut [u8; PAGE_SIZE] {
        unsafe { &mut *(addr as *mut [u8; PAGE_SIZE]) }
    }

    /// Convert a physical address to an immutable page-sized slice.
    #[inline(always)]
    fn page_ref(&self, addr: u64) -> &[u8; PAGE_SIZE] {
        unsafe { &*(addr as *const [u8; PAGE_SIZE]) }
    }

    // ── Frame allocator wrappers ─────────────────────────────────────

    fn alloc_page(&mut self) -> Result<u64, VfsError> {
        let allocator = unsafe { &mut *self.alloc };
        let addr = allocator.alloc(PageSize::FourK).map_err(|_| VfsError::NoSpace)?;
        let ptr = addr.as_usize() as *mut u8;
        // Zero the page.
        unsafe { core::ptr::write_bytes(ptr, 0, PAGE_SIZE); }
        Ok(addr.as_usize() as u64)
    }

    fn free_page(&mut self, addr: u64) {
        if addr == NO_PAGE {
            return;
        }
        let allocator = unsafe { &mut *self.alloc };
        allocator.dealloc(PhysAddr::new(addr as usize), PageSize::FourK);
    }

    // ── Inode helpers ────────────────────────────────────────────────

    #[inline(always)]
    fn meta(&self, ino: InodeId) -> Result<&InodeMeta, VfsError> {
        let idx = ino as usize;
        if idx >= MAX_INODES {
            return Err(VfsError::NotFound);
        }
        let m = &self.inodes[idx];
        if !m.active {
            return Err(VfsError::NotFound);
        }
        Ok(m)
    }

    #[inline(always)]
    fn meta_mut(&mut self, ino: InodeId) -> Result<&mut InodeMeta, VfsError> {
        let idx = ino as usize;
        if idx >= MAX_INODES {
            return Err(VfsError::NotFound);
        }
        let m = &mut self.inodes[idx];
        if !m.active {
            return Err(VfsError::NotFound);
        }
        Ok(m)
    }

    fn alloc_inode(&mut self) -> Result<usize, VfsError> {
        let start = self.next_inode as usize;
        let mut idx = start;
        loop {
            if idx >= MAX_INODES {
                idx = 1; // skip root
            }
            if !self.inodes[idx].active {
                self.next_inode = (idx + 1) as u32;
                return Ok(idx);
            }
            idx += 1;
            if idx == start {
                return Err(VfsError::NoSpace);
            }
        }
    }

    /// Free all data pages associated with an inode, then mark it inactive.
    fn free_inode(&mut self, idx: usize) {
        // Collect addresses to free first (avoids borrow conflicts).
        let mut to_free = [NO_PAGE; DIRECT_PAGES + 1]; // direct + indirect page itself
        let m = &self.inodes[idx];

        for i in 0..DIRECT_PAGES {
            to_free[i] = m.direct[i];
        }
        let indirect_addr = m.indirect;
        to_free[DIRECT_PAGES] = indirect_addr;

        // If there's an indirect page, copy out its entries before freeing.
        let mut indirect_entries = [NO_PAGE; PAGE_SIZE / 8];
        if indirect_addr != NO_PAGE {
            let indirect_page = self.page_ref(indirect_addr);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    indirect_page.as_ptr() as *const u64,
                    indirect_entries.as_mut_ptr(),
                    PAGE_SIZE / 8,
                );
            }
        }

        // Now free everything.
        for &addr in &to_free {
            self.free_page(addr);
        }
        if indirect_addr != NO_PAGE {
            for &entry in &indirect_entries {
                if entry != NO_PAGE {
                    self.free_page(entry);
                }
            }
        }

        self.inodes[idx] = InodeMeta::ZERO;
    }

    // ── Data page management (extent list) ───────────────────────────

    /// Get the physical address of the Nth data page for an inode.
    /// Returns NO_PAGE if not allocated.
    fn get_data_page(&self, m: &InodeMeta, page_idx: usize) -> u64 {
        if page_idx < DIRECT_PAGES {
            m.direct[page_idx]
        } else if m.indirect != NO_PAGE {
            let slot = page_idx - DIRECT_PAGES;
            if slot >= PAGE_SIZE / 8 {
                return NO_PAGE;
            }
            let indirect_page = self.page_ref(m.indirect);
            let addr = u64::from_le_bytes([
                indirect_page[slot * 8],
                indirect_page[slot * 8 + 1],
                indirect_page[slot * 8 + 2],
                indirect_page[slot * 8 + 3],
                indirect_page[slot * 8 + 4],
                indirect_page[slot * 8 + 5],
                indirect_page[slot * 8 + 6],
                indirect_page[slot * 8 + 7],
            ]);
            if addr == 0 { NO_PAGE } else { addr }
        } else {
            NO_PAGE
        }
    }

    /// Ensure the Nth data page exists for an inode, allocating if needed.
    /// Returns the physical address.
    fn ensure_data_page(&mut self, ino_idx: usize, page_idx: usize) -> Result<u64, VfsError> {
        if page_idx >= MAX_FILE_PAGES {
            return Err(VfsError::NoSpace);
        }

        if page_idx < DIRECT_PAGES {
            if self.inodes[ino_idx].direct[page_idx] == NO_PAGE {
                let addr = self.alloc_page()?;
                self.inodes[ino_idx].direct[page_idx] = addr;
            }
            Ok(self.inodes[ino_idx].direct[page_idx])
        } else {
            // Need indirect page.
            if self.inodes[ino_idx].indirect == NO_PAGE {
                let addr = self.alloc_page()?;
                // Initialize all entries to NO_PAGE (0xFF..FF).
                let page = self.page_mut(addr);
                for byte in page.iter_mut() {
                    *byte = 0xFF;
                }
                self.inodes[ino_idx].indirect = addr;
            }

            let slot = page_idx - DIRECT_PAGES;
            let indirect_addr = self.inodes[ino_idx].indirect;
            let indirect_page = self.page_ref(indirect_addr);
            let existing = u64::from_le_bytes([
                indirect_page[slot * 8],
                indirect_page[slot * 8 + 1],
                indirect_page[slot * 8 + 2],
                indirect_page[slot * 8 + 3],
                indirect_page[slot * 8 + 4],
                indirect_page[slot * 8 + 5],
                indirect_page[slot * 8 + 6],
                indirect_page[slot * 8 + 7],
            ]);

            if existing == NO_PAGE {
                let data_addr = self.alloc_page()?;
                let indirect_page = self.page_mut(indirect_addr);
                let bytes = data_addr.to_le_bytes();
                indirect_page[slot * 8..slot * 8 + 8].copy_from_slice(&bytes);
                Ok(data_addr)
            } else {
                Ok(existing)
            }
        }
    }

    /// Free data pages from `from_page` (inclusive) to the end.
    /// Used by truncate.
    fn free_data_pages_from(&mut self, ino_idx: usize, from_page: usize) {
        // Free direct pages.
        for i in from_page..DIRECT_PAGES {
            let addr = self.inodes[ino_idx].direct[i];
            if addr != NO_PAGE {
                self.free_page(addr);
                self.inodes[ino_idx].direct[i] = NO_PAGE;
            }
        }

        // Free indirect entries.
        if self.inodes[ino_idx].indirect != NO_PAGE {
            let start_slot = if from_page > DIRECT_PAGES { from_page - DIRECT_PAGES } else { 0 };
            let indirect_addr = self.inodes[ino_idx].indirect;

            let mut any_remaining = false;
            for slot in 0..PAGE_SIZE / 8 {
                let page = self.page_ref(indirect_addr);
                let entry = u64::from_le_bytes([
                    page[slot * 8],
                    page[slot * 8 + 1],
                    page[slot * 8 + 2],
                    page[slot * 8 + 3],
                    page[slot * 8 + 4],
                    page[slot * 8 + 5],
                    page[slot * 8 + 6],
                    page[slot * 8 + 7],
                ]);
                if slot >= start_slot && entry != NO_PAGE {
                    self.free_page(entry);
                    let page = self.page_mut(indirect_addr);
                    let bytes = NO_PAGE.to_le_bytes();
                    page[slot * 8..slot * 8 + 8].copy_from_slice(&bytes);
                } else if slot < start_slot && entry != NO_PAGE {
                    any_remaining = true;
                }
            }

            // If no indirect entries remain, free the indirect page itself.
            if !any_remaining && from_page <= DIRECT_PAGES {
                self.free_page(indirect_addr);
                self.inodes[ino_idx].indirect = NO_PAGE;
            }
        }
    }

    /// Count the number of allocated data pages for an inode.
    fn count_data_pages(&self, m: &InodeMeta) -> u64 {
        let mut count = 0u64;
        for i in 0..DIRECT_PAGES {
            if m.direct[i] != NO_PAGE {
                count += 1;
            }
        }
        if m.indirect != NO_PAGE {
            count += 1; // the indirect page itself
            let indirect_page = self.page_ref(m.indirect);
            for slot in 0..PAGE_SIZE / 8 {
                let entry = u64::from_le_bytes([
                    indirect_page[slot * 8],
                    indirect_page[slot * 8 + 1],
                    indirect_page[slot * 8 + 2],
                    indirect_page[slot * 8 + 3],
                    indirect_page[slot * 8 + 4],
                    indirect_page[slot * 8 + 5],
                    indirect_page[slot * 8 + 6],
                    indirect_page[slot * 8 + 7],
                ]);
                if entry != NO_PAGE {
                    count += 1;
                }
            }
        }
        count
    }

    // ── Directory entry helpers ──────────────────────────────────────

    /// Write a packed dir entry into a page at the given slot index.
    fn write_dir_entry_raw(
        page: &mut [u8; PAGE_SIZE],
        slot: usize,
        name: &[u8],
        kind: InodeType,
        ino: u32,
    ) {
        let off = slot * DIR_ENTRY_SIZE;
        let len = name.len().min(DIR_ENTRY_NAME_CAP);
        // inode (4 bytes LE)
        let ino_bytes = ino.to_le_bytes();
        page[off..off + 4].copy_from_slice(&ino_bytes);
        // name_len (1 byte)
        page[off + 4] = len as u8;
        // kind (1 byte)
        page[off + 5] = kind as u8;
        // pad (2 bytes)
        page[off + 6] = 0;
        page[off + 7] = 0;
        // name
        page[off + 8..off + 8 + len].copy_from_slice(&name[..len]);
        // Zero the rest.
        for b in &mut page[off + 8 + len..off + DIR_ENTRY_SIZE] {
            *b = 0;
        }
    }

    /// Read a packed dir entry. Returns (name_len, kind_byte, inode).
    #[inline(always)]
    fn read_dir_entry_raw(page: &[u8; PAGE_SIZE], slot: usize) -> (u8, u8, u32) {
        let off = slot * DIR_ENTRY_SIZE;
        let ino = u32::from_le_bytes([page[off], page[off + 1], page[off + 2], page[off + 3]]);
        let nlen = page[off + 4];
        let kind = page[off + 5];
        (nlen, kind, ino)
    }

    /// Get the name bytes of a dir entry at `slot`.
    #[inline(always)]
    fn dir_entry_name(page: &[u8; PAGE_SIZE], slot: usize, nlen: u8) -> &[u8] {
        let off = slot * DIR_ENTRY_SIZE + 8;
        &page[off..off + nlen as usize]
    }

    /// Compute the page index and slot within that page for a linear dir entry index.
    #[inline(always)]
    fn dir_entry_location(entry_idx: usize) -> (usize, usize) {
        (entry_idx / DIR_ENTRIES_PER_PAGE, entry_idx % DIR_ENTRIES_PER_PAGE)
    }

    /// Look up a name in a directory. Returns (linear entry index, inode number).
    fn dir_lookup(&self, dir_meta: &InodeMeta, name: &[u8]) -> Result<(usize, u32), VfsError> {
        let count = dir_meta.size as usize;
        for entry_idx in 0..count {
            let (page_idx, slot) = Self::dir_entry_location(entry_idx);
            let page_addr = self.get_data_page(dir_meta, page_idx);
            if page_addr == NO_PAGE {
                continue;
            }
            let page = self.page_ref(page_addr);
            let (nlen, _kind, ino) = Self::read_dir_entry_raw(page, slot);
            if nlen as usize == name.len() {
                if Self::dir_entry_name(page, slot, nlen) == name {
                    return Ok((entry_idx, ino));
                }
            }
        }
        Err(VfsError::NotFound)
    }

    /// Add a dir entry to a directory.
    fn dir_add_entry(
        &mut self,
        dir_ino: usize,
        name: &[u8],
        kind: InodeType,
        target_ino: u32,
    ) -> Result<usize, VfsError> {
        let count = self.inodes[dir_ino].size as usize;
        let (page_idx, slot) = Self::dir_entry_location(count);
        let page_addr = self.ensure_data_page(dir_ino, page_idx)?;
        let page = self.page_mut(page_addr);
        Self::write_dir_entry_raw(page, slot, name, kind, target_ino);
        self.inodes[dir_ino].size = (count + 1) as u64;
        Ok(count)
    }

    /// Remove a dir entry by linear index, compact by moving last entry into the gap.
    fn dir_remove_entry(&mut self, dir_ino: usize, entry_idx: usize) {
        let count = self.inodes[dir_ino].size as usize;
        if entry_idx < count - 1 {
            // Copy last entry into this slot.
            let last = count - 1;
            let (last_page_idx, last_slot) = Self::dir_entry_location(last);
            let last_page_addr = self.get_data_page(&self.inodes[dir_ino], last_page_idx);
            let last_page = self.page_ref(last_page_addr);
            let src_off = last_slot * DIR_ENTRY_SIZE;
            let mut tmp = [0u8; DIR_ENTRY_SIZE];
            tmp.copy_from_slice(&last_page[src_off..src_off + DIR_ENTRY_SIZE]);

            let (dst_page_idx, dst_slot) = Self::dir_entry_location(entry_idx);
            let dst_page_addr = self.get_data_page(&self.inodes[dir_ino], dst_page_idx);
            let dst_page = self.page_mut(dst_page_addr);
            let dst_off = dst_slot * DIR_ENTRY_SIZE;
            dst_page[dst_off..dst_off + DIR_ENTRY_SIZE].copy_from_slice(&tmp);
        }
        self.inodes[dir_ino].size = (count - 1) as u64;

        // Optionally free now-empty trailing pages.
        let new_count = count - 1;
        let (needed_pages, _) = Self::dir_entry_location(new_count.max(1) - 1);
        let needed_pages = needed_pages + 1; // pages needed = last used page + 1
        // Free pages beyond what's needed (only if we actually reduced).
        let (old_last_page, _) = Self::dir_entry_location(count - 1);
        for pg in needed_pages..=old_last_page {
            if pg < DIRECT_PAGES {
                let addr = self.inodes[dir_ino].direct[pg];
                if addr != NO_PAGE {
                    self.free_page(addr);
                    self.inodes[dir_ino].direct[pg] = NO_PAGE;
                }
            }
            // Indirect pages for dirs are unlikely but handle correctly.
        }
    }

    /// Ensure a directory is valid for child operations.
    fn check_dir(&self, dir: InodeId) -> Result<usize, VfsError> {
        let idx = dir as usize;
        if idx >= MAX_INODES {
            return Err(VfsError::NotFound);
        }
        let m = &self.inodes[idx];
        if !m.active {
            return Err(VfsError::NotFound);
        }
        if m.kind != InodeType::Directory {
            return Err(VfsError::NotADirectory);
        }
        Ok(idx)
    }
}

// ── FileSystem impl ────────────────────────────────────────────────────

impl FileSystem for RamFs {
    #[inline(always)]
    fn root_inode(&self) -> InodeId {
        0
    }

    fn stat(&self, ino: InodeId, buf: &mut InodeStat) -> Result<(), VfsError> {
        let m = self.meta(ino)?;
        buf.ino = ino;
        buf.mode = m.mode;
        buf.nlink = m.nlink;
        buf.uid = m.uid;
        buf.gid = m.gid;
        buf.size = match m.kind {
            InodeType::Directory => m.size * DIR_ENTRY_SIZE as u64,
            _ => m.size,
        };
        let pages = self.count_data_pages(m);
        buf.blocks = pages * (PAGE_SIZE as u64 / 512);
        buf.blksize = PAGE_SIZE as u32;
        buf._pad0 = 0;
        buf.atime = m.atime;
        buf.mtime = m.mtime;
        buf.ctime = m.ctime;
        buf.dev = 0;
        buf.rdev = 0;
        Ok(())
    }

    fn read(&self, ino: InodeId, offset: u64, buf: &mut [u8]) -> Result<usize, VfsError> {
        let m = self.meta(ino)?;
        if m.kind == InodeType::Directory {
            return Err(VfsError::IsADirectory);
        }
        if offset >= m.size {
            return Ok(0);
        }
        let avail = (m.size - offset) as usize;
        let to_read = buf.len().min(avail);
        let mut buf_off = 0usize;
        let mut file_off = offset as usize;

        while buf_off < to_read {
            let page_idx = file_off / PAGE_SIZE;
            let page_off = file_off % PAGE_SIZE;
            let chunk = (PAGE_SIZE - page_off).min(to_read - buf_off);

            let page_addr = self.get_data_page(m, page_idx);
            if page_addr == NO_PAGE {
                // Sparse: read as zeros.
                for b in &mut buf[buf_off..buf_off + chunk] {
                    *b = 0;
                }
            } else {
                let page = self.page_ref(page_addr);
                buf[buf_off..buf_off + chunk].copy_from_slice(&page[page_off..page_off + chunk]);
            }
            buf_off += chunk;
            file_off += chunk;
        }
        Ok(to_read)
    }

    fn write(&mut self, ino: InodeId, offset: u64, buf: &[u8]) -> Result<usize, VfsError> {
        let idx = ino as usize;
        if idx >= MAX_INODES || !self.inodes[idx].active {
            return Err(VfsError::NotFound);
        }
        if self.inodes[idx].kind == InodeType::Directory {
            return Err(VfsError::IsADirectory);
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let end = offset as usize + buf.len();
        let max_size = MAX_FILE_PAGES * PAGE_SIZE;
        if end > max_size {
            return Err(VfsError::NoSpace);
        }

        let mut buf_off = 0usize;
        let mut file_off = offset as usize;

        while buf_off < buf.len() {
            let page_idx = file_off / PAGE_SIZE;
            let page_off = file_off % PAGE_SIZE;
            let chunk = (PAGE_SIZE - page_off).min(buf.len() - buf_off);

            let page_addr = self.ensure_data_page(idx, page_idx)?;
            let page = self.page_mut(page_addr);
            page[page_off..page_off + chunk].copy_from_slice(&buf[buf_off..buf_off + chunk]);

            buf_off += chunk;
            file_off += chunk;
        }

        if end as u64 > self.inodes[idx].size {
            self.inodes[idx].size = end as u64;
        }
        Ok(buf.len())
    }

    fn truncate(&mut self, ino: InodeId, size: u64) -> Result<(), VfsError> {
        let idx = ino as usize;
        let m = self.meta_mut(ino)?;
        if m.kind == InodeType::Directory {
            return Err(VfsError::IsADirectory);
        }
        let max_size = (MAX_FILE_PAGES * PAGE_SIZE) as u64;
        if size > max_size {
            return Err(VfsError::NoSpace);
        }

        let old_size = self.inodes[idx].size;
        self.inodes[idx].size = size;

        if size < old_size {
            // Free pages that are no longer needed.
            let needed_pages = if size == 0 {
                0
            } else {
                ((size as usize) + PAGE_SIZE - 1) / PAGE_SIZE
            };
            self.free_data_pages_from(idx, needed_pages);
        }

        Ok(())
    }

    fn lookup(&self, dir: InodeId, name: FileName<'_>) -> Result<InodeId, VfsError> {
        let dir_idx = self.check_dir(dir)?;
        let dm = &self.inodes[dir_idx];
        let (_entry_idx, ino) = self.dir_lookup(dm, name.as_bytes())?;
        Ok(ino as InodeId)
    }

    fn create(
        &mut self,
        dir: InodeId,
        name: FileName<'_>,
        mode: u32,
    ) -> Result<InodeId, VfsError> {
        let dir_idx = self.check_dir(dir)?;
        let dm = &self.inodes[dir_idx];
        if self.dir_lookup(dm, name.as_bytes()).is_ok() {
            return Err(VfsError::AlreadyExists);
        }
        let new_ino = self.alloc_inode()?;
        {
            let m = &mut self.inodes[new_ino];
            m.active = true;
            m.kind = InodeType::File;
            m.mode = S_IFREG | (mode & 0o7777);
            m.nlink = 1;
            m.size = 0;
        }
        if let Err(e) = self.dir_add_entry(dir_idx, name.as_bytes(), InodeType::File, new_ino as u32)
        {
            self.inodes[new_ino] = InodeMeta::ZERO;
            return Err(e);
        }
        Ok(new_ino as InodeId)
    }

    fn mkdir(
        &mut self,
        dir: InodeId,
        name: FileName<'_>,
        mode: u32,
    ) -> Result<InodeId, VfsError> {
        let dir_idx = self.check_dir(dir)?;
        let dm = &self.inodes[dir_idx];
        if self.dir_lookup(dm, name.as_bytes()).is_ok() {
            return Err(VfsError::AlreadyExists);
        }
        let new_ino = self.alloc_inode()?;
        let new_page = match self.alloc_page() {
            Ok(p) => p,
            Err(e) => {
                self.inodes[new_ino] = InodeMeta::ZERO;
                return Err(e);
            }
        };
        {
            let m = &mut self.inodes[new_ino];
            m.active = true;
            m.kind = InodeType::Directory;
            m.mode = S_IFDIR | (mode & 0o7777);
            m.nlink = 2;
            m.size = 2; // "." and ".."
            m.direct[0] = new_page;
        }
        // Write "." and ".."
        let page = self.page_mut(new_page);
        Self::write_dir_entry_raw(page, 0, b".", InodeType::Directory, new_ino as u32);
        Self::write_dir_entry_raw(page, 1, b"..", InodeType::Directory, dir_idx as u32);

        if let Err(e) = self.dir_add_entry(
            dir_idx,
            name.as_bytes(),
            InodeType::Directory,
            new_ino as u32,
        ) {
            self.free_inode(new_ino);
            return Err(e);
        }
        // Increment parent nlink for ".." in new dir.
        self.inodes[dir_idx].nlink += 1;
        Ok(new_ino as InodeId)
    }

    fn unlink(&mut self, dir: InodeId, name: FileName<'_>) -> Result<(), VfsError> {
        let dir_idx = self.check_dir(dir)?;
        let dm = &self.inodes[dir_idx];
        let (entry_idx, target_ino) = self.dir_lookup(dm, name.as_bytes())?;
        let target = target_ino as usize;

        if self.inodes[target].kind == InodeType::Directory {
            return Err(VfsError::IsADirectory);
        }

        self.dir_remove_entry(dir_idx, entry_idx);
        self.inodes[target].nlink = self.inodes[target].nlink.saturating_sub(1);
        if self.inodes[target].nlink == 0 {
            self.free_inode(target);
        }
        Ok(())
    }

    fn rmdir(&mut self, dir: InodeId, name: FileName<'_>) -> Result<(), VfsError> {
        let dir_idx = self.check_dir(dir)?;
        let dm = &self.inodes[dir_idx];
        let (entry_idx, target_ino) = self.dir_lookup(dm, name.as_bytes())?;
        let target = target_ino as usize;

        if self.inodes[target].kind != InodeType::Directory {
            return Err(VfsError::NotADirectory);
        }
        if self.inodes[target].size > 2 {
            return Err(VfsError::DirectoryNotEmpty);
        }

        self.dir_remove_entry(dir_idx, entry_idx);
        self.inodes[dir_idx].nlink = self.inodes[dir_idx].nlink.saturating_sub(1);
        self.free_inode(target);
        Ok(())
    }

    fn link(
        &mut self,
        dir: InodeId,
        name: FileName<'_>,
        target: InodeId,
    ) -> Result<(), VfsError> {
        let dir_idx = self.check_dir(dir)?;
        let target_idx = target as usize;
        if target_idx >= MAX_INODES || !self.inodes[target_idx].active {
            return Err(VfsError::NotFound);
        }
        if self.inodes[target_idx].kind == InodeType::Directory {
            return Err(VfsError::IsADirectory);
        }
        let dm = &self.inodes[dir_idx];
        if self.dir_lookup(dm, name.as_bytes()).is_ok() {
            return Err(VfsError::AlreadyExists);
        }
        self.dir_add_entry(
            dir_idx,
            name.as_bytes(),
            self.inodes[target_idx].kind,
            target_idx as u32,
        )?;
        self.inodes[target_idx].nlink += 1;
        Ok(())
    }

    fn symlink(
        &mut self,
        dir: InodeId,
        name: FileName<'_>,
        target: &[u8],
    ) -> Result<InodeId, VfsError> {
        let dir_idx = self.check_dir(dir)?;
        let dm = &self.inodes[dir_idx];
        if self.dir_lookup(dm, name.as_bytes()).is_ok() {
            return Err(VfsError::AlreadyExists);
        }
        if target.len() > PAGE_SIZE {
            return Err(VfsError::NameTooLong);
        }
        let new_ino = self.alloc_inode()?;
        let new_page = match self.alloc_page() {
            Ok(p) => p,
            Err(e) => {
                self.inodes[new_ino] = InodeMeta::ZERO;
                return Err(e);
            }
        };
        {
            let m = &mut self.inodes[new_ino];
            m.active = true;
            m.kind = InodeType::Symlink;
            m.mode = S_IFLNK | 0o777;
            m.nlink = 1;
            m.size = target.len() as u64;
            m.direct[0] = new_page;
        }
        let page = self.page_mut(new_page);
        page[..target.len()].copy_from_slice(target);

        if let Err(e) = self.dir_add_entry(
            dir_idx,
            name.as_bytes(),
            InodeType::Symlink,
            new_ino as u32,
        ) {
            self.free_inode(new_ino);
            return Err(e);
        }
        Ok(new_ino as InodeId)
    }

    fn readlink(&self, ino: InodeId, buf: &mut [u8]) -> Result<usize, VfsError> {
        let m = self.meta(ino)?;
        if m.kind != InodeType::Symlink {
            return Err(VfsError::InvalidPath);
        }
        let page_addr = self.get_data_page(m, 0);
        if page_addr == NO_PAGE {
            return Ok(0);
        }
        let page = self.page_ref(page_addr);
        let len = (m.size as usize).min(buf.len());
        buf[..len].copy_from_slice(&page[..len]);
        Ok(len)
    }

    fn readdir(
        &self,
        dir: InodeId,
        offset: usize,
        buf: &mut DirEntry,
    ) -> Result<bool, VfsError> {
        let dir_idx = self.check_dir(dir)?;
        let dm = &self.inodes[dir_idx];
        let count = dm.size as usize;
        if offset >= count {
            return Ok(false);
        }
        let (page_idx, slot) = Self::dir_entry_location(offset);
        let page_addr = self.get_data_page(dm, page_idx);
        if page_addr == NO_PAGE {
            return Ok(false);
        }
        let page = self.page_ref(page_addr);
        let (nlen, kind_byte, ino) = Self::read_dir_entry_raw(page, slot);
        let name_bytes = Self::dir_entry_name(page, slot, nlen);

        buf.ino = ino as InodeId;
        // Use the cached kind from the dir entry if the inode is valid,
        // otherwise fall back to the cached kind byte.
        let ino_idx = ino as usize;
        if ino_idx < MAX_INODES && self.inodes[ino_idx].active {
            buf.kind = self.inodes[ino_idx].kind;
        } else {
            // Safety: InodeType repr(u8), transmute from stored byte.
            buf.kind = unsafe { core::mem::transmute::<u8, InodeType>(kind_byte) };
        }
        buf.name_len = nlen;
        buf._pad = [0; 6];
        buf.name = [0; 256];
        buf.name[..nlen as usize].copy_from_slice(name_bytes);
        Ok(true)
    }

    fn rename(
        &mut self,
        old_dir: InodeId,
        old_name: FileName<'_>,
        new_dir: InodeId,
        new_name: FileName<'_>,
    ) -> Result<(), VfsError> {
        let old_dir_idx = self.check_dir(old_dir)?;
        let new_dir_idx = self.check_dir(new_dir)?;

        // Find the source entry.
        let dm = &self.inodes[old_dir_idx];
        let (_old_entry_idx, target_ino) = self.dir_lookup(dm, old_name.as_bytes())?;
        let target_kind = self.inodes[target_ino as usize].kind;

        // Check if destination already exists and remove it.
        let new_dm = &self.inodes[new_dir_idx];
        if let Ok((existing_entry_idx, existing_ino)) =
            self.dir_lookup(new_dm, new_name.as_bytes())
        {
            let ei = existing_ino as usize;
            if self.inodes[ei].kind == InodeType::Directory {
                if self.inodes[ei].size > 2 {
                    return Err(VfsError::DirectoryNotEmpty);
                }
                self.inodes[new_dir_idx].nlink =
                    self.inodes[new_dir_idx].nlink.saturating_sub(1);
            }
            self.dir_remove_entry(new_dir_idx, existing_entry_idx);
            self.inodes[ei].nlink = self.inodes[ei].nlink.saturating_sub(1);
            if self.inodes[ei].nlink == 0 {
                self.free_inode(ei);
            }
        }

        // Remove from old dir.
        // Re-lookup because indices may have shifted if old_dir == new_dir.
        let dm = &self.inodes[old_dir_idx];
        let (old_entry_idx, _) = self.dir_lookup(dm, old_name.as_bytes())?;
        self.dir_remove_entry(old_dir_idx, old_entry_idx);

        // Add to new dir.
        self.dir_add_entry(new_dir_idx, new_name.as_bytes(), target_kind, target_ino)?;

        // If we moved a directory, update ".." in the moved dir.
        if self.inodes[target_ino as usize].kind == InodeType::Directory
            && old_dir_idx != new_dir_idx
        {
            let moved_page_addr = self.get_data_page(&self.inodes[target_ino as usize], 0);
            if moved_page_addr != NO_PAGE {
                let page = self.page_mut(moved_page_addr);
                Self::write_dir_entry_raw(
                    page,
                    1,
                    b"..",
                    InodeType::Directory,
                    new_dir_idx as u32,
                );
            }
            self.inodes[old_dir_idx].nlink =
                self.inodes[old_dir_idx].nlink.saturating_sub(1);
            self.inodes[new_dir_idx].nlink += 1;
        }

        Ok(())
    }

    fn chmod(&mut self, ino: InodeId, mode: u32) -> Result<(), VfsError> {
        let m = self.meta_mut(ino)?;
        m.mode = (m.mode & S_IFMT) | (mode & 0o7777);
        Ok(())
    }

    fn chown(&mut self, ino: InodeId, uid: u32, gid: u32) -> Result<(), VfsError> {
        let m = self.meta_mut(ino)?;
        m.uid = uid;
        m.gid = gid;
        Ok(())
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use super::*;
    use crate::{DirEntry, FileName, FileSystem, InodeStat, InodeType, VfsError, NAME_MAX};

    // ── Mock frame allocator ─────────────────────────────────────────

    /// Simple mock allocator that hands out heap-backed pages.
    /// Each "page" is a Box<[u8; 4096]> whose pointer becomes the PhysAddr.
    struct MockAllocator {
        /// All allocated page pointers (for cleanup / tracking).
        pages: Vec<*mut [u8; PAGE_SIZE]>,
    }

    impl MockAllocator {
        fn new() -> Self {
            Self { pages: Vec::new() }
        }
    }

    impl FrameAllocator for MockAllocator {
        fn alloc(&mut self, _size: PageSize) -> Result<PhysAddr, rux_mm::MemoryError> {
            let page = Box::new([0u8; PAGE_SIZE]);
            let ptr = Box::into_raw(page);
            self.pages.push(ptr);
            Ok(PhysAddr::new(ptr as usize))
        }

        fn dealloc(&mut self, addr: PhysAddr, _size: PageSize) {
            let ptr = addr.as_usize() as *mut [u8; PAGE_SIZE];
            // Remove from tracking and free.
            if let Some(pos) = self.pages.iter().position(|&p| p == ptr) {
                self.pages.swap_remove(pos);
            }
            unsafe { drop(Box::from_raw(ptr)); }
        }

        fn available_frames(&self, _size: PageSize) -> usize {
            usize::MAX // unlimited for tests
        }
    }

    impl Drop for MockAllocator {
        fn drop(&mut self) {
            for &ptr in &self.pages {
                unsafe { drop(Box::from_raw(ptr)); }
            }
        }
    }

    fn new_fs() -> (Box<MockAllocator>, Box<RamFs>) {
        let mut alloc = Box::new(MockAllocator::new());
        let alloc_ptr: *mut dyn FrameAllocator = &mut *alloc as &mut dyn FrameAllocator;
        let fs = unsafe { RamFs::new_boxed(alloc_ptr) };
        (alloc, fs)
    }

    fn zeroed_stat() -> InodeStat {
        InodeStat {
            ino: 0, mode: 0, nlink: 0, uid: 0, gid: 0,
            size: 0, blocks: 0, blksize: 0, _pad0: 0,
            atime: 0, mtime: 0, ctime: 0, dev: 0, rdev: 0,
        }
    }

    fn zeroed_dirent() -> DirEntry {
        DirEntry {
            ino: 0, kind: InodeType::File, name_len: 0,
            _pad: [0; 6], name: [0; 256],
        }
    }

    #[test]
    fn root_inode_is_zero() {
        let (_alloc, fs) = new_fs();
        assert_eq!(fs.root_inode(), 0);
    }

    #[test]
    fn stat_root() {
        let (_alloc, fs) = new_fs();
        let mut st = zeroed_stat();
        fs.stat(0, &mut st).unwrap();
        assert_eq!(st.ino, 0);
        assert_eq!(st.nlink, 2);
        assert!(st.mode & S_IFDIR != 0);
    }

    #[test]
    fn create_and_stat_file() {
        let (_alloc, mut fs) = new_fs();
        let name = FileName::new(b"hello.txt").unwrap();
        let ino = fs.create(0, name, 0o644).unwrap();
        assert!(ino > 0);
        let mut st = zeroed_stat();
        fs.stat(ino, &mut st).unwrap();
        assert_eq!(st.nlink, 1);
        assert!(st.mode & S_IFREG != 0);
    }

    #[test]
    fn create_duplicate_fails() {
        let (_alloc, mut fs) = new_fs();
        let name = FileName::new(b"dup").unwrap();
        fs.create(0, name, 0o644).unwrap();
        assert_eq!(fs.create(0, name, 0o644), Err(VfsError::AlreadyExists));
    }

    #[test]
    fn write_and_read() {
        let (_alloc, mut fs) = new_fs();
        let name = FileName::new(b"data").unwrap();
        let ino = fs.create(0, name, 0o644).unwrap();
        let data = b"Hello, RamFS!";
        let written = fs.write(ino, 0, data).unwrap();
        assert_eq!(written, data.len());
        let mut buf = [0u8; 64];
        let read = fs.read(ino, 0, &mut buf).unwrap();
        assert_eq!(read, data.len());
        assert_eq!(&buf[..read], data);
    }

    #[test]
    fn write_at_offset() {
        let (_alloc, mut fs) = new_fs();
        let name = FileName::new(b"off").unwrap();
        let ino = fs.create(0, name, 0o644).unwrap();
        fs.write(ino, 0, b"AAAA").unwrap();
        fs.write(ino, 2, b"BB").unwrap();
        let mut buf = [0u8; 4];
        fs.read(ino, 0, &mut buf).unwrap();
        assert_eq!(&buf, b"AABB");
    }

    #[test]
    fn read_past_eof_returns_zero() {
        let (_alloc, mut fs) = new_fs();
        let name = FileName::new(b"small").unwrap();
        let ino = fs.create(0, name, 0o644).unwrap();
        fs.write(ino, 0, b"hi").unwrap();
        let mut buf = [0u8; 4];
        let n = fs.read(ino, 100, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn truncate_file() {
        let (_alloc, mut fs) = new_fs();
        let name = FileName::new(b"trunc").unwrap();
        let ino = fs.create(0, name, 0o644).unwrap();
        fs.write(ino, 0, b"data").unwrap();
        fs.truncate(ino, 0).unwrap();
        let mut st = zeroed_stat();
        fs.stat(ino, &mut st).unwrap();
        assert_eq!(st.size, 0);
    }

    #[test]
    fn lookup_existing() {
        let (_alloc, mut fs) = new_fs();
        let name = FileName::new(b"found").unwrap();
        let ino = fs.create(0, name, 0o644).unwrap();
        assert_eq!(fs.lookup(0, name).unwrap(), ino);
    }

    #[test]
    fn lookup_missing() {
        let (_alloc, fs) = new_fs();
        let name = FileName::new(b"nope").unwrap();
        assert_eq!(fs.lookup(0, name), Err(VfsError::NotFound));
    }

    #[test]
    fn mkdir_and_lookup() {
        let (_alloc, mut fs) = new_fs();
        let name = FileName::new(b"subdir").unwrap();
        let ino = fs.mkdir(0, name, 0o755).unwrap();
        assert_eq!(fs.lookup(0, name).unwrap(), ino);
        let mut st = zeroed_stat();
        fs.stat(ino, &mut st).unwrap();
        assert!(st.mode & S_IFDIR != 0);
        assert_eq!(st.nlink, 2);
    }

    #[test]
    fn unlink_file() {
        let (_alloc, mut fs) = new_fs();
        let name = FileName::new(b"gone").unwrap();
        fs.create(0, name, 0o644).unwrap();
        fs.unlink(0, name).unwrap();
        assert_eq!(fs.lookup(0, name), Err(VfsError::NotFound));
    }

    #[test]
    fn unlink_directory_fails() {
        let (_alloc, mut fs) = new_fs();
        let name = FileName::new(b"dir").unwrap();
        fs.mkdir(0, name, 0o755).unwrap();
        assert_eq!(fs.unlink(0, name), Err(VfsError::IsADirectory));
    }

    #[test]
    fn rmdir_empty() {
        let (_alloc, mut fs) = new_fs();
        let name = FileName::new(b"empty").unwrap();
        fs.mkdir(0, name, 0o755).unwrap();
        fs.rmdir(0, name).unwrap();
        assert_eq!(fs.lookup(0, name), Err(VfsError::NotFound));
    }

    #[test]
    fn rmdir_notempty_fails() {
        let (_alloc, mut fs) = new_fs();
        let dname = FileName::new(b"dir2").unwrap();
        let dir_ino = fs.mkdir(0, dname, 0o755).unwrap();
        let fname = FileName::new(b"child").unwrap();
        fs.create(dir_ino, fname, 0o644).unwrap();
        assert_eq!(fs.rmdir(0, dname), Err(VfsError::DirectoryNotEmpty));
    }

    #[test]
    fn hard_link() {
        let (_alloc, mut fs) = new_fs();
        let name = FileName::new(b"orig").unwrap();
        let ino = fs.create(0, name, 0o644).unwrap();
        let link_name = FileName::new(b"link").unwrap();
        fs.link(0, link_name, ino).unwrap();
        assert_eq!(fs.lookup(0, link_name).unwrap(), ino);
        let mut st = zeroed_stat();
        fs.stat(ino, &mut st).unwrap();
        assert_eq!(st.nlink, 2);
    }

    #[test]
    fn symlink_and_readlink() {
        let (_alloc, mut fs) = new_fs();
        let name = FileName::new(b"sym").unwrap();
        let target = b"/etc/passwd";
        let ino = fs.symlink(0, name, target).unwrap();
        let mut buf = [0u8; 64];
        let n = fs.readlink(ino, &mut buf).unwrap();
        assert_eq!(&buf[..n], target);
    }

    #[test]
    fn readdir_root() {
        let (_alloc, mut fs) = new_fs();
        let name = FileName::new(b"file1").unwrap();
        fs.create(0, name, 0o644).unwrap();
        let mut de = zeroed_dirent();
        // ".", "..", "file1" => 3 entries
        assert!(fs.readdir(0, 0, &mut de).unwrap()); // "."
        assert!(fs.readdir(0, 1, &mut de).unwrap()); // ".."
        assert!(fs.readdir(0, 2, &mut de).unwrap()); // "file1"
        assert!(!fs.readdir(0, 3, &mut de).unwrap()); // end
    }

    #[test]
    fn rename_file() {
        let (_alloc, mut fs) = new_fs();
        let old = FileName::new(b"old").unwrap();
        let new = FileName::new(b"new").unwrap();
        let ino = fs.create(0, old, 0o644).unwrap();
        fs.write(ino, 0, b"content").unwrap();
        fs.rename(0, old, 0, new).unwrap();
        assert_eq!(fs.lookup(0, old), Err(VfsError::NotFound));
        let ino2 = fs.lookup(0, new).unwrap();
        assert_eq!(ino2, ino);
    }

    #[test]
    fn chmod_file() {
        let (_alloc, mut fs) = new_fs();
        let name = FileName::new(b"ch").unwrap();
        let ino = fs.create(0, name, 0o644).unwrap();
        fs.chmod(ino, 0o755).unwrap();
        let mut st = zeroed_stat();
        fs.stat(ino, &mut st).unwrap();
        assert_eq!(st.mode & 0o7777, 0o755);
        assert!(st.mode & S_IFREG != 0);
    }

    #[test]
    fn chown_file() {
        let (_alloc, mut fs) = new_fs();
        let name = FileName::new(b"own").unwrap();
        let ino = fs.create(0, name, 0o644).unwrap();
        fs.chown(ino, 1000, 1000).unwrap();
        let mut st = zeroed_stat();
        fs.stat(ino, &mut st).unwrap();
        assert_eq!(st.uid, 1000);
        assert_eq!(st.gid, 1000);
    }

    #[test]
    fn stat_nonexistent_fails() {
        let (_alloc, fs) = new_fs();
        let mut st = zeroed_stat();
        assert_eq!(fs.stat(999, &mut st), Err(VfsError::NotFound));
    }

    #[test]
    fn write_full_page() {
        let (_alloc, mut fs) = new_fs();
        let name = FileName::new(b"big").unwrap();
        let ino = fs.create(0, name, 0o644).unwrap();
        let data = [0xABu8; PAGE_SIZE];
        let n = fs.write(ino, 0, &data).unwrap();
        assert_eq!(n, PAGE_SIZE);
        let mut buf = [0u8; PAGE_SIZE];
        let r = fs.read(ino, 0, &mut buf).unwrap();
        assert_eq!(r, PAGE_SIZE);
        assert_eq!(buf[0], 0xAB);
        assert_eq!(buf[PAGE_SIZE - 1], 0xAB);
    }

    #[test]
    fn read_directory_fails() {
        let (_alloc, fs) = new_fs();
        let mut buf = [0u8; 64];
        assert_eq!(fs.read(0, 0, &mut buf), Err(VfsError::IsADirectory));
    }

    #[test]
    fn rename_across_dirs() {
        let (_alloc, mut fs) = new_fs();
        let d1 = FileName::new(b"d1").unwrap();
        let d2 = FileName::new(b"d2").unwrap();
        let d1_ino = fs.mkdir(0, d1, 0o755).unwrap();
        let d2_ino = fs.mkdir(0, d2, 0o755).unwrap();
        let fname = FileName::new(b"file").unwrap();
        let ino = fs.create(d1_ino, fname, 0o644).unwrap();
        let newname = FileName::new(b"moved").unwrap();
        fs.rename(d1_ino, fname, d2_ino, newname).unwrap();
        assert_eq!(fs.lookup(d1_ino, fname), Err(VfsError::NotFound));
        assert_eq!(fs.lookup(d2_ino, newname).unwrap(), ino);
    }

    // ── New tests: multi-page files ──────────────────────────────────

    #[test]
    fn write_multi_page_file() {
        let (_alloc, mut fs) = new_fs();
        let name = FileName::new(b"multipage").unwrap();
        let ino = fs.create(0, name, 0o644).unwrap();

        // Write 3 pages worth of data (12288 bytes).
        let data = [0xCDu8; PAGE_SIZE * 3];
        let n = fs.write(ino, 0, &data).unwrap();
        assert_eq!(n, PAGE_SIZE * 3);

        // Read it back.
        let mut buf = [0u8; PAGE_SIZE * 3];
        let r = fs.read(ino, 0, &mut buf).unwrap();
        assert_eq!(r, PAGE_SIZE * 3);
        assert!(buf.iter().all(|&b| b == 0xCD));

        // Verify stat shows correct size.
        let mut st = zeroed_stat();
        fs.stat(ino, &mut st).unwrap();
        assert_eq!(st.size, (PAGE_SIZE * 3) as u64);
    }

    #[test]
    fn write_spanning_page_boundary() {
        let (_alloc, mut fs) = new_fs();
        let name = FileName::new(b"spanning").unwrap();
        let ino = fs.create(0, name, 0o644).unwrap();

        // Write starting in the middle of page 0, spanning into page 1.
        let offset = PAGE_SIZE as u64 - 10;
        let data = [0xEEu8; 20]; // 10 bytes in page 0, 10 bytes in page 1
        let n = fs.write(ino, offset, &data).unwrap();
        assert_eq!(n, 20);

        let mut buf = [0u8; 20];
        let r = fs.read(ino, offset, &mut buf).unwrap();
        assert_eq!(r, 20);
        assert!(buf.iter().all(|&b| b == 0xEE));
    }

    #[test]
    fn write_all_direct_pages() {
        let (_alloc, mut fs) = new_fs();
        let name = FileName::new(b"alldir").unwrap();
        let ino = fs.create(0, name, 0o644).unwrap();

        // Fill all 12 direct pages (48 KiB).
        let data = [0xAAu8; DIRECT_PAGES * PAGE_SIZE];
        let n = fs.write(ino, 0, &data).unwrap();
        assert_eq!(n, DIRECT_PAGES * PAGE_SIZE);

        // Read back the last page.
        let mut buf = [0u8; PAGE_SIZE];
        let r = fs.read(ino, ((DIRECT_PAGES - 1) * PAGE_SIZE) as u64, &mut buf).unwrap();
        assert_eq!(r, PAGE_SIZE);
        assert!(buf.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn write_with_indirect_pages() {
        let (_alloc, mut fs) = new_fs();
        let name = FileName::new(b"indirect").unwrap();
        let ino = fs.create(0, name, 0o644).unwrap();

        // Write into the 13th page (first indirect).
        let offset = (DIRECT_PAGES * PAGE_SIZE) as u64;
        let data = [0xBBu8; PAGE_SIZE];
        let n = fs.write(ino, offset, &data).unwrap();
        assert_eq!(n, PAGE_SIZE);

        let mut buf = [0u8; PAGE_SIZE];
        let r = fs.read(ino, offset, &mut buf).unwrap();
        assert_eq!(r, PAGE_SIZE);
        assert!(buf.iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn truncate_multi_page_file() {
        let (_alloc, mut fs) = new_fs();
        let name = FileName::new(b"trunc_mp").unwrap();
        let ino = fs.create(0, name, 0o644).unwrap();

        let data = [0xFFu8; PAGE_SIZE * 5];
        fs.write(ino, 0, &data).unwrap();
        fs.truncate(ino, PAGE_SIZE as u64).unwrap();

        let mut st = zeroed_stat();
        fs.stat(ino, &mut st).unwrap();
        assert_eq!(st.size, PAGE_SIZE as u64);

        // Reading beyond truncated size returns 0 bytes.
        let mut buf = [0u8; 1];
        let r = fs.read(ino, PAGE_SIZE as u64, &mut buf).unwrap();
        assert_eq!(r, 0);
    }

    // ── New tests: large directories ─────────────────────────────────

    #[test]
    fn large_directory_more_than_one_page() {
        let (_alloc, mut fs) = new_fs();
        let dir_name = FileName::new(b"bigdir").unwrap();
        let dir_ino = fs.mkdir(0, dir_name, 0o755).unwrap();

        // Create 20 entries (more than 15 per page, so needs 2 data pages).
        // Dir already has "." and ".." = 2 entries.
        let count = 20usize;
        for i in 0..count {
            let mut name_buf = [0u8; 8];
            let n = fmt_u32(i as u32, &mut name_buf);
            let name = FileName::new(&name_buf[..n]).unwrap();
            fs.create(dir_ino, name, 0o644).unwrap();
        }

        // Verify all entries can be found.
        for i in 0..count {
            let mut name_buf = [0u8; 8];
            let n = fmt_u32(i as u32, &mut name_buf);
            let name = FileName::new(&name_buf[..n]).unwrap();
            assert!(fs.lookup(dir_ino, name).is_ok(), "missing entry {}", i);
        }

        // readdir should return all entries (2 + count).
        let total = 2 + count;
        let mut de = zeroed_dirent();
        for off in 0..total {
            assert!(fs.readdir(dir_ino, off, &mut de).unwrap(), "readdir failed at {}", off);
        }
        assert!(!fs.readdir(dir_ino, total, &mut de).unwrap());
    }

    #[test]
    fn large_directory_unlink_compaction() {
        let (_alloc, mut fs) = new_fs();
        let dir_name = FileName::new(b"unlinkdir").unwrap();
        let dir_ino = fs.mkdir(0, dir_name, 0o755).unwrap();

        // Create 20 files.
        for i in 0..20u32 {
            let mut name_buf = [0u8; 8];
            let n = fmt_u32(i, &mut name_buf);
            let name = FileName::new(&name_buf[..n]).unwrap();
            fs.create(dir_ino, name, 0o644).unwrap();
        }

        // Unlink half of them.
        for i in (0..20u32).step_by(2) {
            let mut name_buf = [0u8; 8];
            let n = fmt_u32(i, &mut name_buf);
            let name = FileName::new(&name_buf[..n]).unwrap();
            fs.unlink(dir_ino, name).unwrap();
        }

        // The remaining 10 odd-numbered entries should still be findable.
        for i in (1..20u32).step_by(2) {
            let mut name_buf = [0u8; 8];
            let n = fmt_u32(i, &mut name_buf);
            let name = FileName::new(&name_buf[..n]).unwrap();
            assert!(fs.lookup(dir_ino, name).is_ok(), "missing entry {}", i);
        }
    }

    // ── New test: NAME_MAX filenames ─────────────────────────────────

    #[test]
    fn name_max_filename() {
        let (_alloc, mut fs) = new_fs();
        let long_name = [b'x'; NAME_MAX];
        let name = FileName::new(&long_name).unwrap();
        let ino = fs.create(0, name, 0o644).unwrap();
        assert_eq!(fs.lookup(0, name).unwrap(), ino);
    }

    // ── Helper ───────────────────────────────────────────────────────

    fn fmt_u32(mut v: u32, buf: &mut [u8; 8]) -> usize {
        // Prefix with 'f' to avoid purely numeric names starting with 0.
        buf[0] = b'f';
        if v == 0 {
            buf[1] = b'0';
            return 2;
        }
        let mut digits = [0u8; 6];
        let mut i = 6;
        while v > 0 {
            i -= 1;
            digits[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
        let len = 6 - i;
        buf[1..1 + len].copy_from_slice(&digits[i..6]);
        1 + len
    }
}
