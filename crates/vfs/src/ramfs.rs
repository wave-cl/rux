#![allow(clippy::cast_possible_truncation)]

#[cfg(any(test, feature = "alloc"))]
extern crate alloc;

use crate::{
    DirEntry, FileSystem, FileName, InodeId, InodeStat, InodeType, VfsError,
    S_IFDIR, S_IFLNK, S_IFREG, S_IFMT,
};

// ── Constants ──────────────────────────────────────────────────────────

pub const MAX_INODES: usize = 256;
pub const MAX_PAGES: usize = 256;
pub const PAGE_SIZE: usize = 4096;

/// Sentinel: inode has no data page allocated.
const NO_PAGE: u16 = 0xFFFF;

/// Packed directory entry stored inside a data page.
/// 32 bytes each, 128 entries per 4096-byte page.
const DIR_ENTRY_SIZE: usize = 32;
const DIR_ENTRY_NAME_CAP: usize = 28;
const DIR_ENTRIES_PER_PAGE: usize = PAGE_SIZE / DIR_ENTRY_SIZE;

// ── Inode metadata ─────────────────────────────────────────────────────

#[derive(Clone, Copy)]
#[repr(C)]
pub struct RamInodeMeta {
    pub active: bool,
    pub kind: InodeType,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub page_idx: u16,
    pub _pad: [u8; 6],
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
}

impl RamInodeMeta {
    const ZERO: Self = Self {
        active: false,
        kind: InodeType::File,
        mode: 0,
        nlink: 0,
        uid: 0,
        gid: 0,
        size: 0,
        page_idx: NO_PAGE,
        _pad: [0; 6],
        atime: 0,
        mtime: 0,
        ctime: 0,
    };
}

// ── RamFs ──────────────────────────────────────────────────────────────

/// In-memory RAM filesystem. ~1 MB total (pages dominate).
///
/// For testing: heap-allocate via `Box::new(RamFs::new())`.
/// In the kernel: placed at a known physical address.
#[repr(C)]
pub struct RamFs {
    inodes: [RamInodeMeta; MAX_INODES],
    pages: [[u8; PAGE_SIZE]; MAX_PAGES],
    page_used: [bool; MAX_PAGES],
    next_inode: usize,
}

impl RamFs {
    /// Initialise an already-allocated RamFs in place (root directory at inode 0).
    ///
    /// # Safety
    /// The memory pointed to by `this` must be valid, aligned, and zero-initialised.
    #[cfg(any(test, feature = "alloc"))]
    unsafe fn init_in_place(this: &mut Self) {
        this.next_inode = 1;
        // All inodes are zero-initialised (active=false) — good.
        // Root inode (0).
        let root = &mut this.inodes[0];
        root.active = true;
        root.kind = InodeType::Directory;
        root.mode = S_IFDIR | 0o755;
        root.nlink = 2;
        root.page_idx = 0;
        this.page_used[0] = true;

        Self::write_dir_entry_raw(&mut this.pages[0], 0, b".", 0);
        Self::write_dir_entry_raw(&mut this.pages[0], 1, b"..", 0);
        this.inodes[0].size = 2;
    }

    /// Create a new RamFs with an initialised root directory (inode 0).
    ///
    /// WARNING: This struct is ~1 MB. On targets with small stacks this will
    /// overflow. Use [`RamFs::new_boxed`] in hosted / test environments.
    pub fn new() -> Self {
        let mut fs = Self {
            inodes: [RamInodeMeta::ZERO; MAX_INODES],
            pages: [[0u8; PAGE_SIZE]; MAX_PAGES],
            page_used: [false; MAX_PAGES],
            next_inode: 1,
        };

        // Root inode (0) — directory with "." and ".." pointing to itself.
        let root = &mut fs.inodes[0];
        root.active = true;
        root.kind = InodeType::Directory;
        root.mode = S_IFDIR | 0o755;
        root.nlink = 2; // self (".") + parent ("..") for root both point here
        root.page_idx = 0;
        fs.page_used[0] = true;

        // Write "." and ".." entries.
        Self::write_dir_entry_raw(&mut fs.pages[0], 0, b".", 0);
        Self::write_dir_entry_raw(&mut fs.pages[0], 1, b"..", 0);
        root.size = 2;

        fs
    }

    /// Allocate a RamFs directly on the heap, avoiding stack overflow.
    ///
    /// Uses `alloc_zeroed` + in-place init so the ~1 MB struct never touches
    /// the stack. Requires `alloc` crate.
    #[cfg(any(test, feature = "alloc"))]
    pub fn new_boxed() -> alloc::boxed::Box<Self> {
        use core::alloc::Layout;
        unsafe {
            let layout = Layout::new::<Self>();
            let ptr = alloc::alloc::alloc_zeroed(layout) as *mut Self;
            if ptr.is_null() {
                alloc::alloc::handle_alloc_error(layout);
            }
            Self::init_in_place(&mut *ptr);
            alloc::boxed::Box::from_raw(ptr)
        }
    }

    // ── Internal helpers ───────────────────────────────────────────────

    #[inline(always)]
    fn meta(&self, ino: InodeId) -> Result<&RamInodeMeta, VfsError> {
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
    fn meta_mut(&mut self, ino: InodeId) -> Result<&mut RamInodeMeta, VfsError> {
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
        let start = self.next_inode;
        let mut idx = start;
        loop {
            if idx >= MAX_INODES {
                idx = 1; // skip root (0)
            }
            if !self.inodes[idx].active {
                self.next_inode = idx + 1;
                return Ok(idx);
            }
            idx += 1;
            if idx == start {
                return Err(VfsError::NoSpace);
            }
        }
    }

    fn alloc_page(&mut self) -> Result<u16, VfsError> {
        for i in 0..MAX_PAGES {
            if !self.page_used[i] {
                self.page_used[i] = true;
                self.pages[i] = [0u8; PAGE_SIZE];
                return Ok(i as u16);
            }
        }
        Err(VfsError::NoSpace)
    }

    fn free_page(&mut self, idx: u16) {
        if (idx as usize) < MAX_PAGES {
            self.page_used[idx as usize] = false;
        }
    }

    fn free_inode(&mut self, idx: usize) {
        let m = &mut self.inodes[idx];
        if m.page_idx != NO_PAGE {
            self.page_used[m.page_idx as usize] = false;
        }
        *m = RamInodeMeta::ZERO;
    }

    /// Write a packed dir entry into a page at the given slot index.
    fn write_dir_entry_raw(page: &mut [u8; PAGE_SIZE], slot: usize, name: &[u8], ino: u16) {
        let off = slot * DIR_ENTRY_SIZE;
        let len = name.len().min(DIR_ENTRY_NAME_CAP);
        page[off] = len as u8;
        page[off + 1] = 0; // pad
        page[off + 2] = (ino & 0xFF) as u8;
        page[off + 3] = (ino >> 8) as u8;
        page[off + 4..off + 4 + len].copy_from_slice(&name[..len]);
        // Zero the rest of the name area.
        for b in &mut page[off + 4 + len..off + DIR_ENTRY_SIZE] {
            *b = 0;
        }
    }

    /// Read a packed dir entry from a page. Returns (name_len, inode_idx).
    #[inline(always)]
    fn read_dir_entry_raw(page: &[u8; PAGE_SIZE], slot: usize) -> (u8, u16) {
        let off = slot * DIR_ENTRY_SIZE;
        let nlen = page[off];
        let ino = page[off + 2] as u16 | ((page[off + 3] as u16) << 8);
        (nlen, ino)
    }

    /// Get the name bytes of a dir entry at `slot`.
    #[inline(always)]
    fn dir_entry_name(page: &[u8; PAGE_SIZE], slot: usize, nlen: u8) -> &[u8] {
        let off = slot * DIR_ENTRY_SIZE + 4;
        &page[off..off + nlen as usize]
    }

    /// Scan directory page for a name. Returns slot index if found.
    fn dir_lookup_slot(
        &self,
        dir_meta: &RamInodeMeta,
        name: &[u8],
    ) -> Result<usize, VfsError> {
        if dir_meta.page_idx == NO_PAGE {
            return Err(VfsError::NotFound);
        }
        let page = &self.pages[dir_meta.page_idx as usize];
        let count = dir_meta.size as usize;
        for slot in 0..count.min(DIR_ENTRIES_PER_PAGE) {
            let (nlen, _ino) = Self::read_dir_entry_raw(page, slot);
            if nlen as usize == name.len() {
                if Self::dir_entry_name(page, slot, nlen) == name {
                    return Ok(slot);
                }
            }
        }
        Err(VfsError::NotFound)
    }

    /// Add a dir entry to a directory. Returns the slot used.
    fn dir_add_entry(
        &mut self,
        dir_ino: usize,
        name: &[u8],
        target_ino: u16,
    ) -> Result<usize, VfsError> {
        if self.inodes[dir_ino].page_idx == NO_PAGE {
            let pg = self.alloc_page()?;
            self.inodes[dir_ino].page_idx = pg;
        }
        let count = self.inodes[dir_ino].size as usize;
        if count >= DIR_ENTRIES_PER_PAGE {
            return Err(VfsError::NoSpace);
        }
        let pg = self.inodes[dir_ino].page_idx as usize;
        Self::write_dir_entry_raw(&mut self.pages[pg], count, name, target_ino);
        self.inodes[dir_ino].size = (count + 1) as u64;
        Ok(count)
    }

    /// Remove a dir entry by slot, compact by moving last entry into the gap.
    fn dir_remove_entry(&mut self, dir_ino: usize, slot: usize) {
        let dir = &mut self.inodes[dir_ino];
        let count = dir.size as usize;
        let pg = dir.page_idx as usize;
        if slot < count - 1 {
            // Move last entry into this slot.
            let last = count - 1;
            let src_off = last * DIR_ENTRY_SIZE;
            let dst_off = slot * DIR_ENTRY_SIZE;
            let mut tmp = [0u8; DIR_ENTRY_SIZE];
            tmp.copy_from_slice(&self.pages[pg][src_off..src_off + DIR_ENTRY_SIZE]);
            self.pages[pg][dst_off..dst_off + DIR_ENTRY_SIZE].copy_from_slice(&tmp);
        }
        dir.size = (count - 1) as u64;
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
        buf.blocks = if m.page_idx != NO_PAGE { (PAGE_SIZE as u64 + 511) / 512 } else { 0 };
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
        if m.page_idx == NO_PAGE || offset >= m.size {
            return Ok(0);
        }
        let page = &self.pages[m.page_idx as usize];
        let start = offset as usize;
        let avail = (m.size as usize).saturating_sub(start);
        let n = buf.len().min(avail);
        buf[..n].copy_from_slice(&page[start..start + n]);
        Ok(n)
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
        if end > PAGE_SIZE {
            return Err(VfsError::NoSpace);
        }
        // Allocate page on first write.
        if self.inodes[idx].page_idx == NO_PAGE {
            let pg = self.alloc_page()?;
            self.inodes[idx].page_idx = pg;
        }
        let pg = self.inodes[idx].page_idx as usize;
        self.pages[pg][offset as usize..end].copy_from_slice(buf);
        if end as u64 > self.inodes[idx].size {
            self.inodes[idx].size = end as u64;
        }
        Ok(buf.len())
    }

    fn truncate(&mut self, ino: InodeId, size: u64) -> Result<(), VfsError> {
        let m = self.meta_mut(ino)?;
        if m.kind == InodeType::Directory {
            return Err(VfsError::IsADirectory);
        }
        if size == 0 && m.page_idx != NO_PAGE {
            let pg = m.page_idx;
            m.page_idx = NO_PAGE;
            self.free_page(pg);
        } else if size > PAGE_SIZE as u64 {
            return Err(VfsError::NoSpace);
        }
        self.inodes[ino as usize].size = size;
        Ok(())
    }

    fn lookup(&self, dir: InodeId, name: FileName<'_>) -> Result<InodeId, VfsError> {
        let dir_idx = self.check_dir(dir)?;
        let dm = &self.inodes[dir_idx];
        let slot = self.dir_lookup_slot(dm, name.as_bytes())?;
        let page = &self.pages[dm.page_idx as usize];
        let (_nlen, ino) = Self::read_dir_entry_raw(page, slot);
        Ok(ino as InodeId)
    }

    fn create(
        &mut self,
        dir: InodeId,
        name: FileName<'_>,
        mode: u32,
    ) -> Result<InodeId, VfsError> {
        let dir_idx = self.check_dir(dir)?;
        // Check for existing entry.
        let dm = &self.inodes[dir_idx];
        if self.dir_lookup_slot(dm, name.as_bytes()).is_ok() {
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
            m.page_idx = NO_PAGE;
        }
        if name.len() > DIR_ENTRY_NAME_CAP {
            self.inodes[new_ino] = RamInodeMeta::ZERO;
            return Err(VfsError::NameTooLong);
        }
        self.dir_add_entry(dir_idx, name.as_bytes(), new_ino as u16)?;
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
        if self.dir_lookup_slot(dm, name.as_bytes()).is_ok() {
            return Err(VfsError::AlreadyExists);
        }
        let new_ino = self.alloc_inode()?;
        let new_page = match self.alloc_page() {
            Ok(p) => p,
            Err(e) => {
                self.inodes[new_ino] = RamInodeMeta::ZERO;
                return Err(e);
            }
        };
        {
            let m = &mut self.inodes[new_ino];
            m.active = true;
            m.kind = InodeType::Directory;
            m.mode = S_IFDIR | (mode & 0o7777);
            m.nlink = 2; // "." + parent's entry
            m.size = 2; // "." and ".."
            m.page_idx = new_page;
        }
        // Write "." and ".."
        Self::write_dir_entry_raw(
            &mut self.pages[new_page as usize],
            0,
            b".",
            new_ino as u16,
        );
        Self::write_dir_entry_raw(
            &mut self.pages[new_page as usize],
            1,
            b"..",
            dir_idx as u16,
        );
        if name.len() > DIR_ENTRY_NAME_CAP {
            self.free_inode(new_ino);
            return Err(VfsError::NameTooLong);
        }
        self.dir_add_entry(dir_idx, name.as_bytes(), new_ino as u16)?;
        // Increment parent nlink for ".." in new dir.
        self.inodes[dir_idx].nlink += 1;
        Ok(new_ino as InodeId)
    }

    fn unlink(&mut self, dir: InodeId, name: FileName<'_>) -> Result<(), VfsError> {
        let dir_idx = self.check_dir(dir)?;
        let dm = &self.inodes[dir_idx];
        let slot = self.dir_lookup_slot(dm, name.as_bytes())?;
        let page = &self.pages[dm.page_idx as usize];
        let (_nlen, target_ino) = Self::read_dir_entry_raw(page, slot);
        let target = target_ino as usize;

        if self.inodes[target].kind == InodeType::Directory {
            return Err(VfsError::IsADirectory);
        }

        self.dir_remove_entry(dir_idx, slot);
        self.inodes[target].nlink = self.inodes[target].nlink.saturating_sub(1);
        if self.inodes[target].nlink == 0 {
            self.free_inode(target);
        }
        Ok(())
    }

    fn rmdir(&mut self, dir: InodeId, name: FileName<'_>) -> Result<(), VfsError> {
        let dir_idx = self.check_dir(dir)?;
        let dm = &self.inodes[dir_idx];
        let slot = self.dir_lookup_slot(dm, name.as_bytes())?;
        let page = &self.pages[dm.page_idx as usize];
        let (_nlen, target_ino) = Self::read_dir_entry_raw(page, slot);
        let target = target_ino as usize;

        if self.inodes[target].kind != InodeType::Directory {
            return Err(VfsError::NotADirectory);
        }
        // Check empty: only "." and ".." allowed.
        if self.inodes[target].size > 2 {
            return Err(VfsError::DirectoryNotEmpty);
        }

        self.dir_remove_entry(dir_idx, slot);
        // Decrement parent nlink (for ".." in removed dir).
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
        if self.dir_lookup_slot(dm, name.as_bytes()).is_ok() {
            return Err(VfsError::AlreadyExists);
        }
        if name.len() > DIR_ENTRY_NAME_CAP {
            return Err(VfsError::NameTooLong);
        }
        self.dir_add_entry(dir_idx, name.as_bytes(), target_idx as u16)?;
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
        if self.dir_lookup_slot(dm, name.as_bytes()).is_ok() {
            return Err(VfsError::AlreadyExists);
        }
        if target.len() > PAGE_SIZE {
            return Err(VfsError::NameTooLong);
        }
        let new_ino = self.alloc_inode()?;
        let new_page = match self.alloc_page() {
            Ok(p) => p,
            Err(e) => {
                self.inodes[new_ino] = RamInodeMeta::ZERO;
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
            m.page_idx = new_page;
        }
        self.pages[new_page as usize][..target.len()].copy_from_slice(target);
        if name.len() > DIR_ENTRY_NAME_CAP {
            self.free_inode(new_ino);
            return Err(VfsError::NameTooLong);
        }
        self.dir_add_entry(dir_idx, name.as_bytes(), new_ino as u16)?;
        Ok(new_ino as InodeId)
    }

    fn readlink(&self, ino: InodeId, buf: &mut [u8]) -> Result<usize, VfsError> {
        let m = self.meta(ino)?;
        if m.kind != InodeType::Symlink {
            return Err(VfsError::InvalidPath);
        }
        if m.page_idx == NO_PAGE {
            return Ok(0);
        }
        let page = &self.pages[m.page_idx as usize];
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
        if dm.page_idx == NO_PAGE {
            return Ok(false);
        }
        let page = &self.pages[dm.page_idx as usize];
        let (nlen, ino) = Self::read_dir_entry_raw(page, offset);
        let name_bytes = Self::dir_entry_name(page, offset, nlen);

        buf.ino = ino as InodeId;
        buf.kind = self.inodes[ino as usize].kind;
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
        let slot = self.dir_lookup_slot(dm, old_name.as_bytes())?;
        let page = &self.pages[dm.page_idx as usize];
        let (_nlen, target_ino) = Self::read_dir_entry_raw(page, slot);

        // Check if destination already exists and remove it.
        let new_dm = &self.inodes[new_dir_idx];
        if let Ok(existing_slot) = self.dir_lookup_slot(new_dm, new_name.as_bytes()) {
            let epage = &self.pages[new_dm.page_idx as usize];
            let (_en, existing_ino) = Self::read_dir_entry_raw(epage, existing_slot);
            let ei = existing_ino as usize;
            // If replacing a directory, it must be empty.
            if self.inodes[ei].kind == InodeType::Directory {
                if self.inodes[ei].size > 2 {
                    return Err(VfsError::DirectoryNotEmpty);
                }
                self.inodes[new_dir_idx].nlink =
                    self.inodes[new_dir_idx].nlink.saturating_sub(1);
            }
            self.dir_remove_entry(new_dir_idx, existing_slot);
            self.inodes[ei].nlink = self.inodes[ei].nlink.saturating_sub(1);
            if self.inodes[ei].nlink == 0 {
                self.free_inode(ei);
            }
        }

        // Remove from old dir.
        self.dir_remove_entry(old_dir_idx, slot);

        // Add to new dir.
        if new_name.len() > DIR_ENTRY_NAME_CAP {
            return Err(VfsError::NameTooLong);
        }
        self.dir_add_entry(new_dir_idx, new_name.as_bytes(), target_ino)?;

        // If we moved a directory, update ".." in the moved dir.
        if self.inodes[target_ino as usize].kind == InodeType::Directory
            && old_dir_idx != new_dir_idx
        {
            let moved_pg = self.inodes[target_ino as usize].page_idx as usize;
            // ".." is at slot 1.
            Self::write_dir_entry_raw(
                &mut self.pages[moved_pg],
                1,
                b"..",
                new_dir_idx as u16,
            );
            self.inodes[old_dir_idx].nlink =
                self.inodes[old_dir_idx].nlink.saturating_sub(1);
            self.inodes[new_dir_idx].nlink += 1;
        }

        Ok(())
    }

    fn chmod(&mut self, ino: InodeId, mode: u32) -> Result<(), VfsError> {
        let m = self.meta_mut(ino)?;
        // Preserve file type bits, update permission bits.
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
    use super::*;
    use crate::{FileName, InodeStat, DirEntry, InodeType, VfsError, FileSystem};

    fn new_fs() -> Box<RamFs> {
        RamFs::new_boxed()
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
        let fs = new_fs();
        assert_eq!(fs.root_inode(), 0);
    }

    #[test]
    fn stat_root() {
        let fs = new_fs();
        let mut st = zeroed_stat();
        fs.stat(0, &mut st).unwrap();
        assert_eq!(st.ino, 0);
        assert_eq!(st.nlink, 2);
        assert!(st.mode & S_IFDIR != 0);
    }

    #[test]
    fn create_and_stat_file() {
        let mut fs = new_fs();
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
        let mut fs = new_fs();
        let name = FileName::new(b"dup").unwrap();
        fs.create(0, name, 0o644).unwrap();
        assert_eq!(fs.create(0, name, 0o644), Err(VfsError::AlreadyExists));
    }

    #[test]
    fn write_and_read() {
        let mut fs = new_fs();
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
        let mut fs = new_fs();
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
        let mut fs = new_fs();
        let name = FileName::new(b"small").unwrap();
        let ino = fs.create(0, name, 0o644).unwrap();
        fs.write(ino, 0, b"hi").unwrap();
        let mut buf = [0u8; 4];
        let n = fs.read(ino, 100, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn truncate_file() {
        let mut fs = new_fs();
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
        let mut fs = new_fs();
        let name = FileName::new(b"found").unwrap();
        let ino = fs.create(0, name, 0o644).unwrap();
        assert_eq!(fs.lookup(0, name).unwrap(), ino);
    }

    #[test]
    fn lookup_missing() {
        let fs = new_fs();
        let name = FileName::new(b"nope").unwrap();
        assert_eq!(fs.lookup(0, name), Err(VfsError::NotFound));
    }

    #[test]
    fn mkdir_and_lookup() {
        let mut fs = new_fs();
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
        let mut fs = new_fs();
        let name = FileName::new(b"gone").unwrap();
        fs.create(0, name, 0o644).unwrap();
        fs.unlink(0, name).unwrap();
        assert_eq!(fs.lookup(0, name), Err(VfsError::NotFound));
    }

    #[test]
    fn unlink_directory_fails() {
        let mut fs = new_fs();
        let name = FileName::new(b"dir").unwrap();
        fs.mkdir(0, name, 0o755).unwrap();
        assert_eq!(fs.unlink(0, name), Err(VfsError::IsADirectory));
    }

    #[test]
    fn rmdir_empty() {
        let mut fs = new_fs();
        let name = FileName::new(b"empty").unwrap();
        fs.mkdir(0, name, 0o755).unwrap();
        fs.rmdir(0, name).unwrap();
        assert_eq!(fs.lookup(0, name), Err(VfsError::NotFound));
    }

    #[test]
    fn rmdir_notempty_fails() {
        let mut fs = new_fs();
        let dname = FileName::new(b"dir2").unwrap();
        let dir_ino = fs.mkdir(0, dname, 0o755).unwrap();
        let fname = FileName::new(b"child").unwrap();
        fs.create(dir_ino, fname, 0o644).unwrap();
        assert_eq!(fs.rmdir(0, dname), Err(VfsError::DirectoryNotEmpty));
    }

    #[test]
    fn hard_link() {
        let mut fs = new_fs();
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
        let mut fs = new_fs();
        let name = FileName::new(b"sym").unwrap();
        let target = b"/etc/passwd";
        let ino = fs.symlink(0, name, target).unwrap();
        let mut buf = [0u8; 64];
        let n = fs.readlink(ino, &mut buf).unwrap();
        assert_eq!(&buf[..n], target);
    }

    #[test]
    fn readdir_root() {
        let mut fs = new_fs();
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
        let mut fs = new_fs();
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
        let mut fs = new_fs();
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
        let mut fs = new_fs();
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
        let fs = new_fs();
        let mut st = zeroed_stat();
        assert_eq!(fs.stat(999, &mut st), Err(VfsError::NotFound));
    }

    #[test]
    fn write_full_page() {
        let mut fs = new_fs();
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
    fn write_beyond_page_fails() {
        let mut fs = new_fs();
        let name = FileName::new(b"toobig").unwrap();
        let ino = fs.create(0, name, 0o644).unwrap();
        let data = [0u8; PAGE_SIZE + 1];
        assert_eq!(fs.write(ino, 0, &data), Err(VfsError::NoSpace));
    }

    #[test]
    fn read_directory_fails() {
        let fs = new_fs();
        let mut buf = [0u8; 64];
        assert_eq!(fs.read(0, 0, &mut buf), Err(VfsError::IsADirectory));
    }

    #[test]
    fn rename_across_dirs() {
        let mut fs = new_fs();
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
}
