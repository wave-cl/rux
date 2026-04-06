//! Read-only ext2 filesystem driver.
//!
//! Implements the `FileSystem` trait for ext2 images accessed through a
//! `BlockDevice`. Supports direct, single-indirect, and double-indirect
//! blocks, directory traversal, symlinks, and stat.

mod superblock;
mod inode;
mod dir;
mod block;
mod alloc;

use core::cell::UnsafeCell;
use crate::{FileSystem, FileName, InodeId, InodeStat, InodeType, DirEntry, VfsError};

/// Read-only ext2 filesystem backed by a block device.
///
/// Interior mutability via UnsafeCell for the block cache, since
/// FileSystem trait methods take `&self` but we need to update the cache.
/// Single-threaded boot-time access makes this safe.
pub struct Ext2Fs {
    /// Block device providing sector reads.
    dev: *const dyn rux_drivers::BlockDevice,
    /// Block size in bytes (1024 << s_log_block_size).
    pub block_size: u32,
    /// Inodes per block group.
    pub(crate) inodes_per_group: u32,
    /// Blocks per block group.
    pub(crate) blocks_per_group: u32,
    /// Inode size in bytes.
    pub(crate) inode_size: u16,
    /// Total inode count.
    pub(crate) inode_count: u32,
    /// Block group descriptor table (first block after superblock).
    pub(crate) bgdt_block: u32,
    /// Mutable state behind UnsafeCell for interior mutability.
    inner: UnsafeCell<Ext2Inner>,
}

struct Ext2Inner {
    cache: [CacheEntry; 32],
    cache_idx: usize,
}

/// Reentrant filesystem lock — prevents concurrent ext2 metadata corruption.
/// Uses a depth counter so nested calls (e.g., unlink → truncate) don't deadlock.
static FS_LOCK: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static mut FS_LOCK_DEPTH: u32 = 0;

fn fs_lock() {
    unsafe {
        if FS_LOCK_DEPTH > 0 {
            FS_LOCK_DEPTH += 1;
            return;
        }
        while FS_LOCK.swap(true, core::sync::atomic::Ordering::Acquire) {
            core::hint::spin_loop();
        }
        FS_LOCK_DEPTH = 1;
    }
}
fn fs_unlock() {
    unsafe {
        FS_LOCK_DEPTH -= 1;
        if FS_LOCK_DEPTH == 0 {
            FS_LOCK.store(false, core::sync::atomic::Ordering::Release);
        }
    }
}

/// RAII guard for the filesystem lock. Automatically unlocks on drop,
/// preventing lock-depth leaks from early returns and `?` operators.
struct FsLockGuard;
impl FsLockGuard {
    #[inline(always)]
    fn new() -> Self { fs_lock(); Self }
}
impl Drop for FsLockGuard {
    #[inline(always)]
    fn drop(&mut self) { fs_unlock(); }
}

// ── Endianness helpers (canonical copies — used by all ext2 submodules) ──

#[inline(always)]
pub(crate) fn le16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}
#[inline(always)]
pub(crate) fn le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}
#[inline(always)]
pub(crate) fn set_le16(buf: &mut [u8], off: usize, val: u16) {
    let b = val.to_le_bytes(); buf[off] = b[0]; buf[off + 1] = b[1];
}
#[inline(always)]
pub(crate) fn set_le32(buf: &mut [u8], off: usize, val: u32) {
    let b = val.to_le_bytes();
    buf[off] = b[0]; buf[off + 1] = b[1]; buf[off + 2] = b[2]; buf[off + 3] = b[3];
}

/// Block cache entry. Uses 1024-byte data buffer (matching ext2 block size)
/// to allow more entries in the same BSS footprint.
#[derive(Clone)]
struct CacheEntry {
    block_no: u64,
    valid: bool,
    data: [u8; 1024],
}

impl CacheEntry {
    const fn empty() -> Self {
        Self { block_no: 0, valid: false, data: [0; 1024] }
    }
}

impl Ext2Fs {
    /// Mount an ext2 filesystem from a block device.
    ///
    /// # Safety
    /// `dev` must remain valid for the lifetime of the Ext2Fs.
    pub unsafe fn mount(dev: *const dyn rux_drivers::BlockDevice) -> Result<Self, VfsError> {
        let mut sb_buf = [0u8; 1024];
        // Superblock is at byte offset 1024 (sectors 2-3 for 512-byte sectors)
        let blk = &*dev;
        blk.read_block(2, sb_buf.as_mut_ptr()).map_err(|_| VfsError::IoError)?;
        blk.read_block(3, sb_buf.as_mut_ptr().add(512)).map_err(|_| VfsError::IoError)?;

        let sb = superblock::parse(&sb_buf)?;

        let bgdt_block = if sb.block_size == 1024 { 2 } else { 1 };

        Ok(Self {
            dev,
            block_size: sb.block_size,
            inodes_per_group: sb.inodes_per_group,
            blocks_per_group: sb.blocks_per_group,
            inode_size: sb.inode_size,
            inode_count: sb.inode_count,
            bgdt_block,
            inner: UnsafeCell::new(Ext2Inner {
                cache: {
                    const E: CacheEntry = CacheEntry::empty();
                    [E; 32]
                },
                cache_idx: 0,
            }),
        })
    }

    /// Read a filesystem block into `buf`. Uses the block cache.
    pub(crate) unsafe fn read_block(&self, block_no: u64, buf: &mut [u8]) -> Result<(), VfsError> {
        // Bounds check: prevent reading beyond the disk (256K blocks = 256MB max)
        if block_no > 262144 { return Err(VfsError::IoError); }

        let bs = self.block_size as usize;
        let inner = &mut *self.inner.get();

        // Check cache
        for entry in inner.cache.iter() {
            if entry.valid && entry.block_no == block_no {
                buf[..bs].copy_from_slice(&entry.data[..bs]);
                return Ok(());
            }
        }

        // Cache miss: read from device sector-by-sector
        let sectors_per_block = bs / 512;
        let start_sector = block_no * sectors_per_block as u64;
        let dev = &*self.dev;
        // Read all sectors for this block
        for i in 0..sectors_per_block {
            let sector = start_sector + i as u64;
            dev.read_block(sector, buf.as_mut_ptr().add(i * 512))
                .map_err(|_| VfsError::IoError)?;
        }

        // Insert into cache (round-robin)
        let idx = inner.cache_idx;
        inner.cache_idx = (idx + 1) % 32;
        inner.cache[idx].block_no = block_no;
        inner.cache[idx].data[..bs].copy_from_slice(&buf[..bs]);
        inner.cache[idx].valid = true;

        Ok(())
    }

    /// Write a filesystem block from `buf` to disk. Updates cache.
    pub(crate) unsafe fn write_block(&self, block_no: u64, buf: &[u8]) -> Result<(), VfsError> {
        let bs = self.block_size as usize;
        let sectors_per_block = bs / 512;
        let start_sector = block_no * sectors_per_block as u64;

        // Write-through: write to device immediately
        let dev = &mut *(self.dev as *mut dyn rux_drivers::BlockDevice);
        for i in 0..sectors_per_block {
            dev.write_block(start_sector + i as u64, buf.as_ptr().add(i * 512))
                .map_err(|_| VfsError::IoError)?;
        }

        // Update cache (or insert if not cached) for read-after-write consistency
        let inner = &mut *self.inner.get();
        let mut found = false;
        for entry in inner.cache.iter_mut() {
            if entry.valid && entry.block_no == block_no {
                entry.data[..bs].copy_from_slice(&buf[..bs]);
                found = true;
                break;
            }
        }
        if !found {
            let idx = inner.cache_idx;
            inner.cache_idx = (idx + 1) % 32;
            inner.cache[idx].block_no = block_no;
            inner.cache[idx].data[..bs].copy_from_slice(&buf[..bs]);
            inner.cache[idx].valid = true;
        }

        Ok(())
    }

    /// Read raw inode data by inode number.
    pub(crate) unsafe fn read_inode_raw(&self, ino: u32) -> Result<inode::RawInode, VfsError> {
        inode::read_raw(self, ino)
    }

    /// Write raw inode data back to disk.
    pub(crate) unsafe fn write_inode_raw(&self, ino: u32, raw: &inode::RawInode) -> Result<(), VfsError> {
        inode::write_raw(self, ino, raw)
    }
}

// ── FileSystem trait implementation ────────────────────────────────

impl FileSystem for Ext2Fs {
    fn root_inode(&self) -> InodeId { 2 } // ext2 root is always inode 2

    fn stat(&self, ino: InodeId, buf: &mut InodeStat) -> Result<(), VfsError> {
        unsafe {
            let raw = self.read_inode_raw(ino as u32)?;
            buf.ino = ino;
            buf.size = ((raw.size_high as u64) << 32) | raw.size as u64;
            buf.mode = raw.mode as u32;
            buf.nlink = raw.links_count as u32;
            buf.uid = raw.uid as u32;
            buf.gid = raw.gid as u32;
            buf.atime = raw.atime as u64;
            buf.mtime = raw.mtime as u64;
            buf.ctime = raw.ctime as u64;
            buf.blksize = self.block_size;
            buf.blocks = raw.blocks as u64;
            Ok(())
        }
    }

    fn read(&self, ino: InodeId, offset: u64, buf: &mut [u8]) -> Result<usize, VfsError> {
        unsafe { block::read_file(self, ino as u32, offset, buf) }
    }

    fn write(&mut self, ino: InodeId, offset: u64, buf: &[u8]) -> Result<usize, VfsError> {
        let _g = FsLockGuard::new();
        unsafe { block::write_file(self, ino as u32, offset, buf) }
    }

    fn truncate(&mut self, ino: InodeId, size: u64) -> Result<(), VfsError> {
        let _g = FsLockGuard::new();
        unsafe {
            let mut raw = self.read_inode_raw(ino as u32)?;
            let old_size = raw.size as u64 | ((raw.size_high as u64) << 32);

            // Free data blocks when truncating to 0
            if size == 0 && old_size > 0 {
                // Free direct blocks (indices 0..12)
                for i in 0..12 {
                    let blk = raw.block[i];
                    if blk > 1 { // guard: never free block 0 or 1 (superblock)
                        let _ = alloc::free_block(self, blk);
                    }
                    raw.block[i] = 0;
                }

                // Free single indirect block and its entries
                let ind = raw.block[12];
                if ind > 1 {
                    let bs = self.block_size as usize;
                    let mut ind_buf = [0u8; 4096];
                    if self.read_block(ind as u64, &mut ind_buf).is_ok() {
                        let ptrs = bs / 4;
                        for i in 0..ptrs {
                            let off = i * 4;
                            let bnum = u32::from_le_bytes([
                                ind_buf[off], ind_buf[off+1], ind_buf[off+2], ind_buf[off+3],
                            ]);
                            if bnum > 1 {
                                let _ = alloc::free_block(self, bnum);
                            }
                        }
                        let _ = alloc::free_block(self, ind);
                    }
                    raw.block[12] = 0;
                }
                // Double/triple indirect (block[13], block[14]) — rare for small files
                // Just zero the pointers without freeing (small space leak)
                raw.block[13] = 0;
                raw.block[14] = 0;
                raw.blocks = 0;
            }

            raw.size = size as u32;
            raw.size_high = (size >> 32) as u32;
            self.write_inode_raw(ino as u32, &raw)
        }
    }

    fn lookup(&self, dir_ino: InodeId, name: FileName<'_>) -> Result<InodeId, VfsError> {
        unsafe {

            dir::lookup(self, dir_ino as u32, name.as_bytes())
                .map(|ino| ino as InodeId)
        }
    }

    fn create(&mut self, dir_ino: InodeId, name: FileName<'_>, mode: u32) -> Result<InodeId, VfsError> {
        let _g = FsLockGuard::new();
        unsafe {
            // Check for duplicate name
            if dir::lookup(self, dir_ino as u32, name.as_bytes()).is_ok() {
                return Err(VfsError::AlreadyExists);
            }
            let ino = alloc::alloc_inode(self)?;
            // Initialize inode as regular file
            let raw = inode::RawInode {
                mode: (0x8000 | (mode & 0xFFF)) as u16, // S_IFREG | perms
                uid: 0, gid: 0, size: 0, atime: 0, ctime: 0, mtime: 0,
                links_count: 1, blocks: 0, block: [0; 15], size_high: 0,
            };
            self.write_inode_raw(ino, &raw)?;
            dir::add_entry(self, dir_ino as u32, ino, name.as_bytes(), 1)?; // 1 = regular file
            Ok(ino as InodeId)
        }
    }

    fn mkdir(&mut self, dir_ino: InodeId, name: FileName<'_>, mode: u32) -> Result<InodeId, VfsError> {
        let _g = FsLockGuard::new();
        unsafe {
            // Check for duplicate name
            if dir::lookup(self, dir_ino as u32, name.as_bytes()).is_ok() {
                return Err(VfsError::AlreadyExists);
            }
            let ino = alloc::alloc_inode(self)?;
            let block_num = alloc::alloc_block(self)?;

            // Initialize inode as directory
            let mut raw = inode::RawInode {
                mode: (0x4000 | (mode & 0xFFF)) as u16, // S_IFDIR | perms
                uid: 0, gid: 0, size: self.block_size, atime: 0, ctime: 0, mtime: 0,
                links_count: 2, blocks: (self.block_size / 512) as u32,
                block: [0; 15], size_high: 0,
            };
            raw.block[0] = block_num;
            self.write_inode_raw(ino, &raw)?;

            // Initialize directory block with . and ..
            let bs = self.block_size as usize;
            let mut dir_buf = [0u8; 4096];

            // "." entry
            let dot_rec_len = 12u16;
            set_le32(&mut dir_buf, 0, ino);
            set_le16(&mut dir_buf, 4, dot_rec_len);
            dir_buf[6] = 1; // name_len
            dir_buf[7] = 2; // file_type = directory
            dir_buf[8] = b'.';

            // ".." entry (takes remaining space)
            let dotdot_off = dot_rec_len as usize;
            set_le32(&mut dir_buf, dotdot_off, dir_ino as u32);
            set_le16(&mut dir_buf, dotdot_off + 4, (bs - dotdot_off) as u16);
            dir_buf[dotdot_off + 6] = 2; // name_len
            dir_buf[dotdot_off + 7] = 2; // file_type = directory
            dir_buf[dotdot_off + 8] = b'.';
            dir_buf[dotdot_off + 9] = b'.';

            self.write_block(block_num as u64, &dir_buf)?;

            // Add entry in parent directory
            dir::add_entry(self, dir_ino as u32, ino, name.as_bytes(), 2)?; // 2 = directory

            // Increment parent's link count
            let mut parent_raw = self.read_inode_raw(dir_ino as u32)?;
            parent_raw.links_count += 1;
            self.write_inode_raw(dir_ino as u32, &parent_raw)?;

            Ok(ino as InodeId)
        }
    }

    fn unlink(&mut self, dir_ino: InodeId, name: FileName<'_>) -> Result<(), VfsError> {
        let _g = FsLockGuard::new();
        unsafe {
            let child_ino = dir::remove_entry(self, dir_ino as u32, name.as_bytes())?;
            let mut raw = self.read_inode_raw(child_ino)?;
            raw.links_count = raw.links_count.saturating_sub(1);
            if raw.links_count == 0 {
                // Free all data blocks and the inode itself
                let _ = self.truncate(child_ino as u64, 0);
                // Free inode (mark as unused in inode bitmap)
                let _ = alloc::free_inode(self, child_ino);
            } else {
                self.write_inode_raw(child_ino, &raw)?;
            }
            Ok(())
        }
    }

    fn rmdir(&mut self, dir_ino: InodeId, name: FileName<'_>) -> Result<(), VfsError> {
        let _g = FsLockGuard::new();
        unsafe {
            // Look up the child directory
            let child_ino = dir::lookup(self, dir_ino as u32, name.as_bytes())?;
            let raw = self.read_inode_raw(child_ino)?;
            if inode::mode_to_type(raw.mode) != InodeType::Directory {
                return Err(VfsError::NotADirectory);
            }
            // Check emptiness: scan for any entry beyond . and ..
            let bs = self.block_size as usize;
            let has_entries = dir::for_each_dir_block(self, child_ino, false, |buf, _phys| {
                let mut off = 0usize;
                while off + 8 <= bs {
                    let d_ino = le32(buf, off);
                    let rec_len = le16(buf, off + 4) as usize;
                    if rec_len == 0 { break; }
                    if d_ino != 0 {
                        let nlen = buf[off + 6] as usize;
                        let n = &buf[off + 8..off + 8 + nlen];
                        if n != b"." && n != b".." {
                            return Ok(Some(true)); // non-trivial entry found
                        }
                    }
                    off += rec_len;
                }
                Ok(None)
            })?.unwrap_or(false);
            if has_entries {
                return Err(VfsError::DirectoryNotEmpty);
            }
            // Empty — remove entry and free inode
            dir::remove_entry(self, dir_ino as u32, name.as_bytes())?;
            let mut child_raw = self.read_inode_raw(child_ino)?;
            child_raw.links_count = child_raw.links_count.saturating_sub(1);
            if child_raw.links_count == 0 {
                let _ = self.truncate(child_ino as u64, 0);
                let _ = alloc::free_inode(self, child_ino);
            } else {
                self.write_inode_raw(child_ino, &child_raw)?;
            }
            // Decrement parent link count
            let mut parent_raw = self.read_inode_raw(dir_ino as u32)?;
            parent_raw.links_count = parent_raw.links_count.saturating_sub(1);
            self.write_inode_raw(dir_ino as u32, &parent_raw)?;
            Ok(())
        }
    }

    fn link(&mut self, dir_ino: InodeId, name: FileName<'_>, target: InodeId) -> Result<(), VfsError> {
        let _g = FsLockGuard::new();
        unsafe {
            let mut raw = self.read_inode_raw(target as u32)?;
            raw.links_count += 1;
            self.write_inode_raw(target as u32, &raw)?;
            dir::add_entry(self, dir_ino as u32, target as u32, name.as_bytes(), 1)?;
            Ok(())
        }
    }

    fn symlink(&mut self, dir_ino: InodeId, name: FileName<'_>, target: &[u8]) -> Result<InodeId, VfsError> {
        let _g = FsLockGuard::new();
        unsafe {
            let ino = alloc::alloc_inode(self)?;
            let mut raw = inode::RawInode {
                mode: 0xA1FF, // S_IFLNK | 0777
                uid: 0, gid: 0, size: target.len() as u32, atime: 0, ctime: 0, mtime: 0,
                links_count: 1, blocks: 0, block: [0; 15], size_high: 0,
            };

            // Fast symlink: store inline if <= 60 bytes
            if target.len() <= 60 {
                let dst = &mut raw.block as *mut u32 as *mut u8;
                core::ptr::copy_nonoverlapping(target.as_ptr(), dst, target.len());
            } else {
                // Slow symlink: write to data block
                self.write_inode_raw(ino, &raw)?;
                block::write_file(self, ino, 0, target)?;
                raw = self.read_inode_raw(ino)?;
            }

            self.write_inode_raw(ino, &raw)?;
            dir::add_entry(self, dir_ino as u32, ino, name.as_bytes(), 7)?; // 7 = symlink
            Ok(ino as InodeId)
        }
    }

    fn readlink(&self, ino: InodeId, buf: &mut [u8]) -> Result<usize, VfsError> {
        unsafe {

            inode::readlink(self, ino as u32, buf)
        }
    }

    fn readdir(&self, dir_ino: InodeId, offset: usize, entry: &mut DirEntry) -> Result<bool, VfsError> {
        unsafe { dir::readdir(self, dir_ino as u32, offset, entry) }
    }

    fn rename(&mut self, old_dir: InodeId, old_name: FileName<'_>, new_dir: InodeId, new_name: FileName<'_>) -> Result<(), VfsError> {
        let _g = FsLockGuard::new();
        unsafe {
            let ino = dir::lookup(self, old_dir as u32, old_name.as_bytes())
                .map_err(|_| VfsError::NotFound)?;
            let raw = self.read_inode_raw(ino)?;
            let ft = if inode::mode_to_type(raw.mode) == InodeType::Directory { 2u8 } else { 1u8 };
            // If target name already exists, remove it first (POSIX atomic replace)
            if dir::lookup(self, new_dir as u32, new_name.as_bytes()).is_ok() {
                let _ = dir::remove_entry(self, new_dir as u32, new_name.as_bytes());
            }
            dir::add_entry(self, new_dir as u32, ino, new_name.as_bytes(), ft)?;
            dir::remove_entry(self, old_dir as u32, old_name.as_bytes())?;
            Ok(())
        }
    }

    fn chmod(&mut self, ino: InodeId, mode: u32) -> Result<(), VfsError> {
        let _g = FsLockGuard::new();
        unsafe {
            let mut raw = self.read_inode_raw(ino as u32)?;
            raw.mode = (raw.mode & 0xF000) | (mode & 0xFFF) as u16;
            self.write_inode_raw(ino as u32, &raw)
        }
    }

    fn chown(&mut self, ino: InodeId, uid: u32, gid: u32) -> Result<(), VfsError> {
        let _g = FsLockGuard::new();
        unsafe {
            let mut raw = self.read_inode_raw(ino as u32)?;
            raw.uid = uid as u16;
            raw.gid = gid as u16;
            self.write_inode_raw(ino as u32, &raw)
        }
    }

    fn utimes(&mut self, ino: InodeId, atime: u64, mtime: u64) -> Result<(), VfsError> {
        let _g = FsLockGuard::new();
        unsafe {
            let mut raw = self.read_inode_raw(ino as u32)?;
            raw.atime = atime as u32;
            raw.mtime = mtime as u32;
            self.write_inode_raw(ino as u32, &raw)
        }
    }
}
