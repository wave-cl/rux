//! Read-only ext2 filesystem driver.
//!
//! Implements the `FileSystem` trait for ext2 images accessed through a
//! `BlockDevice`. Supports direct, single-indirect, and double-indirect
//! blocks, directory traversal, symlinks, and stat.

mod superblock;
mod inode;
mod dir;
mod block;

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
    cache: [CacheEntry; 8],
    cache_idx: usize,
}

#[derive(Clone)]
struct CacheEntry {
    block_no: u64,
    valid: bool,
    data: [u8; 4096],
}

impl CacheEntry {
    const fn empty() -> Self {
        Self { block_no: 0, valid: false, data: [0; 4096] }
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
                cache: [
                    CacheEntry::empty(), CacheEntry::empty(),
                    CacheEntry::empty(), CacheEntry::empty(),
                    CacheEntry::empty(), CacheEntry::empty(),
                    CacheEntry::empty(), CacheEntry::empty(),
                ],
                cache_idx: 0,
            }),
        })
    }

    /// Read a filesystem block into `buf`. Uses the block cache.
    pub(crate) unsafe fn read_block(&self, block_no: u64, buf: &mut [u8]) -> Result<(), VfsError> {
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
        inner.cache_idx = (idx + 1) % 8;
        inner.cache[idx].block_no = block_no;
        inner.cache[idx].data[..bs].copy_from_slice(&buf[..bs]);
        inner.cache[idx].valid = true;

        Ok(())
    }

    /// Read raw inode data by inode number.
    pub(crate) unsafe fn read_inode_raw(&self, ino: u32) -> Result<inode::RawInode, VfsError> {
        inode::read_raw(self, ino)
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
        unsafe {

            block::read_file(self, ino as u32, offset, buf)
        }
    }

    fn write(&mut self, _ino: InodeId, _offset: u64, _buf: &[u8]) -> Result<usize, VfsError> {
        Err(VfsError::NotSupported)
    }

    fn truncate(&mut self, _ino: InodeId, _size: u64) -> Result<(), VfsError> {
        Err(VfsError::NotSupported)
    }

    fn lookup(&self, dir_ino: InodeId, name: FileName<'_>) -> Result<InodeId, VfsError> {
        unsafe {

            dir::lookup(self, dir_ino as u32, name.as_bytes())
                .map(|ino| ino as InodeId)
        }
    }

    fn create(&mut self, _dir: InodeId, _name: FileName<'_>, _mode: u32) -> Result<InodeId, VfsError> {
        Err(VfsError::NotSupported)
    }

    fn mkdir(&mut self, _dir: InodeId, _name: FileName<'_>, _mode: u32) -> Result<InodeId, VfsError> {
        Err(VfsError::NotSupported)
    }

    fn unlink(&mut self, _dir: InodeId, _name: FileName<'_>) -> Result<(), VfsError> {
        Err(VfsError::NotSupported)
    }

    fn rmdir(&mut self, _dir: InodeId, _name: FileName<'_>) -> Result<(), VfsError> {
        Err(VfsError::NotSupported)
    }

    fn link(&mut self, _dir: InodeId, _name: FileName<'_>, _target: InodeId) -> Result<(), VfsError> {
        Err(VfsError::NotSupported)
    }

    fn symlink(&mut self, _dir: InodeId, _name: FileName<'_>, _target: &[u8]) -> Result<InodeId, VfsError> {
        Err(VfsError::NotSupported)
    }

    fn readlink(&self, ino: InodeId, buf: &mut [u8]) -> Result<usize, VfsError> {
        unsafe {

            inode::readlink(self, ino as u32, buf)
        }
    }

    fn readdir(&self, dir_ino: InodeId, offset: usize, entry: &mut DirEntry) -> Result<bool, VfsError> {
        unsafe {

            dir::readdir(self, dir_ino as u32, offset, entry)
        }
    }

    fn rename(&mut self, _od: InodeId, _on: FileName<'_>, _nd: InodeId, _nn: FileName<'_>) -> Result<(), VfsError> {
        Err(VfsError::NotSupported)
    }

    fn chmod(&mut self, _ino: InodeId, _mode: u32) -> Result<(), VfsError> {
        Err(VfsError::NotSupported)
    }

    fn chown(&mut self, _ino: InodeId, _uid: u32, _gid: u32) -> Result<(), VfsError> {
        Err(VfsError::NotSupported)
    }

    fn utimes(&mut self, _ino: InodeId, _atime: u64, _mtime: u64) -> Result<(), VfsError> {
        Err(VfsError::NotSupported)
    }
}
