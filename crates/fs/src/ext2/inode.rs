//! ext2 inode reading.

use crate::{InodeType, VfsError};
use super::Ext2Fs;
use super::superblock::{self};

/// Raw on-disk inode fields we need.
pub(crate) struct RawInode {
    pub mode: u16,
    pub uid: u16,
    pub size: u32,
    pub atime: u32,
    pub ctime: u32,
    pub mtime: u32,
    pub gid: u16,
    pub links_count: u16,
    pub blocks: u32,       // 512-byte block count
    pub block: [u32; 15],  // direct[0-11], indirect[12], dindirect[13], tindirect[14]
    pub size_high: u32,    // upper 32 bits of size (for large files)
}

fn le16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Read a raw inode by inode number (1-based, as per ext2 convention).
pub(crate) unsafe fn read_raw(fs: &Ext2Fs, ino: u32) -> Result<RawInode, VfsError> {
    if ino == 0 || ino > fs.inode_count {
        return Err(VfsError::NotFound);
    }

    let group = (ino - 1) / fs.inodes_per_group;
    let local_idx = (ino - 1) % fs.inodes_per_group;

    // Read block group descriptor to find inode table block
    let bgd_size = 32u32; // ext2 block group descriptor is 32 bytes
    let bgd_offset = group * bgd_size;
    let bgd_block = fs.bgdt_block as u64 + (bgd_offset / fs.block_size) as u64;
    let bgd_off_in_block = (bgd_offset % fs.block_size) as usize;

    let mut buf = [0u8; 4096];
    fs.read_block(bgd_block, &mut buf)?;

    // Inode table block is at offset 8 in the block group descriptor
    let inode_table_block = le32(&buf, bgd_off_in_block + 8);

    // Calculate which block and offset within that block
    let inode_byte_offset = local_idx as u64 * fs.inode_size as u64;
    let inode_block = inode_table_block as u64 + inode_byte_offset / fs.block_size as u64;
    let inode_off = (inode_byte_offset % fs.block_size as u64) as usize;

    fs.read_block(inode_block, &mut buf)?;

    // Parse inode fields
    let b = &buf[inode_off..];
    let mut block = [0u32; 15];
    for i in 0..15 {
        block[i] = le32(b, 40 + i * 4);
    }

    Ok(RawInode {
        mode: le16(b, 0),
        uid: le16(b, 2),
        size: le32(b, 4),
        atime: le32(b, 8),
        ctime: le32(b, 12),
        mtime: le32(b, 16),
        gid: le16(b, 24),
        links_count: le16(b, 26),
        blocks: le32(b, 28),
        block,
        size_high: le32(b, 108),
    })
}

/// Convert ext2 mode to InodeType.
pub(crate) fn mode_to_type(mode: u16) -> InodeType {
    match mode & 0xF000 {
        0x4000 => InodeType::Directory,
        0x8000 => InodeType::File,
        0xA000 => InodeType::Symlink,
        _ => InodeType::File,
    }
}

/// Read symlink target. Short symlinks (< 60 bytes) are stored inline
/// in the inode's i_block[] array. Longer symlinks are stored in data blocks.
pub(crate) unsafe fn readlink(fs: &Ext2Fs, ino: u32, buf: &mut [u8]) -> Result<usize, VfsError> {
    let raw = read_raw(fs, ino)?;
    let size = raw.size as usize;
    if size == 0 || size > buf.len() {
        return Err(VfsError::IoError);
    }

    // Fast symlink: target stored inline in i_block[] (up to 60 bytes)
    if size <= 60 && raw.blocks == 0 {
        let src = &raw.block as *const u32 as *const u8;
        core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), size);
        return Ok(size);
    }

    // Slow symlink: read from data blocks
    super::block::read_file(fs, ino, 0, &mut buf[..size])
}
