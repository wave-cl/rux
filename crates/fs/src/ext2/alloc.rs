//! ext2 block and inode allocation via bitmaps.

use crate::VfsError;
use super::{Ext2Fs, le16, le32, set_le16};

/// Read a block group descriptor. Returns (bgd_block, bgd_offset_in_block, bgd_buf).
#[inline]
unsafe fn read_bgd(fs: &Ext2Fs, group: u32, buf: &mut [u8; 4096]) -> Result<(u64, usize), VfsError> {
    let bgd_offset = group * 32;
    let bgd_block = fs.bgdt_block as u64 + (bgd_offset / fs.block_size) as u64;
    let bgd_off = (bgd_offset % fs.block_size) as usize;
    fs.read_block(bgd_block, buf)?;
    Ok((bgd_block, bgd_off))
}

/// Number of block groups on this filesystem.
#[inline]
fn num_groups(fs: &Ext2Fs) -> u32 {
    (fs.inode_count + fs.inodes_per_group - 1) / fs.inodes_per_group
}

/// Allocate a free block. Returns the block number (1-based).
pub(crate) unsafe fn alloc_block(fs: &Ext2Fs) -> Result<u32, VfsError> {
    let bs = fs.block_size as usize;
    let mut bgd_buf = [0u8; 4096];
    let mut bitmap_buf = [0u8; 4096];

    for group in 0..num_groups(fs) {
        let (bgd_block, bgd_off) = read_bgd(fs, group, &mut bgd_buf)?;
        let free = le16(&bgd_buf, bgd_off + 12);
        if free == 0 { continue; }

        let bitmap_block = le32(&bgd_buf, bgd_off) as u64;
        fs.read_block(bitmap_block, &mut bitmap_buf)?;

        let bits = fs.blocks_per_group.min(bs as u32 * 8);
        for bit in 0..bits {
            let byte = bit as usize / 8;
            let mask = 1u8 << (bit % 8);
            if bitmap_buf[byte] & mask == 0 {
                bitmap_buf[byte] |= mask;
                fs.write_block(bitmap_block, &bitmap_buf)?;
                set_le16(&mut bgd_buf, bgd_off + 12, free - 1);
                fs.write_block(bgd_block, &bgd_buf)?;
                let first_data_block = if fs.block_size == 1024 { 1u32 } else { 0u32 };
                return Ok(group * fs.blocks_per_group + bit + first_data_block);
            }
        }
    }
    Err(VfsError::NoSpace)
}

/// Allocate a free inode. Returns the inode number (1-based).
pub(crate) unsafe fn alloc_inode(fs: &Ext2Fs) -> Result<u32, VfsError> {
    let mut bgd_buf = [0u8; 4096];
    let mut bitmap_buf = [0u8; 4096];

    for group in 0..num_groups(fs) {
        let (bgd_block, bgd_off) = read_bgd(fs, group, &mut bgd_buf)?;
        let free = le16(&bgd_buf, bgd_off + 14);
        if free == 0 { continue; }

        let bitmap_block = le32(&bgd_buf, bgd_off + 4) as u64;
        fs.read_block(bitmap_block, &mut bitmap_buf)?;

        for bit in 0..fs.inodes_per_group {
            let byte = bit as usize / 8;
            let mask = 1u8 << (bit % 8);
            if bitmap_buf[byte] & mask == 0 {
                bitmap_buf[byte] |= mask;
                fs.write_block(bitmap_block, &bitmap_buf)?;
                set_le16(&mut bgd_buf, bgd_off + 14, free - 1);
                fs.write_block(bgd_block, &bgd_buf)?;
                return Ok(group * fs.inodes_per_group + bit + 1);
            }
        }
    }
    Err(VfsError::NoSpace)
}

/// Free an inode back to the bitmap.
pub(crate) unsafe fn free_inode(fs: &Ext2Fs, ino: u32) -> Result<(), VfsError> {
    if ino < 2 { return Ok(()); }
    let adj = ino - 1;
    let group = adj / fs.inodes_per_group;
    let bit = adj % fs.inodes_per_group;

    let mut bgd_buf = [0u8; 4096];
    let mut bitmap_buf = [0u8; 4096];
    let (bgd_block, bgd_off) = read_bgd(fs, group, &mut bgd_buf)?;

    let bitmap_block = le32(&bgd_buf, bgd_off + 4) as u64;
    fs.read_block(bitmap_block, &mut bitmap_buf)?;

    bitmap_buf[bit as usize / 8] &= !(1u8 << (bit % 8));
    fs.write_block(bitmap_block, &bitmap_buf)?;

    let free = le16(&bgd_buf, bgd_off + 14);
    set_le16(&mut bgd_buf, bgd_off + 14, free + 1);
    fs.write_block(bgd_block, &bgd_buf)?;
    Ok(())
}

/// Free a block back to the bitmap.
pub(crate) unsafe fn free_block(fs: &Ext2Fs, block_num: u32) -> Result<(), VfsError> {
    let first_data_block = if fs.block_size == 1024 { 1u32 } else { 0u32 };
    if block_num <= first_data_block { return Ok(()); }
    let adj = block_num - first_data_block;
    let group = adj / fs.blocks_per_group;
    let bit = adj % fs.blocks_per_group;

    let mut bgd_buf = [0u8; 4096];
    let mut bitmap_buf = [0u8; 4096];
    let (bgd_block, bgd_off) = read_bgd(fs, group, &mut bgd_buf)?;

    let bitmap_block = le32(&bgd_buf, bgd_off) as u64;
    fs.read_block(bitmap_block, &mut bitmap_buf)?;

    bitmap_buf[bit as usize / 8] &= !(1u8 << (bit % 8));
    fs.write_block(bitmap_block, &bitmap_buf)?;

    let free = le16(&bgd_buf, bgd_off + 12);
    set_le16(&mut bgd_buf, bgd_off + 12, free + 1);
    fs.write_block(bgd_block, &bgd_buf)?;

    // Invalidate cache entry for the freed block
    let inner = &mut *fs.inner.get();
    for entry in inner.cache.iter_mut() {
        if entry.valid && entry.block_no == block_num as u64 {
            entry.valid = false;
            break;
        }
    }
    Ok(())
}
