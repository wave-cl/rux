//! ext2 block and inode allocation via bitmaps.

use crate::VfsError;
use super::Ext2Fs;

fn le16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn set_le16(buf: &mut [u8], off: usize, val: u16) {
    let b = val.to_le_bytes();
    buf[off] = b[0]; buf[off + 1] = b[1];
}

#[allow(dead_code)]
fn set_le32(buf: &mut [u8], off: usize, val: u32) {
    let b = val.to_le_bytes();
    buf[off] = b[0]; buf[off + 1] = b[1]; buf[off + 2] = b[2]; buf[off + 3] = b[3];
}

/// Allocate a free block. Returns the block number (1-based).
pub(crate) unsafe fn alloc_block(fs: &Ext2Fs) -> Result<u32, VfsError> {
    let bs = fs.block_size as usize;
    let mut bgd_buf = [0u8; 4096];
    let mut bitmap_buf = [0u8; 4096];

    // Scan each block group
    let num_groups = (fs.inode_count + fs.inodes_per_group - 1) / fs.inodes_per_group;
    for group in 0..num_groups {
        // Read block group descriptor
        let bgd_offset = group * 32;
        let bgd_block = fs.bgdt_block as u64 + (bgd_offset / fs.block_size) as u64;
        let bgd_off = (bgd_offset % fs.block_size) as usize;
        fs.read_block(bgd_block, &mut bgd_buf)?;

        let free_blocks = le16(&bgd_buf, bgd_off + 12);
        if free_blocks == 0 { continue; }

        let bitmap_block = le32(&bgd_buf, bgd_off + 0) as u64;
        fs.read_block(bitmap_block, &mut bitmap_buf)?;

        // Find first free bit in bitmap
        let bits_to_check = fs.blocks_per_group.min(bs as u32 * 8);
        for bit in 0..bits_to_check {
            let byte = bit as usize / 8;
            let mask = 1u8 << (bit % 8);
            if bitmap_buf[byte] & mask == 0 {
                // Found free block — set bit
                bitmap_buf[byte] |= mask;
                fs.write_block(bitmap_block, &bitmap_buf)?;

                // Update free count in BGD
                set_le16(&mut bgd_buf, bgd_off + 12, free_blocks - 1);
                fs.write_block(bgd_block, &bgd_buf)?;

                let _block_num = group * fs.blocks_per_group + bit + 1; // ext2 blocks are 1-based per group start
                // Actually: first block of group = group * blocks_per_group + first_data_block
                // For simplicity with 1024-byte blocks: first_data_block = 1
                let first_data_block = if fs.block_size == 1024 { 1u32 } else { 0u32 };
                return Ok(group * fs.blocks_per_group + bit + first_data_block);
            }
        }
    }
    Err(VfsError::NoSpace)
}

/// Allocate a free inode. Returns the inode number (1-based).
pub(crate) unsafe fn alloc_inode(fs: &Ext2Fs) -> Result<u32, VfsError> {
    let _bs = fs.block_size as usize;
    let mut bgd_buf = [0u8; 4096];
    let mut bitmap_buf = [0u8; 4096];

    let num_groups = (fs.inode_count + fs.inodes_per_group - 1) / fs.inodes_per_group;
    for group in 0..num_groups {
        let bgd_offset = group * 32;
        let bgd_block = fs.bgdt_block as u64 + (bgd_offset / fs.block_size) as u64;
        let bgd_off = (bgd_offset % fs.block_size) as usize;
        fs.read_block(bgd_block, &mut bgd_buf)?;

        let free_inodes = le16(&bgd_buf, bgd_off + 14);
        if free_inodes == 0 { continue; }

        let inode_bitmap_block = le32(&bgd_buf, bgd_off + 4) as u64;
        fs.read_block(inode_bitmap_block, &mut bitmap_buf)?;

        for bit in 0..fs.inodes_per_group {
            let byte = bit as usize / 8;
            let mask = 1u8 << (bit % 8);
            if bitmap_buf[byte] & mask == 0 {
                bitmap_buf[byte] |= mask;
                fs.write_block(inode_bitmap_block, &bitmap_buf)?;

                set_le16(&mut bgd_buf, bgd_off + 14, free_inodes - 1);
                fs.write_block(bgd_block, &bgd_buf)?;

                return Ok(group * fs.inodes_per_group + bit + 1);
            }
        }
    }
    Err(VfsError::NoSpace)
}

/// Free an inode back to the bitmap.
pub(crate) unsafe fn free_inode(fs: &Ext2Fs, ino: u32) -> Result<(), VfsError> {
    if ino < 2 { return Ok(()); } // never free root inode or inode 0
    let adj = ino - 1; // inodes are 1-based
    let group = adj / fs.inodes_per_group;
    let bit = adj % fs.inodes_per_group;

    let mut bgd_buf = [0u8; 4096];
    let mut bitmap_buf = [0u8; 4096];

    let bgd_offset = group * 32;
    let bgd_block = fs.bgdt_block as u64 + (bgd_offset / fs.block_size) as u64;
    let bgd_off = (bgd_offset % fs.block_size) as usize;
    fs.read_block(bgd_block, &mut bgd_buf)?;

    let inode_bitmap_block = le32(&bgd_buf, bgd_off + 4) as u64;
    fs.read_block(inode_bitmap_block, &mut bitmap_buf)?;

    let byte = bit as usize / 8;
    let mask = 1u8 << (bit % 8);
    bitmap_buf[byte] &= !mask;
    fs.write_block(inode_bitmap_block, &bitmap_buf)?;

    let free_inodes = le16(&bgd_buf, bgd_off + 14);
    set_le16(&mut bgd_buf, bgd_off + 14, free_inodes + 1);
    fs.write_block(bgd_block, &bgd_buf)?;

    Ok(())
}

/// Free a block back to the bitmap.
pub(crate) unsafe fn free_block(fs: &Ext2Fs, block_num: u32) -> Result<(), VfsError> {
    let first_data_block = if fs.block_size == 1024 { 1u32 } else { 0u32 };
    if block_num <= first_data_block { return Ok(()); } // never free superblock/boot block
    let adj = block_num - first_data_block;
    let group = adj / fs.blocks_per_group;
    let bit = adj % fs.blocks_per_group;

    let mut bgd_buf = [0u8; 4096];
    let mut bitmap_buf = [0u8; 4096];

    let bgd_offset = group * 32;
    let bgd_block = fs.bgdt_block as u64 + (bgd_offset / fs.block_size) as u64;
    let bgd_off = (bgd_offset % fs.block_size) as usize;
    fs.read_block(bgd_block, &mut bgd_buf)?;

    let bitmap_block = le32(&bgd_buf, bgd_off + 0) as u64;
    fs.read_block(bitmap_block, &mut bitmap_buf)?;

    let byte = bit as usize / 8;
    let mask = 1u8 << (bit % 8);
    bitmap_buf[byte] &= !mask;
    fs.write_block(bitmap_block, &bitmap_buf)?;

    let free_blocks = le16(&bgd_buf, bgd_off + 12);
    set_le16(&mut bgd_buf, bgd_off + 12, free_blocks + 1);
    fs.write_block(bgd_block, &bgd_buf)?;

    // Invalidate cache entry for the freed block so stale data isn't served
    let inner = &mut *fs.inner.get();
    for entry in inner.cache.iter_mut() {
        if entry.valid && entry.block_no == block_num as u64 {
            entry.valid = false;
            break;
        }
    }

    Ok(())
}
