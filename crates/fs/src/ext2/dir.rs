//! ext2 directory entry parsing.

use crate::{InodeId, DirEntry, InodeType, VfsError};
use super::Ext2Fs;
use super::inode;

pub(crate) fn set_le16(buf: &mut [u8], off: usize, val: u16) {
    let b = val.to_le_bytes(); buf[off] = b[0]; buf[off+1] = b[1];
}
pub(crate) fn set_le32(buf: &mut [u8], off: usize, val: u32) {
    let b = val.to_le_bytes(); buf[off] = b[0]; buf[off+1] = b[1]; buf[off+2] = b[2]; buf[off+3] = b[3];
}

fn le16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// ext2 directory entry file types (from d_file_type field).
fn file_type_to_inode_type(ft: u8) -> InodeType {
    match ft {
        1 => InodeType::File,
        2 => InodeType::Directory,
        7 => InodeType::Symlink,
        _ => InodeType::File,
    }
}

/// Look up a name in a directory. Returns the inode number.
pub(crate) unsafe fn lookup(fs: &Ext2Fs, dir_ino: u32, name: &[u8]) -> Result<u32, VfsError> {
    let raw = inode::read_raw(fs, dir_ino)?;
    if inode::mode_to_type(raw.mode) != InodeType::Directory {
        return Err(VfsError::NotADirectory);
    }

    let size = raw.size as u64;
    let bs = fs.block_size as usize;
    let mut buf = [0u8; 4096];
    let mut pos: u64 = 0;

    while pos < size {
        // Read the block containing this position
        let file_block = (pos / bs as u64) as u32;
        let phys_block = super::block::translate(fs, &raw, file_block)?;
        if phys_block == 0 { break; }
        fs.read_block(phys_block as u64, &mut buf)?;

        let mut off = (pos % bs as u64) as usize;
        while off < bs && (pos + off as u64 - (pos / bs as u64) * bs as u64) < size {
            if off + 8 > bs { break; }
            let d_ino = le32(&buf, off);
            let rec_len = le16(&buf, off + 4) as usize;
            let name_len = buf[off + 6] as usize;

            if rec_len == 0 { break; } // corrupted

            if d_ino != 0 && name_len == name.len() {
                let entry_name = &buf[off + 8..off + 8 + name_len];
                if entry_name == name {
                    return Ok(d_ino);
                }
            }

            off += rec_len;
        }
        pos = (pos / bs as u64 + 1) * bs as u64;
    }

    Err(VfsError::NotFound)
}

/// Read directory entries starting at `offset` (byte offset into dir data).
/// Writes the next entry into `entry` and returns true. Returns false when done.
/// Cache for readdir: remembers the byte position of the last returned entry
/// so sequential readdir calls don't restart from byte 0 every time.
/// This turns O(N²) directory listing into O(N).
static mut READDIR_CACHE: (u32, usize, usize) = (0, 0, 0); // (dir_ino, last_idx, last_byte_pos)

pub(crate) unsafe fn readdir(
    fs: &Ext2Fs,
    dir_ino: u32,
    offset: usize,
    entry: &mut DirEntry,
) -> Result<bool, VfsError> {
    let raw = inode::read_raw(fs, dir_ino)?;
    let size = raw.size as usize;
    let bs = fs.block_size as usize;

    // Use cached byte position if this is a sequential read of the same directory
    let (start_pos, start_idx) = if READDIR_CACHE.0 == dir_ino
        && READDIR_CACHE.1 < offset
        && offset == READDIR_CACHE.1 + 1
    {
        (READDIR_CACHE.2, READDIR_CACHE.1 + 1)
    } else if offset == 0 {
        (0, 0)
    } else if READDIR_CACHE.0 == dir_ino && READDIR_CACHE.1 == offset {
        // Re-reading same entry (shouldn't happen but handle it)
        // Walk from cached position of previous entry
        let prev_offset = if offset > 0 { offset - 1 } else { 0 };
        if READDIR_CACHE.1 == prev_offset { (READDIR_CACHE.2, prev_offset) }
        else { (0, 0) }
    } else {
        (0, 0) // non-sequential: restart from beginning
    };

    let mut buf = [0u8; 4096];
    let mut pos = start_pos;
    let mut idx = start_idx;

    while pos < size {
        let file_block = (pos / bs) as u32;
        let phys_block = super::block::translate(fs, &raw, file_block)?;
        if phys_block == 0 { return Ok(false); }
        fs.read_block(phys_block as u64, &mut buf)?;

        let off = pos % bs;
        if off + 8 > bs { pos = (pos / bs + 1) * bs; continue; }

        let d_ino = le32(&buf, off);
        let rec_len = le16(&buf, off + 4) as usize;
        let name_len = buf[off + 6] as usize;
        let file_type = buf[off + 7];

        if rec_len == 0 { return Ok(false); }

        if d_ino != 0 && name_len > 0 {
            if idx == offset {
                entry.ino = d_ino as InodeId;
                entry.kind = file_type_to_inode_type(file_type);
                entry.name_len = name_len.min(255) as u8;
                entry.name[..entry.name_len as usize]
                    .copy_from_slice(&buf[off + 8..off + 8 + entry.name_len as usize]);
                // Cache position for next sequential call
                READDIR_CACHE = (dir_ino, offset, pos + rec_len);
                return Ok(true);
            }
            idx += 1;
        }

        pos += rec_len;
    }

    // Reset cache at end of directory
    READDIR_CACHE = (0, 0, 0);
    Ok(false)
}

/// Add a directory entry. Finds space in existing blocks or allocates new one.
pub(crate) unsafe fn add_entry(
    fs: &Ext2Fs, dir_ino: u32, child_ino: u32, name: &[u8], file_type: u8,
) -> Result<(), VfsError> {
    let mut raw = inode::read_raw(fs, dir_ino)?;
    let bs = fs.block_size as usize;
    let dir_size = raw.size as usize;
    let needed = ((8 + name.len() + 3) / 4) * 4; // align to 4

    let mut buf = [0u8; 4096];
    let num_blocks = (dir_size + bs - 1) / bs;

    // Try to find space in existing blocks
    for blk_idx in 0..num_blocks {
        let phys = super::block::translate(fs, &raw, blk_idx as u32)?;
        if phys == 0 { continue; }
        fs.read_block(phys as u64, &mut buf)?;

        let mut off = 0usize;
        while off < bs {
            let rec_len = le16(&buf, off + 4) as usize;
            if rec_len == 0 { break; }
            let d_ino = le32(&buf, off);
            let d_name_len = buf[off + 6] as usize;
            let actual_len = ((8 + d_name_len + 3) / 4) * 4;

            // Check for slack space after this entry
            if d_ino != 0 && rec_len >= actual_len + needed {
                // Split: shrink current entry, add new entry in the slack
                let new_off = off + actual_len;
                let new_rec_len = rec_len - actual_len;

                // Shrink current
                set_le16(&mut buf, off + 4, actual_len as u16);

                // Write new entry
                set_le32(&mut buf, new_off, child_ino);
                set_le16(&mut buf, new_off + 4, new_rec_len as u16);
                buf[new_off + 6] = name.len() as u8;
                buf[new_off + 7] = file_type;
                buf[new_off + 8..new_off + 8 + name.len()].copy_from_slice(name);

                fs.write_block(phys as u64, &buf)?;
                return Ok(());
            }

            // Deleted entry — reuse if big enough
            if d_ino == 0 && rec_len >= needed {
                set_le32(&mut buf, off, child_ino);
                buf[off + 6] = name.len() as u8;
                buf[off + 7] = file_type;
                buf[off + 8..off + 8 + name.len()].copy_from_slice(name);
                fs.write_block(phys as u64, &buf)?;
                return Ok(());
            }

            off += rec_len;
        }
    }

    // No space in existing blocks — allocate a new one
    let new_block = super::alloc::alloc_block(fs)?;
    let new_blk_idx = num_blocks as u32;
    super::block::assign_block(fs, &mut raw, new_blk_idx, new_block)?;
    raw.size += fs.block_size;
    raw.blocks += (fs.block_size / 512) as u32;
    inode::write_raw(fs, dir_ino, &raw)?;

    // Initialize new block with single entry spanning the whole block
    let mut new_buf = [0u8; 4096];
    set_le32(&mut new_buf, 0, child_ino);
    set_le16(&mut new_buf, 4, bs as u16); // rec_len = whole block
    new_buf[6] = name.len() as u8;
    new_buf[7] = file_type;
    new_buf[8..8 + name.len()].copy_from_slice(name);
    fs.write_block(new_block as u64, &new_buf)?;

    Ok(())
}

/// Remove a directory entry by name. Marks it as deleted (ino=0) and
/// merges with the previous entry if possible.
pub(crate) unsafe fn remove_entry(
    fs: &Ext2Fs, dir_ino: u32, name: &[u8],
) -> Result<u32, VfsError> {
    let raw = inode::read_raw(fs, dir_ino)?;
    let bs = fs.block_size as usize;
    let dir_size = raw.size as usize;
    let mut buf = [0u8; 4096];

    let num_blocks = (dir_size + bs - 1) / bs;
    for blk_idx in 0..num_blocks {
        let phys = super::block::translate(fs, &raw, blk_idx as u32)?;
        if phys == 0 { continue; }
        fs.read_block(phys as u64, &mut buf)?;

        let mut off = 0usize;
        let mut prev_off = 0usize;

        while off < bs {
            let d_ino = le32(&buf, off);
            let rec_len = le16(&buf, off + 4) as usize;
            if rec_len == 0 { break; }
            let d_name_len = buf[off + 6] as usize;

            if d_ino != 0 && d_name_len == name.len() {
                let entry_name = &buf[off + 8..off + 8 + d_name_len];
                if entry_name == name {
                    // Found: merge with previous entry if possible
                    if off != prev_off {
                        let prev_rec = le16(&buf, prev_off + 4) as usize;
                        set_le16(&mut buf, prev_off + 4, (prev_rec + rec_len) as u16);
                    }
                    // Clear inode
                    set_le32(&mut buf, off, 0);
                    fs.write_block(phys as u64, &buf)?;
                    return Ok(d_ino);
                }
            }

            prev_off = off;
            off += rec_len;
        }
    }
    Err(VfsError::NotFound)
}
