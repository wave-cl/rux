//! ext2 directory entry parsing.

use crate::{InodeId, DirEntry, InodeType, VfsError};
use super::Ext2Fs;
use super::inode;

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
pub(crate) unsafe fn readdir(
    fs: &Ext2Fs,
    dir_ino: u32,
    offset: usize,
    entry: &mut DirEntry,
) -> Result<bool, VfsError> {
    let raw = inode::read_raw(fs, dir_ino)?;
    let size = raw.size as usize;
    let bs = fs.block_size as usize;

    if offset >= size {
        return Ok(false);
    }

    let mut buf = [0u8; 4096];
    let mut pos = offset;

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
            entry.ino = d_ino as InodeId;
            entry.kind = file_type_to_inode_type(file_type);
            entry.name_len = name_len.min(255) as u8;
            entry.name[..entry.name_len as usize]
                .copy_from_slice(&buf[off + 8..off + 8 + entry.name_len as usize]);
            return Ok(true);
        }

        pos += rec_len;
    }

    Ok(false)
}
