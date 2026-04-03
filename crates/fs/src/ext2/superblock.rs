//! ext2 superblock parsing.

use crate::VfsError;

const EXT2_MAGIC: u16 = 0xEF53;

/// Parsed superblock fields we need.
pub(crate) struct SuperblockInfo {
    pub block_size: u32,
    pub inodes_per_group: u32,
    pub blocks_per_group: u32,
    pub inode_size: u16,
    pub inode_count: u32,
}

/// Read a little-endian u16 from a byte slice.
fn le16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

/// Read a little-endian u32 from a byte slice.
fn le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Parse the 1024-byte superblock buffer.
pub(crate) fn parse(buf: &[u8]) -> Result<SuperblockInfo, VfsError> {
    if buf.len() < 1024 {
        return Err(VfsError::IoError);
    }

    let magic = le16(buf, 56);
    if magic != EXT2_MAGIC {
        return Err(VfsError::IoError);
    }

    let s_log_block_size = le32(buf, 24);
    let block_size = 1024u32 << s_log_block_size;

    let inode_count = le32(buf, 0);
    let inodes_per_group = le32(buf, 40);
    let blocks_per_group = le32(buf, 32);

    // Inode size: at offset 88 in revision >= 1, default 128
    let rev_level = le32(buf, 76);
    let inode_size = if rev_level >= 1 {
        le16(buf, 88)
    } else {
        128
    };

    Ok(SuperblockInfo {
        block_size,
        inodes_per_group,
        blocks_per_group,
        inode_size,
        inode_count,
    })
}
