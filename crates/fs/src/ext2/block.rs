//! ext2 block addressing: logical file block → physical disk block.
//!
//! i_block[0..11]  = direct blocks
//! i_block[12]     = single-indirect block (points to block of u32 block numbers)
//! i_block[13]     = double-indirect block (points to block of indirect blocks)
//! i_block[14]     = triple-indirect block (not supported — files up to ~4GB)

use crate::VfsError;
use super::Ext2Fs;
use super::inode::RawInode;

fn le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Translate a logical file block number to a physical disk block number.
pub(crate) unsafe fn translate(fs: &Ext2Fs, inode: &RawInode, file_block: u32) -> Result<u32, VfsError> {
    let ptrs_per_block = fs.block_size / 4; // number of u32 pointers per block

    // Direct blocks: 0-11
    if file_block < 12 {
        return Ok(inode.block[file_block as usize]);
    }

    // Single-indirect: block 12..12+ptrs_per_block
    let fb = file_block - 12;
    if fb < ptrs_per_block {
        let indirect_block = inode.block[12];
        if indirect_block == 0 { return Ok(0); }
        let mut buf = [0u8; 4096];
        fs.read_block(indirect_block as u64, &mut buf)?;
        return Ok(le32(&buf, fb as usize * 4));
    }

    // Double-indirect: block 12+N..12+N+N*N
    let fb = fb - ptrs_per_block;
    if fb < ptrs_per_block * ptrs_per_block {
        let dindirect_block = inode.block[13];
        if dindirect_block == 0 { return Ok(0); }
        let mut buf = [0u8; 4096];
        fs.read_block(dindirect_block as u64, &mut buf)?;
        let idx1 = fb / ptrs_per_block;
        let indirect_block = le32(&buf, idx1 as usize * 4);
        if indirect_block == 0 { return Ok(0); }
        fs.read_block(indirect_block as u64, &mut buf)?;
        let idx2 = fb % ptrs_per_block;
        return Ok(le32(&buf, idx2 as usize * 4));
    }

    // Triple-indirect not supported
    Err(VfsError::IoError)
}

/// Read file data starting at `offset` into `buf`. Returns bytes read.
pub(crate) unsafe fn read_file(
    fs: &Ext2Fs,
    ino: u32,
    offset: u64,
    buf: &mut [u8],
) -> Result<usize, VfsError> {
    let inode = super::inode::read_raw(fs, ino)?;
    let file_size = ((inode.size_high as u64) << 32) | inode.size as u64;

    if offset >= file_size {
        return Ok(0);
    }

    let bs = fs.block_size as usize;
    let to_read = buf.len().min((file_size - offset) as usize);
    let mut read = 0usize;
    let mut block_buf = [0u8; 4096];

    while read < to_read {
        let cur_offset = offset + read as u64;
        let file_block = (cur_offset / bs as u64) as u32;
        let off_in_block = (cur_offset % bs as u64) as usize;
        let chunk = (bs - off_in_block).min(to_read - read);

        let phys = translate(fs, &inode, file_block)?;
        if phys == 0 {
            // Sparse: fill with zeros
            for i in 0..chunk { buf[read + i] = 0; }
        } else {
            fs.read_block(phys as u64, &mut block_buf)?;
            buf[read..read + chunk].copy_from_slice(&block_buf[off_in_block..off_in_block + chunk]);
        }

        read += chunk;
    }

    Ok(read)
}
