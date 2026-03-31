//! Linux getdents64 packing: read directory entries into a Linux dirent64 buffer.

use crate::{FileSystem, DirEntry, InodeType, InodeId};

/// Pack directory entries into a Linux `dirent64` buffer.
///
/// Reads entries from `dir_ino` starting at `*offset`, packs them into the
/// buffer at `buf` (up to `bufsize` bytes), and advances `*offset`.
/// Returns the number of bytes written, or 0 if no entries remain.
///
/// # Safety
/// `buf` must point to a writable buffer of at least `bufsize` bytes.
pub unsafe fn pack_getdents64(
    fs: &mut dyn FileSystem,
    dir_ino: InodeId,
    buf: *mut u8,
    bufsize: usize,
    offset: &mut usize,
) -> isize {
    let mut pos = 0usize;

    loop {
        let mut entry = core::mem::zeroed::<DirEntry>();
        match fs.readdir(dir_ino, *offset, &mut entry) {
            Ok(true) => {
                let nlen = entry.name_len as usize;
                // dirent64: ino(8) + off(8) + reclen(2) + type(1) + name(nlen+1)
                let reclen = ((19 + nlen + 1) + 7) & !7; // 8-byte align
                if pos + reclen > bufsize { break; }
                *((buf.add(pos)) as *mut u64) = entry.ino;
                *((buf.add(pos + 8)) as *mut u64) = (*offset + 1) as u64;
                *((buf.add(pos + 16)) as *mut u16) = reclen as u16;
                let dtype: u8 = match entry.kind {
                    InodeType::File => 8,
                    InodeType::Directory => 4,
                    InodeType::Symlink => 10,
                    _ => 0,
                };
                *buf.add(pos + 18) = dtype;
                for i in 0..nlen { *buf.add(pos + 19 + i) = entry.name[i]; }
                *buf.add(pos + 19 + nlen) = 0;
                pos += reclen;
                *offset += 1;
            }
            _ => break,
        }
    }
    pos as isize
}
