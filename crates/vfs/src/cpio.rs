/// CPIO newc (SVR4) archive unpacker for initramfs.
///
/// Parses a cpio archive and extracts files, directories, and symlinks
/// into a RamFs. This is the same format Linux uses for initramfs.
///
/// Format per entry:
///   - 110-byte ASCII header ("070701" magic + 13 hex fields)
///   - filename (padded to 4-byte boundary)
///   - file data (padded to 4-byte boundary)
///   - Trailer: entry named "TRAILER!!!"

use crate::{FileSystem, FileName, S_IFMT, S_IFREG, S_IFDIR, S_IFLNK};

const MAGIC: &[u8; 6] = b"070701";
const HEADER_SIZE: usize = 110;

/// Parse an 8-character hex field from the header.
fn hex8(data: &[u8], offset: usize) -> u32 {
    let mut val = 0u32;
    for i in 0..8 {
        let b = data[offset + i];
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => 0,
        };
        val = (val << 4) | digit as u32;
    }
    val
}

/// Align up to 4-byte boundary.
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Resolve a path, creating parent directories as needed.
/// Returns the inode of the final component's parent and the basename.
fn resolve_or_create_parents<'a>(
    fs: &mut crate::ramfs::RamFs,
    path: &'a [u8],
) -> (u64, &'a [u8]) {
    let root = fs.root_inode();

    // Strip leading ./ or /
    let path = if path.len() >= 2 && path[0] == b'.' && path[1] == b'/' {
        &path[2..]
    } else if !path.is_empty() && path[0] == b'/' {
        &path[1..]
    } else {
        path
    };

    // Split into components
    let mut current = root;
    let mut last_slash = 0;
    for i in 0..path.len() {
        if path[i] == b'/' {
            last_slash = i;
        }
    }

    if last_slash == 0 {
        // No directory component — parent is root
        return (root, path);
    }

    // Walk/create each directory component
    let dir_path = &path[..last_slash];
    let basename = &path[last_slash + 1..];

    let mut start = 0;
    for i in 0..dir_path.len() {
        if dir_path[i] == b'/' || i == dir_path.len() - 1 {
            let end = if dir_path[i] == b'/' { i } else { i + 1 };
            let component = &dir_path[start..end];
            if component.is_empty() { start = i + 1; continue; }

            let fname = match FileName::new(component) {
                Ok(f) => f,
                Err(_) => { start = i + 1; continue; }
            };

            // Try lookup first, create if not found
            current = match fs.lookup(current, fname) {
                Ok(ino) => ino,
                Err(_) => {
                    match fs.mkdir(current, fname, 0o755) {
                        Ok(ino) => ino,
                        Err(_) => current, // already exists or error
                    }
                }
            };

            if dir_path[i] == b'/' {
                start = i + 1;
            }
        }
    }

    (current, basename)
}

/// Unpack a cpio newc archive into a RamFs.
///
/// `data` is the raw cpio archive bytes (uncompressed).
/// `log` is an optional logging callback.
pub fn unpack_cpio(
    fs: &mut crate::ramfs::RamFs,
    data: &[u8],
    log: Option<fn(&str)>,
) {
    let mut pos = 0usize;
    let mut count = 0usize;
    let mut dirs = 0usize;
    let mut files = 0usize;
    let mut syms = 0usize;

    while pos + HEADER_SIZE <= data.len() {
        // Verify magic
        if &data[pos..pos + 6] != MAGIC {
            if let Some(log_fn) = log {
                log_fn("rux: cpio: bad magic, stopping\n");
            }
            break;
        }

        // Parse header fields
        let mode = hex8(data, pos + 14);
        let filesize = hex8(data, pos + 54) as usize;
        let namesize = hex8(data, pos + 94) as usize;

        // Filename starts after header, padded to 4-byte boundary
        let name_start = pos + HEADER_SIZE;
        let name_end = name_start + namesize - 1; // exclude null terminator
        if name_end > data.len() { break; }
        let name = &data[name_start..name_end];

        // Data starts after filename, padded to 4-byte boundary
        let data_start = align4(name_start + namesize);
        let data_end = data_start + filesize;
        if data_end > data.len() { break; }
        let file_data = &data[data_start..data_end];

        // Next entry starts after data, padded to 4-byte boundary
        pos = align4(data_end);

        // Check for trailer
        if name == b"TRAILER!!!" {
            break;
        }

        // Skip "." entry
        if name == b"." {
            continue;
        }

        let file_type = mode & S_IFMT;

        let (parent, basename) = resolve_or_create_parents(fs, name);
        if basename.is_empty() { continue; }

        // Debug: log failed entries
        if file_type != S_IFDIR && file_type != S_IFREG && file_type != S_IFLNK {
            if let Some(log_fn) = log {
                log_fn("rux: cpio: unknown type ");
                let mut buf = [0u8; 10];
                log_fn(format_u32(&mut buf, file_type));
                log_fn("\n");
            }
            continue;
        }

        let fname = match FileName::new(basename) {
            Ok(f) => f,
            Err(_) => continue,
        };

        let perm = mode & 0o7777;

        if file_type == S_IFDIR {
            // Directory — create if not exists
            let _ = fs.mkdir(parent, fname, perm);
            count += 1; dirs += 1;
        } else if file_type == S_IFREG {
            // Regular file — create and write data
            match fs.create(parent, fname, perm | 0o100000) {
                Ok(ino) => {
                    // Write in 4K chunks
                    let mut offset = 0u64;
                    while (offset as usize) < file_data.len() {
                        let remaining = file_data.len() - offset as usize;
                        let chunk_len = remaining.min(4096);
                        let chunk = &file_data[offset as usize..offset as usize + chunk_len];
                        match fs.write(ino, offset, chunk) {
                            Ok(n) => offset += n as u64,
                            Err(_) => break,
                        }
                    }
                    count += 1; files += 1;
                }
                Err(_) => {}
            }
        } else if file_type == S_IFLNK {
            // Symlink — target is in file data
            let target = if filesize > 0 { file_data } else { b"" as &[u8] };
            let _ = fs.symlink(parent, fname, target);
            count += 1; syms += 1;
        }
    }

    if let Some(log_fn) = log {
        log_fn("rux: cpio: unpacked ");
        let mut buf = [0u8; 10];
        log_fn(format_u32(&mut buf, count as u32));
        log_fn(" entries (");
        log_fn(format_u32(&mut buf, dirs as u32));
        log_fn(" dirs, ");
        log_fn(format_u32(&mut buf, files as u32));
        log_fn(" files, ");
        log_fn(format_u32(&mut buf, syms as u32));
        log_fn(" symlinks)\n");
    }
}

/// Format a u32 as decimal into a buffer.
fn format_u32(buf: &mut [u8; 10], mut n: u32) -> &str {
    if n == 0 {
        buf[0] = b'0';
        return unsafe { core::str::from_utf8_unchecked(&buf[..1]) };
    }
    let mut i = 10;
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    unsafe { core::str::from_utf8_unchecked(&buf[i..]) }
}
