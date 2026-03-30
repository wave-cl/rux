use crate::{FileSystem, FileName, InodeId, InodeStat, InodeType, VfsError, S_IFMT, S_IFLNK};

/// Maximum depth for parent tracking during path resolution.
const MAX_DEPTH: usize = 64;

/// Maximum symlink hops before returning ELOOP.
const SYMLOOP_MAX: usize = 8;

/// Resolve an absolute path to an inode ID.
///
/// - Path must start with `b'/'` (absolute).
/// - Handles `.` (current), `..` (parent), and normal components.
/// - Follows symlinks (up to SYMLOOP_MAX hops).
/// - Trailing slashes are ignored.
/// - Empty path returns `InvalidPath`.
#[inline]
pub fn resolve_path<F: FileSystem>(fs: &F, path: &[u8]) -> Result<InodeId, VfsError> {
    resolve_path_inner(fs, fs.root_inode(), path, SYMLOOP_MAX)
}

/// Resolve a path relative to a starting directory inode.
///
/// - If path starts with `/`, resolves from root (absolute).
/// - Otherwise, resolves from `start` (relative to CWD).
/// - Empty path returns `start` (the directory itself).
#[inline]
pub fn resolve_path_at<F: FileSystem>(
    fs: &F,
    start: InodeId,
    path: &[u8],
) -> Result<InodeId, VfsError> {
    if path.is_empty() {
        return Ok(start);
    }
    if path[0] == b'/' {
        return resolve_path_inner(fs, fs.root_inode(), path, SYMLOOP_MAX);
    }
    resolve_path_inner(fs, start, path, SYMLOOP_MAX)
}

fn resolve_path_inner<F: FileSystem>(
    fs: &F,
    start: InodeId,
    path: &[u8],
    symlinks_left: usize,
) -> Result<InodeId, VfsError> {
    if path.is_empty() {
        return Ok(start);
    }

    let root = fs.root_inode();
    let mut current = if path[0] == b'/' { root } else { start };

    // Stack tracks the chain of parents for ".." handling.
    let mut parent_stack = [root; MAX_DEPTH];
    let mut depth: usize = 0;

    let mut i = if path[0] == b'/' { 1 } else { 0 }; // skip leading '/' if absolute
    let len = path.len();

    while i < len {
        // Skip consecutive slashes.
        if path[i] == b'/' {
            i += 1;
            continue;
        }

        // Find end of component.
        let start = i;
        while i < len && path[i] != b'/' {
            i += 1;
        }
        let component = &path[start..i];

        if component == b"." {
            continue;
        }

        if component == b".." {
            if depth > 0 {
                current = parent_stack[depth - 1];
                depth -= 1;
            } else {
                current = root;
            }
            continue;
        }

        // Normal component: lookup in current directory.
        let name = FileName::new(component)?;

        if depth < MAX_DEPTH {
            parent_stack[depth] = current;
            depth += 1;
        } else {
            return Err(VfsError::InvalidPath);
        }

        current = fs.lookup(current, name)?;

        // Follow symlinks
        if is_symlink(fs, current) {
            if symlinks_left == 0 {
                return Err(VfsError::TooManySymlinks);
            }

            let mut link_buf = [0u8; 256];
            let link_len = fs.readlink(current, &mut link_buf)?;
            let target = &link_buf[..link_len];

            if !target.is_empty() && target[0] == b'/' {
                // Absolute symlink: rebuild full path = target + remaining
                let remaining = &path[i..];
                let mut full = [0u8; 512];
                let mut fp = 0;
                for &b in target { if fp < 512 { full[fp] = b; fp += 1; } }
                for &b in remaining { if fp < 512 { full[fp] = b; fp += 1; } }
                return resolve_path_inner(fs, root, &full[..fp], symlinks_left - 1);
            } else {
                // Relative symlink: look up target in the parent directory.
                // Parent is parent_stack[depth-1] (we pushed before lookup).
                let parent = if depth > 0 { parent_stack[depth - 1] } else { root };
                let target_name = FileName::new(target)?;
                current = fs.lookup(parent, target_name)?;
                // Don't increment depth — we're replacing the symlink inode
                // with the target inode at the same depth level.
                // If there are remaining path components, continue resolving.
                // (current might itself be a symlink — will be caught on next iteration)
            }
        }
    }

    Ok(current)
}

/// Resolve a path using a CWD inode for relative paths.
/// Returns the resolved inode ID, or a negative errno on failure.
pub fn resolve_with_cwd<F: FileSystem>(fs: &F, cwd: InodeId, path: &[u8]) -> Result<InodeId, i64> {
    resolve_path_at(fs, cwd, path).map_err(|_| -2i64)
}

/// Resolve a path to (parent_inode, basename).
/// Used by open/creat/unlink/mkdir to find the parent directory.
pub fn resolve_parent_and_name<'a, F: FileSystem>(
    fs: &F,
    cwd: InodeId,
    path: &'a [u8],
) -> Result<(InodeId, &'a [u8]), i64> {
    let mut last_slash = None;
    for j in 0..path.len() {
        if path[j] == b'/' { last_slash = Some(j); }
    }

    match last_slash {
        Some(0) => {
            // "/foo" → parent is root, name is everything after '/'
            let name = &path[1..];
            Ok((fs.root_inode(), name))
        }
        Some(s) => {
            // "/a/b/foo" or "a/b/foo" → resolve parent, name is after last slash
            let parent_path = &path[..s];
            let name = &path[s + 1..];
            match resolve_path_at(fs, cwd, parent_path) {
                Ok(parent_ino) => Ok((parent_ino, name)),
                Err(_) => Err(-2),
            }
        }
        None => {
            // "foo" (no slash) → parent is CWD
            Ok((cwd, path))
        }
    }
}

/// Check if an inode is a symlink by reading its stat.
fn is_symlink<F: FileSystem>(fs: &F, ino: InodeId) -> bool {
    let mut stat = InodeStat {
        ino: 0, mode: 0, nlink: 0, uid: 0, gid: 0, size: 0,
        blocks: 0, blksize: 0, _pad0: 0, atime: 0, mtime: 0, ctime: 0,
        dev: 0, rdev: 0,
    };
    if fs.stat(ino, &mut stat).is_err() {
        return false;
    }
    (stat.mode & S_IFMT) == S_IFLNK
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use super::*;
    use crate::ramfs::{RamFs, PAGE_SIZE};
    use crate::{FileSystem, FileName, VfsError};
    use rux_klib::PhysAddr;
    use rux_mm::{FrameAllocator, MemoryError, PageSize};

    struct MockAllocator {
        pages: Vec<*mut [u8; PAGE_SIZE]>,
    }

    impl MockAllocator {
        fn new() -> Self { Self { pages: Vec::new() } }
    }

    impl FrameAllocator for MockAllocator {
        fn alloc(&mut self, _size: PageSize) -> Result<PhysAddr, MemoryError> {
            let page = Box::new([0u8; PAGE_SIZE]);
            let ptr = Box::into_raw(page);
            self.pages.push(ptr);
            Ok(PhysAddr::new(ptr as usize))
        }
        fn dealloc(&mut self, addr: PhysAddr, _size: PageSize) {
            let ptr = addr.as_usize() as *mut [u8; PAGE_SIZE];
            if let Some(pos) = self.pages.iter().position(|&p| p == ptr) {
                self.pages.swap_remove(pos);
            }
            unsafe { drop(Box::from_raw(ptr)); }
        }
        fn available_frames(&self, _size: PageSize) -> usize { usize::MAX }
    }

    impl Drop for MockAllocator {
        fn drop(&mut self) {
            for &ptr in &self.pages {
                unsafe { drop(Box::from_raw(ptr)); }
            }
        }
    }

    fn setup() -> (Box<MockAllocator>, Box<RamFs>) {
        let mut alloc = Box::new(MockAllocator::new());
        let alloc_ptr: *mut dyn FrameAllocator = &mut *alloc as &mut dyn FrameAllocator;
        let mut fs = unsafe { RamFs::new_boxed(alloc_ptr) };
        // /foo (dir)
        let foo = fs.mkdir(0, FileName::new(b"foo").unwrap(), 0o755).unwrap();
        // /foo/bar (dir)
        let bar = fs.mkdir(foo, FileName::new(b"bar").unwrap(), 0o755).unwrap();
        // /foo/bar/baz.txt (file)
        fs.create(bar, FileName::new(b"baz.txt").unwrap(), 0o644).unwrap();
        // /hello.txt (file)
        fs.create(0, FileName::new(b"hello.txt").unwrap(), 0o644).unwrap();
        (alloc, fs)
    }

    #[test]
    fn resolve_root() {
        let (_alloc, fs) = setup();
        assert_eq!(resolve_path(&*fs, b"/").unwrap(), 0);
    }

    #[test]
    fn resolve_simple_file() {
        let (_alloc, fs) = setup();
        let ino = resolve_path(&*fs, b"/hello.txt").unwrap();
        let expected = fs.lookup(0, FileName::new(b"hello.txt").unwrap()).unwrap();
        assert_eq!(ino, expected);
    }

    #[test]
    fn resolve_nested() {
        let (_alloc, fs) = setup();
        let ino = resolve_path(&*fs, b"/foo/bar/baz.txt").unwrap();
        let foo = fs.lookup(0, FileName::new(b"foo").unwrap()).unwrap();
        let bar = fs.lookup(foo, FileName::new(b"bar").unwrap()).unwrap();
        let expected = fs.lookup(bar, FileName::new(b"baz.txt").unwrap()).unwrap();
        assert_eq!(ino, expected);
    }

    #[test]
    fn resolve_dot() {
        let (_alloc, fs) = setup();
        let ino = resolve_path(&*fs, b"/foo/./bar").unwrap();
        let foo = fs.lookup(0, FileName::new(b"foo").unwrap()).unwrap();
        let expected = fs.lookup(foo, FileName::new(b"bar").unwrap()).unwrap();
        assert_eq!(ino, expected);
    }

    #[test]
    fn resolve_dotdot() {
        let (_alloc, fs) = setup();
        // /foo/bar/.. => /foo
        let ino = resolve_path(&*fs, b"/foo/bar/..").unwrap();
        let expected = fs.lookup(0, FileName::new(b"foo").unwrap()).unwrap();
        assert_eq!(ino, expected);
    }

    #[test]
    fn resolve_dotdot_at_root() {
        let (_alloc, fs) = setup();
        // /.. => / (stays at root)
        assert_eq!(resolve_path(&*fs, b"/..").unwrap(), 0);
    }

    #[test]
    fn resolve_nonexistent() {
        let (_alloc, fs) = setup();
        assert_eq!(
            resolve_path(&*fs, b"/nonexistent"),
            Err(VfsError::NotFound)
        );
    }

    #[test]
    fn resolve_empty_path() {
        let (_alloc, fs) = setup();
        assert_eq!(resolve_path(&*fs, b""), Err(VfsError::InvalidPath));
    }

    #[test]
    fn resolve_relative_path_fails() {
        let (_alloc, fs) = setup();
        assert_eq!(resolve_path(&*fs, b"foo"), Err(VfsError::InvalidPath));
    }

    #[test]
    fn resolve_trailing_slash() {
        let (_alloc, fs) = setup();
        let ino = resolve_path(&*fs, b"/foo/").unwrap();
        let expected = fs.lookup(0, FileName::new(b"foo").unwrap()).unwrap();
        assert_eq!(ino, expected);
    }
}
