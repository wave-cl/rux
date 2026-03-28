use crate::{FileSystem, FileName, InodeId, VfsError};

/// Maximum depth for parent tracking during path resolution.
const MAX_DEPTH: usize = 64;

/// Resolve an absolute path to an inode ID.
///
/// - Path must start with `b'/'` (absolute).
/// - Handles `.` (current), `..` (parent), and normal components.
/// - Trailing slashes are ignored.
/// - Empty path returns `InvalidPath`.
#[inline]
pub fn resolve_path<F: FileSystem>(fs: &F, path: &[u8]) -> Result<InodeId, VfsError> {
    if path.is_empty() {
        return Err(VfsError::InvalidPath);
    }
    if path[0] != b'/' {
        return Err(VfsError::InvalidPath);
    }

    let root = fs.root_inode();
    let mut current = root;

    // Stack tracks the chain of parents for ".." handling.
    // parent_stack[i] is the parent of the directory at depth i.
    let mut parent_stack = [root; MAX_DEPTH];
    let mut depth: usize = 0;

    let mut i = 1; // skip leading '/'
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
            // Go to parent: pop from stack.
            if depth > 0 {
                current = parent_stack[depth - 1];
                depth -= 1;
            } else {
                // At root, ".." stays at root.
                current = root;
            }
            continue;
        }

        // Normal component: lookup in current directory.
        let name = FileName::new(component)?;

        // Push current onto parent stack before descending.
        if depth < MAX_DEPTH {
            parent_stack[depth] = current;
            depth += 1;
        } else {
            return Err(VfsError::InvalidPath);
        }

        current = fs.lookup(current, name)?;
    }

    Ok(current)
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
