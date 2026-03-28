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
    use super::*;
    use crate::ramfs::RamFs;
    use crate::{FileSystem, FileName, VfsError};

    fn setup() -> Box<RamFs> {
        let mut fs = RamFs::new_boxed();
        // /foo (dir)
        let foo = fs.mkdir(0, FileName::new(b"foo").unwrap(), 0o755).unwrap();
        // /foo/bar (dir)
        let bar = fs.mkdir(foo, FileName::new(b"bar").unwrap(), 0o755).unwrap();
        // /foo/bar/baz.txt (file)
        fs.create(bar, FileName::new(b"baz.txt").unwrap(), 0o644).unwrap();
        // /hello.txt (file)
        fs.create(0, FileName::new(b"hello.txt").unwrap(), 0o644).unwrap();
        fs
    }

    #[test]
    fn resolve_root() {
        let fs = setup();
        assert_eq!(resolve_path(&*fs, b"/").unwrap(), 0);
    }

    #[test]
    fn resolve_simple_file() {
        let fs = setup();
        let ino = resolve_path(&*fs, b"/hello.txt").unwrap();
        let expected = fs.lookup(0, FileName::new(b"hello.txt").unwrap()).unwrap();
        assert_eq!(ino, expected);
    }

    #[test]
    fn resolve_nested() {
        let fs = setup();
        let ino = resolve_path(&*fs, b"/foo/bar/baz.txt").unwrap();
        let foo = fs.lookup(0, FileName::new(b"foo").unwrap()).unwrap();
        let bar = fs.lookup(foo, FileName::new(b"bar").unwrap()).unwrap();
        let expected = fs.lookup(bar, FileName::new(b"baz.txt").unwrap()).unwrap();
        assert_eq!(ino, expected);
    }

    #[test]
    fn resolve_dot() {
        let fs = setup();
        let ino = resolve_path(&*fs, b"/foo/./bar").unwrap();
        let foo = fs.lookup(0, FileName::new(b"foo").unwrap()).unwrap();
        let expected = fs.lookup(foo, FileName::new(b"bar").unwrap()).unwrap();
        assert_eq!(ino, expected);
    }

    #[test]
    fn resolve_dotdot() {
        let fs = setup();
        // /foo/bar/.. => /foo
        let ino = resolve_path(&*fs, b"/foo/bar/..").unwrap();
        let expected = fs.lookup(0, FileName::new(b"foo").unwrap()).unwrap();
        assert_eq!(ino, expected);
    }

    #[test]
    fn resolve_dotdot_at_root() {
        let fs = setup();
        // /.. => / (stays at root)
        assert_eq!(resolve_path(&*fs, b"/..").unwrap(), 0);
    }

    #[test]
    fn resolve_nonexistent() {
        let fs = setup();
        assert_eq!(
            resolve_path(&*fs, b"/nonexistent"),
            Err(VfsError::NotFound)
        );
    }

    #[test]
    fn resolve_empty_path() {
        let fs = setup();
        assert_eq!(resolve_path(&*fs, b""), Err(VfsError::InvalidPath));
    }

    #[test]
    fn resolve_relative_path_fails() {
        let fs = setup();
        assert_eq!(resolve_path(&*fs, b"foo"), Err(VfsError::InvalidPath));
    }

    #[test]
    fn resolve_trailing_slash() {
        let fs = setup();
        let ino = resolve_path(&*fs, b"/foo/").unwrap();
        let expected = fs.lookup(0, FileName::new(b"foo").unwrap()).unwrap();
        assert_eq!(ino, expected);
    }
}
