## Directories

### getcwd

`getcwd(buf, size) → buf`

**Success**: Returns pointer to buffer containing absolute pathname of cwd (null-terminated).

**Errors**:
- `EACCES` — search permission denied on a component of the path leading to cwd
- `EFAULT` — bad buffer pointer
- `EINVAL` — size is 0 and buf is not NULL
- `ENAMETOOLONG` — pathname exceeds given size
- `ENOENT` — cwd has been unlinked
- `ERANGE` — buffer too small to hold pathname

### chdir

`chdir(path) → 0`

**Success**: Returns 0. Changes cwd to given path.

**Errors**:
- `EACCES` — search permission denied on path component
- `EFAULT` — bad pathname pointer
- `EIO` — I/O error
- `ELOOP` — too many symlinks
- `ENAMETOOLONG` — pathname too long
- `ENOENT` — path does not exist
- `ENOMEM` — out of kernel memory
- `ENOTDIR` — path component or final component not a directory

### fchdir

`fchdir(fd) → 0`

**Success**: Returns 0. Changes cwd to directory referred to by fd.

**Errors**:
- `EACCES` — search permission denied on the directory
- `EBADF` — fd not valid
- `ENOTDIR` — fd does not refer to a directory

### mkdir / mkdirat

`mkdir(pathname, mode) → 0`
`mkdirat(dirfd, pathname, mode) → 0`

**Success**: Returns 0. Creates directory with given mode subject to umask.

**Errors**:
- `EACCES` — write or search permission denied on parent; or parent has sticky bit and caller doesn't own parent or new dir
- `EBADF` — `mkdirat`: dirfd not valid
- `EDQUOT` — disk quota exhausted
- `EEXIST` — path already exists (as any type)
- `EFAULT` — bad pathname pointer
- `ELOOP` — too many symlinks
- `EMLINK` — parent directory `nlink` would exceed limit
- `ENAMETOOLONG` — pathname too long
- `ENOENT` — parent directory does not exist
- `ENOMEM` — out of kernel memory
- `ENOSPC` — no room on device
- `ENOTDIR` — path component not a directory
- `EPERM` — filesystem does not support directory creation
- `EROFS` — read-only filesystem

### rmdir

`rmdir(pathname) → 0`

**Success**: Returns 0. Removes empty directory.

**Errors**:
- `EACCES` — write permission denied on parent; or search denied on path component; sticky bit restrictions
- `EBUSY` — directory is a mount point or is in use by the system
- `EFAULT` — bad pathname pointer
- `EINVAL` — pathname has `.` as last component
- `ELOOP` — too many symlinks
- `ENAMETOOLONG` — pathname too long
- `ENOENT` — path does not exist
- `ENOMEM` — out of kernel memory
- `ENOTDIR` — path component not a directory; or final component not a directory
- `ENOTEMPTY` — directory is not empty
- `EPERM` — filesystem doesn't support removal; or sticky bit on parent and caller doesn't own dir
- `EROFS` — read-only filesystem

### unlink / unlinkat

`unlink(pathname) → 0`
`unlinkat(dirfd, pathname, flags) → 0`

**Success**: Returns 0. Removes directory entry. File data freed when last link and last open fd are gone. `unlinkat` with `AT_REMOVEDIR` behaves like `rmdir`.

**Errors**:
- `EACCES` — write permission denied on parent; search denied on path; sticky bit restrictions
- `EBADF` — `unlinkat`: dirfd not valid
- `EBUSY` — file is in use by system (e.g. mount point)
- `EFAULT` — bad pathname pointer
- `EINVAL` — `unlinkat`: invalid flags
- `EIO` — I/O error
- `EISDIR` — path refers to a directory (for `unlink`; use `rmdir` or `AT_REMOVEDIR`)
- `ELOOP` — too many symlinks
- `ENAMETOOLONG` — pathname too long
- `ENOENT` — path does not exist
- `ENOMEM` — out of kernel memory
- `ENOTDIR` — path component not a directory
- `EPERM` — path refers to directory and caller is not privileged; or filesystem doesn't support unlinking
- `EROFS` — read-only filesystem

### rename / renameat

`rename(oldpath, newpath) → 0`
`renameat(olddirfd, oldpath, newdirfd, newpath) → 0`

**Success**: Returns 0. Atomically replaces newpath with oldpath.
- If newpath is existing file: old one removed atomically
- If newpath is existing non-empty directory → `ENOTEMPTY`
- If oldpath is directory: newpath must not exist, or be empty directory
- Renaming file to itself succeeds as no-op

**Errors**:
- `EACCES` — write permission denied on parent of oldpath or newpath; search denied on component
- `EBADF` — `renameat`: olddirfd or newdirfd not valid
- `EBUSY` — oldpath or newpath is a mount point
- `EDQUOT` — disk quota exhausted
- `EFAULT` — bad pathname pointer
- `EINVAL` — newpath is inside oldpath (would create loop)
- `EISDIR` — newpath is directory but oldpath is not
- `ELOOP` — too many symlinks
- `EMLINK` — oldpath already has maximum links; or new parent already has max
- `ENAMETOOLONG` — pathname too long
- `ENOENT` — old path does not exist; or new path parent does not exist
- `ENOMEM` — out of kernel memory
- `ENOSPC` — no room on device
- `ENOTDIR` — component not a directory; or oldpath is dir but newpath exists and is not dir
- `ENOTEMPTY` — newpath is non-empty directory
- `EPERM` — sticky bit restrictions; or can't rename directories across certain conditions
- `EROFS` — read-only filesystem
- `EXDEV` — oldpath and newpath are on different filesystems

### link / linkat

`link(oldpath, newpath) → 0`
`linkat(olddirfd, oldpath, newdirfd, newpath, flags) → 0`

**Success**: Returns 0. Creates new hard link (newpath) to existing file (oldpath). Inode `nlink` incremented.

**Errors**:
- `EACCES` — write permission denied on new parent; search denied on component
- `EBADF` — `linkat`: dirfd not valid
- `EDQUOT` — disk quota exhausted
- `EEXIST` — newpath already exists
- `EFAULT` — bad pathname pointer
- `EIO` — I/O error
- `ELOOP` — too many symlinks
- `EMLINK` — inode already at maximum link count
- `ENAMETOOLONG` — pathname too long
- `ENOENT` — oldpath does not exist; new parent doesn't exist
- `ENOMEM` — out of kernel memory
- `ENOSPC` — no room on device
- `ENOTDIR` — component not a directory
- `EPERM` — oldpath is a directory (hard links to directories not allowed without privilege); or filesystem doesn't support hard links
- `EROFS` — read-only filesystem
- `EXDEV` — oldpath and newpath on different filesystems

### symlink / symlinkat

`symlink(target, linkpath) → 0`
`symlinkat(target, newdirfd, linkpath) → 0`

**Success**: Returns 0. Creates symbolic link at linkpath containing target string.

**Errors**:
- `EACCES` — write permission denied on parent; search denied on component
- `EBADF` — `symlinkat`: dirfd not valid
- `EDQUOT` — disk quota exhausted
- `EEXIST` — linkpath already exists
- `EFAULT` — bad pointer
- `EIO` — I/O error
- `ELOOP` — too many symlinks in linkpath resolution
- `ENAMETOOLONG` — target or linkpath too long
- `ENOENT` — parent of linkpath doesn't exist
- `ENOMEM` — out of kernel memory
- `ENOSPC` — no room on device
- `ENOTDIR` — component of linkpath not a directory
- `EPERM` — filesystem doesn't support symlinks
- `EROFS` — read-only filesystem

### getdents64

`getdents64(fd, dirp, count) → bytes_read`

**Success**: Returns number of bytes read into buffer. Each entry: `d_ino`, `d_off`, `d_reclen`, `d_type`, `d_name`. Returns 0 at end of directory.

**Errors**:
- `EBADF` — fd not valid
- `EFAULT` — bad buffer pointer
- `EINVAL` — buffer too small for even one entry
- `ENOENT` — directory has been removed
- `ENOTDIR` — fd is not a directory
