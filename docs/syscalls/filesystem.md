## Filesystem

### statfs / fstatfs

`statfs(path, buf) → 0`
`fstatfs(fd, buf) → 0`

**Success**: Returns 0. Fills `statfs` struct: `f_type` (filesystem magic), `f_bsize` (block size), `f_blocks` (total), `f_bfree` (free), `f_bavail` (free for non-root), `f_files` (total inodes), `f_ffree` (free inodes), `f_fsid`, `f_namelen`, `f_frsize`.

**Errors**:
- `EACCES` — search permission denied on path component (`statfs`)
- `EBADF` — fd not valid (`fstatfs`)
- `EFAULT` — bad pointer
- `EINTR` — interrupted by signal
- `EIO` — I/O error
- `ELOOP` — too many symlinks (`statfs`)
- `ENAMETOOLONG` — pathname too long (`statfs`)
- `ENOENT` — path does not exist (`statfs`)
- `ENOMEM` — insufficient memory
- `ENOSYS` — filesystem doesn't support statfs
- `ENOTDIR` — path component not a directory (`statfs`)
- `EOVERFLOW` — values too large for struct fields

### mount

`mount(source, target, filesystemtype, mountflags, data) → 0`

**Success**: Returns 0. Mounts filesystem.
- `source` → device or special name; `target` → mount point
- `filesystemtype` → "ext4", "tmpfs", "proc", "sysfs", etc.
- `MS_RDONLY` → mount read-only
- `MS_NOSUID` → ignore setuid/setgid bits
- `MS_NOEXEC` → disallow execution
- `MS_REMOUNT` → change flags on existing mount
- `MS_BIND` → bind mount (replicate subtree at another point)
- `MS_MOVE` → move existing mount point

**Errors**:
- `EACCES` — path component not searchable; or mounting read-only was required by flags; or device read-only
- `EBUSY` — `source` already mounted; or cannot remount read-only with open write fds; or mount point in use
- `EFAULT` — bad pointer
- `EINVAL` — `source` has superblock error; or `MS_REMOUNT` without existing mount; or `MS_MOVE` across filesystems; or bad flags
- `ELOOP` — too many symlinks
- `EMFILE` — too many mount points (system-wide)
- `ENAMETOOLONG` — pathname too long
- `ENODEV` — filesystem type not supported
- `ENOENT` — path does not exist
- `ENOMEM` — insufficient memory
- `ENOTBLK` — `source` required to be block device but is not
- `ENOTDIR` — target not a directory; or path component not a directory
- `EPERM` — caller lacks `CAP_SYS_ADMIN`

### umount / umount2

`umount(target) → 0`
`umount2(target, flags) → 0`

**Success**: Returns 0. Unmounts filesystem.
- `MNT_FORCE` → force unmount even with open files (may cause data loss)
- `MNT_DETACH` → lazy unmount; hide mount point but don't free until last reference gone
- `MNT_EXPIRE` → mark as expired; second call with same flag actually unmounts
- `UMOUNT_NOFOLLOW` → don't follow symlinks

**Errors**:
- `EAGAIN` — `MNT_EXPIRE` and mount not idle yet
- `EBUSY` — target still in use (open files, cwd of process, sub-mounts)
- `EFAULT` — bad pointer
- `EINVAL` — target not a mount point; or invalid flags
- `ENAMETOOLONG` — pathname too long
- `ENOENT` — path doesn't exist
- `ENOMEM` — insufficient memory
- `EPERM` — caller lacks `CAP_SYS_ADMIN`

### sync

`sync() → (void)`

**Success**: Returns void (always succeeds). Flushes all dirty file data and metadata to disk system-wide.

### syncfs

`syncfs(fd) → 0`

**Success**: Returns 0. Flushes dirty data for the filesystem containing fd.

**Errors**:
- `EBADF` — fd not valid
- `EIO` — I/O error during sync
- `ENOSPC` — no space for writes during sync
- `EDQUOT` — disk quota exceeded during sync

### fsync

`fsync(fd) → 0`

**Success**: Returns 0. Flushes all dirty data **and metadata** for fd to storage. Blocks until complete.

**Errors**:
- `EBADF` — fd not valid or not open for writing
- `EDQUOT` — disk quota exceeded during flush
- `EINVAL` — fd refers to special file that doesn't support sync
- `EIO` — I/O error during sync
- `ENOSPC` — no space on device during flush
- `EROFS` — fd on read-only filesystem (writes were cached but can't flush)

### fdatasync

`fdatasync(fd) → 0`

**Success**: Returns 0. Like `fsync` but only flushes data and metadata needed for data retrieval (skips timestamp-only updates).

**Errors**: Same as `fsync`.

### fallocate

`fallocate(fd, mode, offset, len) → 0`

**Success**: Returns 0. Allocates or manipulates disk space for fd.
- Default: pre-allocates `len` bytes starting at `offset`
- `FALLOC_FL_KEEP_SIZE` → don't extend file size beyond current
- `FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE` → deallocate blocks in range (create hole)
- `FALLOC_FL_COLLAPSE_RANGE` → remove range and close gap
- `FALLOC_FL_ZERO_RANGE` → zero the range (may use sparse storage)
- `FALLOC_FL_INSERT_RANGE` → insert hole, shifting existing data

**Errors**:
- `EBADF` — fd not valid or not open for writing
- `EFBIG` — offset + len exceeds max file size
- `EINTR` — interrupted by signal
- `EINVAL` — offset < 0; len ≤ 0; unsupported mode flags; or fd not a regular file
- `EIO` — I/O error
- `ENODEV` — fd not a regular file or directory
- `ENOSPC` — no space on device
- `ENOSYS` — filesystem doesn't support fallocate
- `EOPNOTSUPP` — filesystem doesn't support given mode
- `EPERM` — file is append-only or immutable
- `EROFS` — read-only filesystem
- `ESPIPE` — fd is a pipe
- `ETXTBSY` — fd is a swap file

### fadvise (posix_fadvise)

`posix_fadvise(fd, offset, len, advice) → 0`

**Success**: Returns 0. Advisory hint about expected I/O pattern.
- `POSIX_FADV_NORMAL` → default
- `POSIX_FADV_SEQUENTIAL` → will read sequentially
- `POSIX_FADV_RANDOM` → will read randomly
- `POSIX_FADV_NOREUSE` → data will be used only once
- `POSIX_FADV_WILLNEED` → data will be needed soon; trigger readahead
- `POSIX_FADV_DONTNEED` → data not needed; kernel may free pages

**Errors**:
- `EBADF` — fd not valid
- `EINVAL` — invalid `advice` value; or fd refers to pipe/FIFO
- `ESPIPE` — fd is a pipe
