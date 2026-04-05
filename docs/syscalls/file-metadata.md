## File Metadata

### stat / lstat / fstat / fstatat

`stat(pathname, statbuf) → 0`
`lstat(pathname, statbuf) → 0`
`fstat(fd, statbuf) → 0`
`fstatat(dirfd, pathname, statbuf, flags) → 0`

**Success**: Fills `stat` struct: `st_dev`, `st_ino`, `st_mode`, `st_nlink`, `st_uid`, `st_gid`, `st_rdev`, `st_size`, `st_blksize`, `st_blocks`, `st_atime`, `st_mtime`, `st_ctime`.
- `stat` follows symlinks; `lstat` does not (returns link's own metadata)
- `fstat` operates on open fd
- `fstatat` combines dirfd-relative path with `AT_EMPTY_PATH`, `AT_SYMLINK_NOFOLLOW` flags
- Pipe fd → `S_IFIFO`, `st_size = 0`
- Char device fd → `S_IFCHR`
- Symlink via `lstat` → `S_IFLNK`, `st_size` = length of target string

**Errors**:
- `EACCES` — search permission denied on path component
- `EBADF` — `fstat`: fd not valid; `fstatat`: dirfd not valid (with relative path)
- `EFAULT` — bad pathname or stat buffer pointer
- `EINVAL` — `fstatat`: invalid flags
- `ELOOP` — too many symlinks
- `ENAMETOOLONG` — pathname too long
- `ENOENT` — path component does not exist; or path is empty and `AT_EMPTY_PATH` not set
- `ENOMEM` — out of kernel memory
- `ENOTDIR` — path component not a directory; or `fstatat` dirfd not a directory
- `EOVERFLOW` — file size/inode/etc. doesn't fit in stat struct fields

### statx

`statx(dirfd, pathname, flags, mask, statxbuf) → 0`

**Success**: Fills `statx` struct. Superset of `stat` with creation time (`stx_btime`), mount ID, attribute flags. `stx_mask` indicates which fields are filled based on requested mask.

**Errors**: Same as `fstatat` plus:
- `EINVAL` — invalid flags or mask

### readlink / readlinkat

`readlink(pathname, buf, bufsiz) → bytes_placed`
`readlinkat(dirfd, pathname, buf, bufsiz) → bytes_placed`

**Success**: Places symlink target in buffer (not null-terminated). Returns number of bytes placed. If buffer is too small, result is silently truncated.

**Errors**:
- `EACCES` — search permission denied on path component
- `EBADF` — `readlinkat`: dirfd not valid
- `EFAULT` — bad pathname or buffer pointer
- `EINVAL` — path is not a symlink; or `bufsiz` ≤ 0
- `EIO` — I/O error
- `ELOOP` — too many symlinks in prefix
- `ENAMETOOLONG` — pathname too long
- `ENOENT` — path does not exist
- `ENOMEM` — out of kernel memory
- `ENOTDIR` — path component not a directory

### faccessat

`faccessat(dirfd, pathname, mode, flags) → 0`

**Success**: Returns 0 if access is permitted.
- `F_OK` checks existence; `R_OK`, `W_OK`, `X_OK` check permissions
- By default checks against real UID/GID (not effective)
- `AT_EACCESS` flag checks against effective UID/GID

**Errors**:
- `EACCES` — requested access denied; or search permission denied on path component
- `EBADF` — dirfd not valid
- `EFAULT` — bad pathname pointer
- `EINVAL` — invalid mode or flags
- `ELOOP` — too many symlinks
- `ENAMETOOLONG` — pathname too long
- `ENOENT` — path does not exist
- `ENOMEM` — out of kernel memory
- `ENOTDIR` — path component not a directory
- `EROFS` — `W_OK` on file on read-only filesystem
- `ETXTBSY` — `W_OK` on currently-executing executable

### utimensat

`utimensat(dirfd, pathname, times[2], flags) → 0`

**Success**: Returns 0. Sets atime and/or mtime on file.
- `UTIME_NOW` → set to current time
- `UTIME_OMIT` → do not change that timestamp
- `NULL` times → set both to current time
- `AT_SYMLINK_NOFOLLOW` → operate on the symlink itself

**Errors**:
- `EACCES` — times is not NULL and caller does not own file, is not privileged, and file is not writable
- `EBADF` — dirfd not valid
- `EFAULT` — bad pathname or times pointer
- `EINVAL` — invalid `tv_nsec` value; invalid flags
- `ELOOP` — too many symlinks
- `ENAMETOOLONG` — pathname too long
- `ENOENT` — path does not exist
- `ENOTDIR` — path component not a directory
- `EPERM` — caller tried to change timestamps to specific values but doesn't own file and is not privileged
- `EROFS` — read-only filesystem
- `ESRCH` — search permission denied on path component
