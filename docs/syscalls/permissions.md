## Permissions & Ownership

### chmod / fchmod / fchmodat

`chmod(pathname, mode) → 0`
`fchmod(fd, mode) → 0`
`fchmodat(dirfd, pathname, mode, flags) → 0`

**Success**: Returns 0. Sets permission bits on file. New mode readable via `stat`.

**Errors**:
- `EACCES` — search permission denied on path component (path-based variants)
- `EBADF` — `fchmod`: fd not valid; `fchmodat`: dirfd not valid
- `EFAULT` — bad pathname pointer
- `EINVAL` — invalid mode; or `fchmodat` invalid flags
- `EIO` — I/O error
- `ELOOP` — too many symlinks
- `ENAMETOOLONG` — pathname too long
- `ENOENT` — path does not exist
- `ENOMEM` — out of kernel memory
- `ENOTDIR` — path component not a directory
- `EPERM` — caller does not own the file and is not root; or file is immutable
- `EROFS` — read-only filesystem

### chown / fchown / fchownat / lchown

`chown(pathname, owner, group) → 0`
`fchown(fd, owner, group) → 0`
`lchown(pathname, owner, group) → 0`
`fchownat(dirfd, pathname, owner, group, flags) → 0`

**Success**: Returns 0. Sets UID and/or GID on file. `-1` means "no change" for that field. `lchown` does not follow symlinks.

**Errors**:
- `EACCES` — search permission denied on path component
- `EBADF` — `fchown`: fd not valid; `fchownat`: dirfd not valid
- `EFAULT` — bad pathname pointer
- `EINVAL` — invalid UID or GID; `fchownat` invalid flags
- `EIO` — I/O error
- `ELOOP` — too many symlinks
- `ENAMETOOLONG` — pathname too long
- `ENOENT` — path does not exist
- `ENOMEM` — out of kernel memory
- `ENOTDIR` — path component not a directory
- `EPERM` — non-root caller tried to change UID; or changed GID to one not in supplemental groups; or file is immutable
- `EROFS` — read-only filesystem

### umask

`umask(mask) → previous_mask`

**Success**: Returns previous mask. Sets file creation mask. Never fails.

### access

`access(pathname, mode) → 0`

**Success**: Returns 0 if all requested access modes are granted. Checks against real UID/GID.

**Errors**: Same as `faccessat` (see File Metadata section).
