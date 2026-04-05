## Extended Attributes

### getxattr / lgetxattr / fgetxattr

`getxattr(path, name, value, size) → bytes`
`lgetxattr(path, name, value, size) → bytes`
`fgetxattr(fd, name, value, size) → bytes`

**Success**: Returns size of attribute value. Fills buffer.
- `lgetxattr` does not follow symlinks; `fgetxattr` operates on fd
- `size = 0` → returns required buffer size without filling

**Errors**:
- `E2BIG` — attribute value too large for buffer (some filesystems)
- `EACCES` — search permission denied on path component
- `EBADF` — `fgetxattr`: fd not valid
- `EFAULT` — bad pointer
- `ELOOP` — too many symlinks
- `ENAMETOOLONG` — pathname too long
- `ENODATA` — attribute does not exist
- `ENOENT` — path does not exist
- `ENOMEM` — insufficient memory
- `ENOTDIR` — path component not a directory
- `ENOTSUP` — filesystem doesn't support xattrs
- `ERANGE` — `size` > 0 but too small for the value

### setxattr / lsetxattr / fsetxattr

`setxattr(path, name, value, size, flags) → 0`
`lsetxattr(path, name, value, size, flags) → 0`
`fsetxattr(fd, name, value, size, flags) → 0`

**Success**: Returns 0.
- `XATTR_CREATE` → fail if attribute already exists
- `XATTR_REPLACE` → fail if attribute doesn't exist
- Default (flags=0) → create or replace

**Errors**:
- `EACCES` — permission denied
- `EDQUOT` — disk quota exceeded
- `EEXIST` — `XATTR_CREATE` and attribute already exists
- `EFAULT` — bad pointer
- `EINVAL` — invalid name (empty or too long)
- `ELOOP` — too many symlinks
- `ENAMETOOLONG` — pathname too long
- `ENODATA` — `XATTR_REPLACE` and attribute doesn't exist
- `ENOENT` — path does not exist
- `ENOMEM` — insufficient memory
- `ENOSPC` — no space for attribute
- `ENOTDIR` — path component not a directory
- `ENOTSUP` — filesystem doesn't support xattrs
- `EPERM` — file is immutable; or security namespace requires privilege
- `EROFS` — read-only filesystem

### listxattr / llistxattr / flistxattr

`listxattr(path, list, size) → bytes`
`llistxattr(path, list, size) → bytes`
`flistxattr(fd, list, size) → bytes`

**Success**: Returns total size of name list (null-separated). `size = 0` → required size.

**Errors**:
- `EACCES` — permission denied
- `EBADF` — `flistxattr`: fd not valid
- `EFAULT` — bad pointer
- `ELOOP` — too many symlinks
- `ENAMETOOLONG` — pathname too long
- `ENOENT` — path does not exist
- `ENOMEM` — insufficient memory
- `ENOTDIR` — path component not a directory
- `ENOTSUP` — filesystem doesn't support xattrs
- `ERANGE` — buffer too small

### removexattr / lremovexattr / fremovexattr

`removexattr(path, name) → 0`
`lremovexattr(path, name) → 0`
`fremovexattr(fd, name) → 0`

**Success**: Returns 0.

**Errors**:
- `EACCES` — permission denied
- `EBADF` — `fremovexattr`: fd not valid
- `EFAULT` — bad pointer
- `ELOOP` — too many symlinks
- `ENAMETOOLONG` — pathname too long
- `ENODATA` — attribute doesn't exist
- `ENOENT` — path does not exist
- `ENOMEM` — insufficient memory
- `ENOTDIR` — path component not a directory
- `ENOTSUP` — filesystem doesn't support xattrs
- `EPERM` — file is immutable
- `EROFS` — read-only filesystem
