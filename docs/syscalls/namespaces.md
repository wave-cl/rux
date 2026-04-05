## Namespaces

### chroot

`chroot(path) → 0`

**Success**: Returns 0. Changes root directory to given path.
- Does not change cwd; process may be outside new root
- Requires `CAP_SYS_CHROOT`

**Errors**:
- `EACCES` — search permission denied
- `EFAULT` — bad pointer
- `EIO` — I/O error
- `ELOOP` — too many symlinks
- `ENAMETOOLONG` — pathname too long
- `ENOENT` — path doesn't exist
- `ENOMEM` — insufficient memory
- `ENOTDIR` — component or target not a directory
- `EPERM` — caller lacks `CAP_SYS_CHROOT`

### pivot_root

`pivot_root(new_root, put_old) → 0`

**Success**: Returns 0. Swaps root filesystem.
- `new_root` becomes root; old root moved to `put_old`
- Both must be directories and mount points
- Requires `CAP_SYS_ADMIN`

**Errors**:
- `EBUSY` — `new_root` or `put_old` already on current root; or `put_old` not under `new_root`
- `EINVAL` — `new_root` not a mount point; or `put_old` not under `new_root`; or current root is rootfs
- `ENOTDIR` — `new_root` or `put_old` not a directory
- `EPERM` — caller lacks `CAP_SYS_ADMIN`
