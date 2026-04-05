## Miscellaneous

### getrandom

`getrandom(buf, buflen, flags) → bytes_written`

**Success**: Returns bytes written to buffer.
- `GRND_RANDOM` → use `/dev/random` (blocks until entropy available)
- `GRND_NONBLOCK` → `EAGAIN` instead of blocking when entropy low
- `GRND_INSECURE` → never blocks; may return non-random data early in boot

**Errors**:
- `EAGAIN` — `GRND_NONBLOCK` and entropy pool not ready
- `EFAULT` — bad buffer pointer
- `EINTR` — interrupted by signal while blocking
- `EINVAL` — unknown flags

### copy_file_range

`copy_file_range(fd_in, off_in, fd_out, off_out, len, flags) → bytes_copied`

**Success**: Returns bytes copied. Both offsets advanced.

**Errors**:
- `EBADF` — fd not valid or not open in correct direction
- `EFBIG` — write would exceed max file size
- `EINVAL` — fds refer to same file with overlapping ranges; or fd is a pipe; or negative offset
- `EIO` — I/O error
- `ENOMEM` — insufficient memory
- `ENOSPC` — no space on device
- `EOVERFLOW` — offset + length exceeds max
- `EPERM` — file sealed; or immutable
- `ETXTBSY` — target is an executing binary
- `EXDEV` — different filesystems (some kernels)

### truncate / ftruncate

`truncate(path, length) → 0`
`ftruncate(fd, length) → 0`

**Success**: Returns 0. Sets file size to `length`.
- Shorter → data beyond `length` lost
- Longer → extended region reads as zero (hole)

**Errors**:
- `EACCES` — write permission denied (`truncate` only)
- `EBADF` — `ftruncate`: fd not valid or not open for writing
- `EFAULT` — bad pointer (`truncate`)
- `EFBIG` — `length` exceeds max file size
- `EINTR` — interrupted by signal
- `EINVAL` — `length` negative; or fd refers to non-file (socket, etc.)
- `EIO` — I/O error
- `EISDIR` — path is a directory (`truncate`)
- `ELOOP` — too many symlinks (`truncate`)
- `ENAMETOOLONG` — pathname too long (`truncate`)
- `ENOENT` — path doesn't exist (`truncate`)
- `ENOTDIR` — path component not a directory (`truncate`)
- `EPERM` — file is append-only or immutable
- `EROFS` — read-only filesystem
- `ETXTBSY` — file is being executed

### memfd_create

`memfd_create(name, flags) → fd`

**Success**: Returns fd. Anonymous file not in any filesystem.
- `MFD_CLOEXEC` → sets `O_CLOEXEC`
- `MFD_ALLOW_SEALING` → permits `fcntl(F_ADD_SEALS)`
- `MFD_HUGETLB` → huge pages

**Errors**:
- `EFAULT` — bad `name` pointer
- `EINVAL` — unknown flags; or `name` too long (249 bytes)
- `EMFILE` — process fd limit
- `ENFILE` — system fd limit
- `ENOMEM` — insufficient memory

### inotify_init1

`inotify_init() → fd`
`inotify_init1(flags) → fd`

**Success**: Returns inotify fd.
- `IN_CLOEXEC` → `O_CLOEXEC`
- `IN_NONBLOCK` → `O_NONBLOCK`

**Errors**:
- `EINVAL` — invalid flags
- `EMFILE` — process fd limit; or inotify instance limit (`/proc/sys/fs/inotify/max_user_instances`)
- `ENFILE` — system fd limit
- `ENOMEM` — insufficient memory

### inotify_add_watch

`inotify_add_watch(fd, pathname, mask) → wd`

**Success**: Returns watch descriptor (wd). If path already watched, returns existing wd with updated mask.
- Events: `IN_CREATE`, `IN_DELETE`, `IN_MODIFY`, `IN_MOVED_FROM`, `IN_MOVED_TO`, `IN_ATTRIB`, `IN_CLOSE_WRITE`, `IN_CLOSE_NOWRITE`, `IN_OPEN`, `IN_DELETE_SELF`, `IN_MOVE_SELF`
- `IN_ONLYDIR` → fail if not a directory
- `IN_DONT_FOLLOW` → don't follow symlinks
- `IN_MASK_ADD` → add to mask instead of replacing
- `IN_ONESHOT` → generate event once then auto-remove

**Errors**:
- `EACCES` — read access denied to path
- `EBADF` — fd not valid inotify instance
- `EEXIST` — `IN_MASK_CREATE` and watch already exists
- `EFAULT` — bad pointer
- `EINVAL` — mask contains no legal events; or fd is not inotify
- `ENAMETOOLONG` — pathname too long
- `ENOENT` — path doesn't exist
- `ENOMEM` — insufficient memory
- `ENOSPC` — watch limit (`/proc/sys/fs/inotify/max_user_watches`) reached
- `ENOTDIR` — `IN_ONLYDIR` and path is not a directory

### inotify_rm_watch

`inotify_rm_watch(fd, wd) → 0`

**Success**: Returns 0. Generates `IN_IGNORED` event on inotify fd.

**Errors**:
- `EBADF` — fd not valid inotify instance
- `EINVAL` — wd not valid for this inotify instance

### flock

`flock(fd, operation) → 0`

**Success**: Returns 0.
- `LOCK_SH` → shared lock (multiple holders)
- `LOCK_EX` → exclusive lock (one holder)
- `LOCK_UN` → release lock
- `LOCK_NB` → non-blocking; return `EWOULDBLOCK` instead of waiting
- Locks are per open-file-description; `dup`-ed fds share lock
- `fork`-ed child does NOT inherit lock (has separate file description)

**Errors**:
- `EBADF` — fd not valid
- `EINTR` — interrupted by signal while waiting
- `EINVAL` — invalid operation
- `ENOLCK` — kernel lock table full
- `EWOULDBLOCK` — `LOCK_NB` and conflicting lock held

### quotactl

`quotactl(cmd, special, id, addr) → 0`

**Success**: Returns 0.
- `Q_QUOTAON` / `Q_QUOTAOFF` → enable/disable
- `Q_GETQUOTA` / `Q_SETQUOTA` → get/set for UID/GID
- `Q_GETINFO` / `Q_SETINFO` → get/set quota metadata
- `Q_SYNC` → flush quota file

**Errors**:
- `EACCES` — quota file not a regular file
- `EBUSY` — `Q_QUOTAON` but quotas already on
- `EFAULT` — bad pointer
- `EINVAL` — bad `cmd`; or `type` not `USRQUOTA`/`GRPQUOTA`
- `EIO` — I/O error
- `EMFILE` — too many open files internally
- `ENODEV` — no block device for special file
- `ENOENT` — quota file doesn't exist; or path doesn't exist
- `ENOSYS` — kernel compiled without quota support
- `ENOTBLK` — not a block device
- `EPERM` — caller lacks `CAP_SYS_ADMIN`
- `ERANGE` — limit out of range for filesystem
- `ESRCH` — no quota for given ID

### name_to_handle_at

`name_to_handle_at(dirfd, pathname, handle, mount_id, flags) → 0`

**Success**: Returns 0. Fills `file_handle` and mount ID.
- Handle is opaque; survives renames; usable with `open_by_handle_at`

**Errors**:
- `EBADF` — dirfd not valid
- `EFAULT` — bad pointer
- `EINVAL` — bad flags; or `handle_bytes` > `MAX_HANDLE_SZ`
- `ELOOP` — too many symlinks
- `ENAMETOOLONG` — pathname too long
- `ENOENT` — path doesn't exist
- `ENOTDIR` — component not a directory
- `EOPNOTSUPP` — filesystem doesn't support file handles
- `EOVERFLOW` — `handle_bytes` too small (required size written; caller retries)

### open_by_handle_at

`open_by_handle_at(mount_fd, handle, flags) → fd`

**Success**: Returns fd.

**Errors**:
- `EBADF` — `mount_fd` not valid
- `EFAULT` — bad pointer
- `EINVAL` — bad handle size
- `ELOOP` — too many symlinks in handle resolution
- `EMFILE` — process fd limit
- `ENFILE` — system fd limit
- `ENOMEM` — insufficient memory
- `EPERM` — caller lacks `CAP_DAC_READ_SEARCH`
- `ESTALE` — handle no longer valid (file deleted; filesystem unmounted and remounted)

### personality

`personality(persona) → previous_persona`

**Success**: Returns previous personality value. `0xffffffff` → query without setting.
- `PER_LINUX` (0) → standard Linux
- Various compatibility flags

**Errors**:
- `EINVAL` — unknown personality (but many kernels accept anything)

### rseq

`rseq(rseq, rseq_len, flags, sig) → 0`

**Success**: Returns 0. Registers restartable sequence area.
- On preemption in critical section, kernel writes to `cpu_id` field
- `flags = RSEQ_FLAG_UNREGISTER` → unregisters

**Errors**:
- `EBUSY` — already registered for this thread
- `EFAULT` — bad `rseq` pointer
- `EINVAL` — bad `rseq_len`; bad alignment (must be 32-byte); bad flags; or bad signature

### prctl

`prctl(option, arg2, arg3, arg4, arg5) → 0 | value`

**Success**: Returns 0 or requested value.
- `PR_SET_NAME` / `PR_GET_NAME` → thread name (15 chars + null)
- `PR_SET_DUMPABLE` / `PR_GET_DUMPABLE` → core dump behavior
- `PR_SET_NO_NEW_PRIVS` → no privilege escalation via execve (irreversible)
- `PR_GET_KEEPCAPS` / `PR_SET_KEEPCAPS` → retain capabilities across UID transition
- `PR_SET_PDEATHSIG` / `PR_GET_PDEATHSIG` → signal on parent death
- `PR_SET_SECCOMP` / `PR_GET_SECCOMP` → seccomp mode
- `PR_SET_TIMERSLACK` / `PR_GET_TIMERSLACK` → nanosecond timer slack
- `PR_SET_CHILD_SUBREAPER` → reap orphaned descendants

**Errors**:
- `EACCES` — `PR_SET_SECCOMP` without `PR_SET_NO_NEW_PRIVS` and lacks `CAP_SYS_ADMIN`
- `EFAULT` — bad pointer
- `EINVAL` — unknown option; or bad argument for known option
- `ENOENT` — `PR_SET_MM` with field that doesn't exist
- `EPERM` — insufficient privilege for the operation

### sysctl (legacy)

`sysctl(args) → (deprecated — use /proc/sys)`

**Success**: Returns 0 on modern kernels (rare).

**Errors**:
- `ENOSYS` — modern kernels return this unconditionally (use `/proc/sys` instead)
