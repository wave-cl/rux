## File Descriptors

### open / openat

`open(pathname, flags[, mode]) → fd`
`openat(dirfd, pathname, flags[, mode]) → fd`

**Success**: Returns lowest available fd ≥ 0. File opened with requested access mode and flags.
- `O_CREAT` creates file if absent with mode subject to umask; no-op if present
- `O_CREAT | O_EXCL` atomically creates file; fails if already exists
- `O_TRUNC` truncates existing regular file to zero length
- `O_APPEND` positions write pointer at end before every write
- `O_NONBLOCK` sets non-blocking mode on the fd
- `O_CLOEXEC` sets `FD_CLOEXEC`; fd automatically closed on `execve`
- `O_DIRECTORY` fails if path is not a directory
- `O_NOFOLLOW` fails if final component is a symlink
- `openat` with `AT_FDCWD` behaves identically to `open`
- `openat` resolves relative paths against `dirfd`

**Errors**:
- `EACCES` — search permission denied on path component; or file exists and requested access (read/write) not allowed by mode; or `O_CREAT` and write permission denied on parent directory
- `EDQUOT` — `O_CREAT`: disk quota exhausted
- `EEXIST` — `O_CREAT | O_EXCL` and file exists
- `EFAULT` — pathname points outside accessible address space
- `EFBIG` / `EOVERFLOW` — file too large to open (32-bit offset overflow)
- `EINTR` — blocked open interrupted by signal (e.g. FIFO open)
- `EINVAL` — invalid flags; `O_CREAT | O_TMPFILE` with invalid mode; unsupported flags combination
- `EISDIR` — write access requested on a directory
- `ELOOP` — too many symbolic links in path; or `O_NOFOLLOW` and final component is symlink
- `EMFILE` — process open file limit reached
- `ENAMETOOLONG` — pathname or a component exceeds `NAME_MAX` / `PATH_MAX`
- `ENFILE` — system-wide open file limit reached
- `ENODEV` — pathname refers to special file and no device driver for it
- `ENOENT` — path component does not exist; or `O_CREAT` not set and file doesn't exist; or `O_DIRECTORY` and path doesn't exist
- `ENOMEM` — insufficient kernel memory
- `ENOSPC` — `O_CREAT` and no room for new file on device
- `ENOTDIR` — path component used as directory is not one; or `O_DIRECTORY` and final component is not a directory; or `openat` with relative path and `dirfd` is not a directory
- `ENXIO` — `O_NONBLOCK | O_WRONLY` on FIFO with no readers; or special file with no corresponding device
- `EPERM` — `O_NOATIME` flag and caller doesn't own file and is not privileged; file sealed against operation
- `EROFS` — write access requested on read-only filesystem
- `ETXTBSY` — write access to executable that is currently being executed
- `EWOULDBLOCK` — `O_NONBLOCK` on a file that would block (FIFO, device)
- `EBADF` — `openat` with invalid `dirfd` (and path is relative)

### creat

`creat(pathname, mode) → fd`

**Success**: Equivalent to `open(path, O_CREAT | O_WRONLY | O_TRUNC, mode)`. Returns fd.

**Errors**: Same as `open` with those flags.

### close

`close(fd) → 0`

**Success**: Returns 0. Releases the fd. If last reference to open file description, underlying resources (pipe buffers, socket state) are freed.

**Errors**:
- `EBADF` — fd is not a valid open file descriptor
- `EINTR` — interrupted by signal (file may or may not have been closed)
- `EIO` — I/O error during flush of pending writes

### read

`read(fd, buf, count) → bytes_read`

**Success**: Returns number of bytes read (0 = EOF). Data transferred to buffer.
- Partial reads are permitted; less than `count` does not indicate error.

**Errors**:
- `EAGAIN` / `EWOULDBLOCK` — fd is non-blocking and no data available
- `EBADF` — fd not valid or not open for reading
- `EFAULT` — buf outside accessible address space
- `EINTR` — interrupted by signal before any data read
- `EINVAL` — fd attached to object unsuitable for reading; or misaligned buffer for direct I/O
- `EIO` — low-level I/O error
- `EISDIR` — fd refers to a directory

### write

`write(fd, buf, count) → bytes_written`

**Success**: Returns number of bytes written. Partial writes are permitted.

**Errors**:
- `EAGAIN` / `EWOULDBLOCK` — fd is non-blocking and write would block
- `EBADF` — fd not valid or not open for writing
- `EDQUOT` — disk quota exhausted
- `EFAULT` — buf outside accessible address space
- `EFBIG` — write would exceed max file size or process file size limit
- `EINTR` — interrupted by signal before any data written
- `EINVAL` — fd unsuitable for writing; or misaligned buffer for direct I/O
- `EIO` — low-level I/O error
- `ENOSPC` — device has no room
- `EPERM` — file sealed against writes
- `EPIPE` — writing to pipe/socket with no readers; `SIGPIPE` also delivered unless blocked

### pread64 / pwrite64

`pread(fd, buf, count, offset) → bytes_read`
`pwrite(fd, buf, count, offset) → bytes_written`

**Success**: Like `read`/`write` but at given offset without changing file position.

**Errors**: All errors from `read`/`write` plus:
- `EINVAL` — offset is negative
- `ESPIPE` — fd is a pipe, socket, or FIFO (not seekable)
- `EOVERFLOW` — offset + count exceeds max file offset

### readv / writev

`readv(fd, iov, iovcnt) → bytes_read`
`writev(fd, iov, iovcnt) → bytes_written`

**Success**: Atomic scatter/gather I/O across `iov_count` buffers. Returns total bytes transferred.

**Errors**: All errors from `read`/`write` plus:
- `EINVAL` — `iovcnt` ≤ 0 or > `UIO_MAXIOV` (1024); or total overflow of `iov_len` sums
- `EFAULT` — `iov` pointer or any `iov_base` pointer is invalid

### sendfile

`sendfile(out_fd, in_fd, offset, count) → bytes_copied`

**Success**: Copies up to `count` bytes from `in_fd` (at `*offset` or current position) to `out_fd`. Returns bytes copied. Advances `*offset` (or file position if offset is NULL).

**Errors**:
- `EAGAIN` — non-blocking I/O on `out_fd` and write would block
- `EBADF` — `in_fd` not open for reading or `out_fd` not open for writing
- `EFAULT` — bad `offset` pointer
- `EINVAL` — `in_fd` not `mmap`-able (not a regular file); or offset negative; or fds refer to same file with overlapping ranges
- `EIO` — unspecified read error from `in_fd`
- `ENOMEM` — insufficient memory

### lseek

`lseek(fd, offset, whence) → new_offset`

**Success**: Returns resulting file offset from beginning of file.

**Errors**:
- `EBADF` — fd not a valid open fd
- `EINVAL` — `whence` not `SEEK_SET`, `SEEK_CUR`, or `SEEK_END`; or resulting offset would be negative
- `ENXIO` — `SEEK_DATA`/`SEEK_HOLE` and offset is beyond end of file
- `EOVERFLOW` — resulting offset exceeds representable range of `off_t`
- `ESPIPE` — fd is a pipe, socket, or FIFO

### dup

`dup(oldfd) → newfd`

**Success**: Returns new fd (lowest available ≥ 0) referring to same open file description.

**Errors**:
- `EBADF` — `oldfd` not valid
- `EMFILE` — process open file limit reached

### dup2

`dup2(oldfd, newfd) → newfd`

**Success**: Makes `newfd` refer to same open file description as `oldfd`. If `newfd` was open, silently closed first. If `oldfd == newfd`, returns `newfd` without closing.

**Errors**:
- `EBADF` — `oldfd` not valid; or `newfd` out of allowed range
- `EBUSY` — race condition during close-and-reuse (may occur on some kernels)
- `EINTR` — interrupted by signal

### dup3

`dup3(oldfd, newfd, flags) → newfd`

**Success**: Like `dup2` but supports flags. `O_CLOEXEC` sets `FD_CLOEXEC` on `newfd`.

**Errors**:
- `EBADF` — `oldfd` not valid; or `newfd` out of range
- `EINVAL` — `oldfd == newfd`; or invalid flags (anything other than `O_CLOEXEC`)

### fcntl

`fcntl(fd, cmd[, arg]) → varies`

**Success**: Varies by command.

**Commands and errors**:
- `F_DUPFD` / `F_DUPFD_CLOEXEC` — returns new fd ≥ arg; `EINVAL` if arg negative; `EMFILE` if limit
- `F_GETFD` — returns fd flags (e.g. `FD_CLOEXEC`)
- `F_SETFD` — sets fd flags; returns 0
- `F_GETFL` — returns status flags and access mode
- `F_SETFL` — sets `O_APPEND`, `O_ASYNC`, `O_DIRECT`, `O_NOATIME`, `O_NONBLOCK`; ignores access-mode bits; returns 0
- `F_SETLK` — set/clear advisory record lock; `EACCES`/`EAGAIN` if conflicting lock held
- `F_SETLKW` — like `F_SETLK` but blocks; `EDEADLK` if deadlock detected; `EINTR` if interrupted
- `F_GETLK` — tests for lock conflict; returns info about blocking lock or sets `l_type = F_UNLCK`

**General errors**:
- `EBADF` — fd not valid; or `F_SETLK`/`F_SETLKW` with wrong access mode for lock type
- `EFAULT` — lock struct pointer bad
- `EINVAL` — command not recognized; or bad arg for command
- `ENOLCK` — too many locks

### ioctl

`ioctl(fd, request[, arg]) → varies`

**Success**: Varies by request.
- `TIOCGWINSZ` → fills `winsize` struct with terminal rows and columns
- `TCGETS` → fills `termios` struct with terminal attributes
- `TCSETS` / `TCSETSW` / `TCSETSF` → sets terminal attributes (immediately / after drain / after flush)
- `TIOCGPGRP` → returns foreground process group ID
- `TIOCSPGRP` → sets foreground process group ID
- `FIONREAD` → returns bytes available for reading
- `FIONBIO` → sets/clears non-blocking flag

**Errors**:
- `EBADF` — fd not valid
- `EFAULT` — argp references inaccessible memory
- `EINVAL` — request or argp invalid
- `ENOTTY` — fd not associated with a terminal (for terminal ioctls); or device does not support the request
- `EPERM` — insufficient privilege for the request
