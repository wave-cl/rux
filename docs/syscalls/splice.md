## Splice Family

### splice

`splice(fd_in, off_in, fd_out, off_out, len, flags) → bytes_moved`

**Success**: Returns bytes moved. Moves data between fd and pipe without user-space copy.
- At least one of `fd_in`/`fd_out` must be a pipe
- `off_in`/`off_out` for seekable fds (NULL for pipes)
- `SPLICE_F_MOVE` → hint to move pages rather than copy
- `SPLICE_F_NONBLOCK` → don't block on pipe I/O
- `SPLICE_F_MORE` → more data coming
- Returns 0 on EOF

**Errors**:
- `EAGAIN` — `SPLICE_F_NONBLOCK` and would block
- `EBADF` — fd not valid or not open in correct direction
- `EINVAL` — neither fd is a pipe; or offset given for pipe fd; or filesystem doesn't support splicing
- `ENOMEM` — insufficient memory
- `ESPIPE` — offset given for non-seekable fd (but not a pipe)

### vmsplice

`vmsplice(fd, iov, nr_segs, flags) → bytes_spliced`

**Success**: Returns bytes spliced. Maps user-space pages into pipe.
- fd must be write end of a pipe
- `SPLICE_F_GIFT` → pages donated to kernel (user must not modify after)

**Errors**:
- `EBADF` — fd not valid or not a pipe write end
- `EINVAL` — `nr_segs` is 0 or > `UIO_MAXIOV`; or bad alignment
- `ENOMEM` — insufficient memory

### tee

`tee(fd_in, fd_out, len, flags) → bytes_duplicated`

**Success**: Returns bytes duplicated. Copies data between two pipes without consuming from source.

**Errors**:
- `EINVAL` — fd is not a pipe; or same pipe for both
- `ENOMEM` — insufficient memory
