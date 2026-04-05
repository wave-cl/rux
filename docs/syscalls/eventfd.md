## EventFD

### eventfd2

`eventfd(initval, flags) → fd`

**Success**: Returns fd with 64-bit unsigned counter (initial value from arg).
- `write(fd, &val, 8)` → counter += val; wakes readers
- `read(fd, &val, 8)` → val = counter; counter reset to 0; blocks if counter is 0
- `EFD_SEMAPHORE` → `read` returns 1 and decrements counter by 1
- `EFD_NONBLOCK` → `read`/`write` return `EAGAIN` instead of blocking
- `EFD_CLOEXEC` → sets `O_CLOEXEC`
- Counter overflow (would exceed `UINT64_MAX - 1`) → blocks or `EAGAIN`
- `write` with buffer not 8 bytes → `EINVAL`
- `read` with buffer < 8 bytes → `EINVAL`

**Errors**:
- `EINVAL` — invalid flags; or initial value is `UINT64_MAX`
- `EMFILE` — process fd limit
- `ENFILE` — system fd limit
- `ENOMEM` — insufficient memory
