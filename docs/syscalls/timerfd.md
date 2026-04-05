## TimerFD

### timerfd_create

`timerfd_create(clockid, flags) → fd`

**Success**: Returns fd. Timer backed by given clock.

**Errors**:
- `EINVAL` — invalid `clockid`; or invalid `flags`
- `EMFILE` — process fd limit
- `ENFILE` — system fd limit
- `ENODEV` — kernel doesn't support timerfd
- `ENOMEM` — insufficient memory

### timerfd_settime

`timerfd_settime(fd, flags, new_value, old_value) → 0`

**Success**: Returns 0. Arms or disarms timer.
- `TFD_TIMER_ABSTIME` → `new_value.it_value` is absolute
- `it_value = 0` → disarms timer
- `it_interval > 0` → repeating timer
- `old_value` (if not NULL) receives previous settings

**Errors**:
- `EBADF` — fd not valid or not a timerfd
- `ECANCELED` — `TFD_TIMER_CANCEL_ON_SET` and `CLOCK_REALTIME` was set via `clock_settime`
- `EFAULT` — bad pointer
- `EINVAL` — not a timerfd; or bad `flags`; or `tv_nsec` not in [0, 999999999]

### timerfd_gettime

`timerfd_gettime(fd, curr_value) → 0`

**Success**: Returns 0. Fills `curr_value` with remaining time and interval.

**Errors**:
- `EBADF` — fd not valid or not a timerfd
- `EFAULT` — bad pointer
- `EINVAL` — not a timerfd

### Reading a timerfd

`read(fd, buf, 8) → 8  (buf receives expiration count as uint64)`

- `read(fd, &val, 8)` → returns 8 bytes; `val` = number of expirations since last read
- Timer not expired → blocks (or `EAGAIN` if `O_NONBLOCK`)
- Buffer < 8 bytes → `EINVAL`
