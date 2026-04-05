## Poll & Select

### poll / ppoll

`poll(fds, nfds, timeout) → ready_count`
`ppoll(fds, nfds, tmo_p, sigmask) → ready_count`

**Success**: Returns number of fds with non-zero `revents`. 0 on timeout.
- `POLLIN` → data to read; `POLLOUT` → can write; `POLLHUP` → hangup; `POLLERR` → error; `POLLNVAL` → fd not open
- `ppoll` atomically applies signal mask during wait
- `timeout = NULL` → block indefinitely; `timeout = {0,0}` → non-blocking

**Errors**:
- `EFAULT` — bad `fds` or `tmo_p` pointer
- `EINTR` — interrupted by signal
- `EINVAL` — `nfds` > `RLIMIT_NOFILE`; or bad `timeout` value
- `ENOMEM` — insufficient memory

### pselect6 / select

`select(nfds, readfds, writefds, exceptfds, timeout) → ready_count`
`pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask) → ready_count`

**Success**: Returns count of ready fds across read/write/except sets. 0 on timeout.
- `nfds` = highest fd + 1 in any set
- `timeout = NULL` → block indefinitely

**Errors**:
- `EBADF` — invalid fd in one of the sets
- `EFAULT` — bad pointer
- `EINTR` — interrupted by signal
- `EINVAL` — `nfds` negative or > `FD_SETSIZE`; or `timeout` has invalid fields
- `ENOMEM` — insufficient memory
