## Epoll

### epoll_create / epoll_create1

`epoll_create(size) → fd`
`epoll_create1(flags) → fd`

**Success**: Returns epoll fd.
- `epoll_create(size)` → `size` ignored but must be > 0
- `epoll_create1(EPOLL_CLOEXEC)` → sets `O_CLOEXEC`

**Errors**:
- `EINVAL` — `epoll_create`: size ≤ 0; `epoll_create1`: invalid flags
- `EMFILE` — process fd limit
- `ENFILE` — system fd limit
- `ENOMEM` — insufficient memory

### epoll_ctl

`epoll_ctl(epfd, op, fd, event) → 0`

**Success**: Returns 0.
- `EPOLL_CTL_ADD` → adds fd with event mask (`EPOLLIN`, `EPOLLOUT`, `EPOLLET`, `EPOLLONESHOT`, `EPOLLRDHUP`, etc.)
- `EPOLL_CTL_MOD` → modifies event mask for registered fd
- `EPOLL_CTL_DEL` → removes fd from interest set

**Errors**:
- `EBADF` — `epfd` or `fd` not valid
- `EEXIST` — `EPOLL_CTL_ADD` and `fd` already registered
- `EINVAL` — `epfd` not an epoll fd; or `fd == epfd`; or invalid `op`; or `EPOLLEXCLUSIVE` with invalid events
- `ELOOP` — `fd` is another epoll and adding would create a cycle
- `ENOENT` — `EPOLL_CTL_MOD`/`DEL` and `fd` not registered
- `ENOMEM` — insufficient memory
- `ENOSPC` — user-imposed limit on watches (`/proc/sys/fs/epoll/max_user_watches`) reached
- `EPERM` — `fd` does not support epoll (e.g. regular file, directory)

### epoll_wait / epoll_pwait

`epoll_wait(epfd, events, maxevents, timeout) → ready_count`
`epoll_pwait(epfd, events, maxevents, timeout, sigmask) → ready_count`

**Success**: Returns number of ready events (0 on timeout). Fills `events` array.
- `timeout = -1` → block indefinitely
- `timeout = 0` → return immediately (non-blocking poll)
- `timeout > 0` → block up to that many milliseconds
- `epoll_pwait` atomically applies signal mask during wait

**Errors**:
- `EBADF` — `epfd` not valid
- `EFAULT` — bad `events` pointer
- `EINTR` — interrupted by signal
- `EINVAL` — `epfd` not an epoll fd; or `maxevents` ≤ 0
