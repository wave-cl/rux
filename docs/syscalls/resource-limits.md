## Resource Limits

### getrlimit / setrlimit

`getrlimit(resource, rlim) → 0`
`setrlimit(resource, rlim) → 0`

**Success**: Returns 0. Gets/sets per-process resource limits.
- `RLIMIT_NOFILE` → max open fds
- `RLIMIT_NPROC` → max processes per UID
- `RLIMIT_AS` → max address space size
- `RLIMIT_FSIZE` → max file size (exceeding → `SIGXFSZ`)
- `RLIMIT_STACK` → max stack size
- `RLIMIT_MEMLOCK` → max locked memory
- `RLIMIT_CPU` → max CPU seconds (exceeding → `SIGXCPU`)
- `RLIMIT_CORE` → max core dump size
- Soft (`rlim_cur`) ≤ hard (`rlim_max`). Non-root can raise soft up to hard. Only root can raise hard.

**Errors**:
- `EFAULT` — bad pointer
- `EINVAL` — invalid `resource`; or `rlim_cur > rlim_max`
- `EPERM` — non-root attempted to raise hard limit

### prlimit64

`prlimit(pid, resource, new_limit, old_limit) → 0`

**Success**: Returns 0. Gets and/or sets limits for process `pid` (0 = self).

**Errors**: Same as above plus:
- `ESRCH` — no process with given PID
- `EPERM` — insufficient privilege for another process
