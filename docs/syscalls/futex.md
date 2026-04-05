## Futex

### futex

`futex(uaddr, futex_op, val[, timeout][, uaddr2][, val3]) → varies`

**Success**: Varies by operation.
- `FUTEX_WAIT` → if `*uaddr == val`, blocks until woken or timeout. Returns 0 if woken.
- `FUTEX_WAKE` → wakes up to `val` threads. Returns number woken.
- `FUTEX_WAIT_BITSET` → like `WAIT` with bitmask filter; timeout is absolute (`CLOCK_MONOTONIC` or `CLOCK_REALTIME` per bitset)
- `FUTEX_WAKE_BITSET` → like `WAKE` with bitmask filter
- `FUTEX_CMP_REQUEUE` → atomically requeue waiters to another futex
- `FUTEX_WAKE_OP` → wake + conditional wake on two futexes

**Errors**:
- `EAGAIN` — `FUTEX_WAIT`: `*uaddr != val` at time of call (value changed)
- `EDEADLK` — `FUTEX_LOCK_PI`: deadlock detected
- `EFAULT` — bad `uaddr` pointer
- `EINTR` — `FUTEX_WAIT` interrupted by signal
- `EINVAL` — `op` not recognized; or `uaddr` not aligned to 4 bytes; or invalid timeout; or bitset is 0
- `ENFILE` — `FUTEX_LOCK_PI`: kernel state table full
- `ENOMEM` — insufficient memory for kernel state
- `ENOSYS` — unknown operation
- `EPERM` — `FUTEX_UNLOCK_PI`: caller doesn't own the futex
- `ESRCH` — `FUTEX_CMP_REQUEUE_PI`: target thread doesn't exist
- `ETIMEDOUT` — timeout expired without being woken
