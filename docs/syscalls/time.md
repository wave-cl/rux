## Time

### clock_gettime

`clock_gettime(clockid, tp) → 0`

**Success**: Returns 0. Fills `timespec` with time for given clock.
- `CLOCK_REALTIME` → wall-clock since epoch; affected by `settimeofday`/`adjtime`
- `CLOCK_MONOTONIC` → monotonically increasing; not affected by time-of-day changes
- `CLOCK_MONOTONIC_RAW` → monotonic, not subject to NTP adjustments
- `CLOCK_PROCESS_CPUTIME_ID` → per-process CPU time
- `CLOCK_THREAD_CPUTIME_ID` → per-thread CPU time
- `CLOCK_BOOTTIME` → like MONOTONIC but includes suspend time

**Errors**:
- `EFAULT` — bad `tp` pointer
- `EINVAL` — unknown `clockid`
- `EPERM` — `CLOCK_PROCESS_CPUTIME_ID` for another process without permission

### clock_settime

`clock_settime(clockid, tp) → 0`

**Success**: Returns 0. Sets `CLOCK_REALTIME` to given value.

**Errors**:
- `EFAULT` — bad `tp` pointer
- `EINVAL` — clock is not settable (e.g. `CLOCK_MONOTONIC`); or `tv_nsec` out of range; or `tv_sec` negative
- `EPERM` — caller lacks `CAP_SYS_TIME`

### clock_getres

`clock_getres(clockid, res) → 0`

**Success**: Returns 0. Fills `res` with resolution (smallest increment) of given clock.

**Errors**:
- `EFAULT` — bad pointer (if `res` not NULL)
- `EINVAL` — unknown `clockid`

### clock_nanosleep

`clock_nanosleep(clockid, flags, request, remain) → 0`

**Success**: Returns 0 after sleeping.
- `TIMER_ABSTIME` → `request` is absolute time; wake at that moment
- Without `TIMER_ABSTIME` → `request` is relative duration

**Errors**:
- `EFAULT` — bad `request` or `remain` pointer
- `EINTR` — interrupted by signal; if not `TIMER_ABSTIME`, `remain` filled with remaining time
- `EINVAL` — unknown `clockid`; or `tv_nsec` not in [0, 999999999]; or `tv_sec` negative; or `TIMER_ABSTIME` with `CLOCK_THREAD_CPUTIME_ID`
- `ENOTSUP` — `TIMER_ABSTIME` not supported for given clock (rare)

### gettimeofday

`gettimeofday(tv, tz) → 0`

**Success**: Returns 0. Fills `tv` with seconds and microseconds since epoch. `tz` (timezone) is obsolete and usually NULL.

**Errors**:
- `EFAULT` — bad `tv` or `tz` pointer
- (Practically never fails on Linux when `tv` is valid)

### nanosleep

`nanosleep(req, rem) → 0`

**Success**: Returns 0 after sleeping for at least the requested duration.

**Errors**:
- `EFAULT` — bad `req` or `rem` pointer
- `EINTR` — interrupted by signal; `rem` filled with remaining time
- `EINVAL` — `tv_nsec` not in [0, 999999999] or `tv_sec` negative

### alarm

`alarm(seconds) → remaining_seconds`

**Success**: Returns seconds remaining from any previous alarm (0 if none). Schedules `SIGALRM` delivery after `seconds`. `alarm(0)` cancels pending alarm.

No errors (always succeeds).

### setitimer / getitimer

`setitimer(which, new_value, old_value) → 0`
`getitimer(which, curr_value) → 0`

**Success**: Returns 0.
- `ITIMER_REAL` → counts real time; delivers `SIGALRM`
- `ITIMER_VIRTUAL` → counts user-mode CPU time; delivers `SIGVTALRM`
- `ITIMER_PROF` → counts user + kernel CPU time; delivers `SIGPROF`
- `it_value` = time until next expiry; `it_interval` = auto-reload value (0 = one-shot)
- `setitimer` with both fields 0 → disarms timer
- `getitimer` → returns current state

**Errors**:
- `EFAULT` — bad pointer
- `EINVAL` — `which` not valid; or `tv_usec` not in [0, 999999]

### timer_create

`timer_create(clockid, sevp, timerid) → 0`

**Success**: Returns 0. Creates a POSIX timer. Timer ID stored in `*timerid`.
- `sigevent` controls notification: `SIGEV_SIGNAL` (signal delivery), `SIGEV_THREAD` (new thread), `SIGEV_THREAD_ID` (signal to specific thread), `SIGEV_NONE` (no notification)

**Errors**:
- `EAGAIN` — system limit on timers exceeded
- `EFAULT` — bad pointer
- `EINVAL` — invalid clock ID; or invalid `sigevent` fields
- `ENOMEM` — insufficient memory
- `EPERM` — `SIGEV_THREAD_ID` targeting thread in different process

### timer_settime

`timer_settime(timerid, flags, new_value, old_value) → 0`

**Success**: Returns 0. Arms or disarms timer.
- `TIMER_ABSTIME` → `it_value` is absolute time
- `it_value = 0` → disarms
- `it_interval > 0` → repeating
- If `old_value` not NULL, previous settings returned

**Errors**:
- `EFAULT` — bad pointer
- `EINVAL` — invalid `timerid`; or bad `flags`; or `tv_nsec` out of range

### timer_gettime

`timer_gettime(timerid, curr_value) → 0`

**Success**: Returns 0. Fills `curr_value` with remaining time and interval.

**Errors**:
- `EFAULT` — bad pointer
- `EINVAL` — invalid `timerid`

### timer_getoverrun

`timer_getoverrun(timerid) → overrun_count`

**Success**: Returns overrun count (number of expirations between signal generation and delivery). Capped at `DELAYTIMER_MAX`.

**Errors**:
- `EINVAL` — invalid `timerid`

### timer_delete

`timer_delete(timerid) → 0`

**Success**: Returns 0. Disarms and deletes timer. Pending signal may still be delivered.

**Errors**:
- `EINVAL` — invalid `timerid`
