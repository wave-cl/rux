## Scheduling

### sched_yield

`sched_yield() → 0`

**Success**: Returns 0. Voluntarily yields CPU. Always succeeds.

### sched_getaffinity / sched_setaffinity

`sched_getaffinity(pid, cpusetsize, mask) → 0`
`sched_setaffinity(pid, cpusetsize, mask) → 0`

**Success**: Returns 0. Gets/sets CPU mask.
- `pid = 0` → calling thread

**Errors**:
- `EFAULT` — bad pointer
- `EINVAL` — `cpusetsize` too small; or no valid CPUs in mask for `setaffinity`
- `EPERM` — `setaffinity` without `CAP_SYS_NICE` for another process; or trying to move to disallowed CPU
- `ESRCH` — no thread with given PID

### sched_getscheduler / sched_setscheduler

`sched_getscheduler(pid) → policy`
`sched_setscheduler(pid, policy, param) → 0`

**Success**: `getscheduler` returns policy constant. `setscheduler` returns 0.
- `SCHED_OTHER` (0), `SCHED_FIFO` (1), `SCHED_RR` (2), `SCHED_BATCH` (3), `SCHED_IDLE` (5), `SCHED_DEADLINE` (6)

**Errors**:
- `EFAULT` — bad pointer
- `EINVAL` — invalid policy or priority for policy
- `EPERM` — insufficient privilege (RT policies need `CAP_SYS_NICE`)
- `ESRCH` — no thread with given PID

### sched_getparam / sched_setparam

`sched_getparam(pid, param) → 0`
`sched_setparam(pid, param) → 0`

**Success**: Returns 0.
- `sched_priority`: 0 for `SCHED_OTHER`; 1-99 for `SCHED_FIFO`/`SCHED_RR`

**Errors**:
- `EFAULT` — bad pointer
- `EINVAL` — priority out of range for policy
- `EPERM` — insufficient privilege
- `ESRCH` — no thread with given PID
