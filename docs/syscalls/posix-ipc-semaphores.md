## POSIX IPC — Semaphores

### semget

`semget(key, nsems, semflg) → semid`

**Success**: Returns semaphore set ID.

**Errors**:
- `EACCES` — set exists but caller lacks permission
- `EEXIST` — `IPC_CREAT | IPC_EXCL` and set exists
- `EINVAL` — `nsems` < 0 or > `SEMMSL`; or set exists with different count
- `ENOENT` — no set for key and `IPC_CREAT` not set
- `ENOMEM` — insufficient memory
- `ENOSPC` — system limit on sets (`SEMMNI`) or semaphores (`SEMMNS`) reached

### semop / semtimedop

`semop(semid, sops, nsops) → 0`
`semtimedop(semid, sops, nsops, timeout) → 0`

**Success**: Returns 0. Operations applied atomically.
- Positive `sem_op` → increment value
- Negative `sem_op` → decrement; blocks if would go below 0 (unless `IPC_NOWAIT`)
- Zero `sem_op` → blocks until value is 0 (unless `IPC_NOWAIT`)
- `SEM_UNDO` → reversed on process exit

**Errors**:
- `E2BIG` — `nsops` > `SEMOPM`
- `EACCES` — insufficient permission
- `EAGAIN` — `IPC_NOWAIT` and would block
- `EFAULT` — bad pointer
- `EFBIG` — `sem_num` ≥ count of semaphores in set
- `EIDRM` — set removed while blocked
- `EINTR` — interrupted by signal
- `EINVAL` — invalid set ID or `nsops` ≤ 0
- `ENOMEM` — `SEM_UNDO` insufficient memory
- `ERANGE` — result would exceed `SEMVMX`

### semctl

`semctl(semid, semnum, cmd[, arg]) → varies`

**Success**: Varies by cmd.
- `GETVAL` → semaphore value; `SETVAL` → 0
- `GETALL`/`SETALL` → get/set all values
- `GETPID` → PID of last `semop`
- `GETNCNT`/`GETZCNT` → waiter counts
- `IPC_STAT`/`IPC_SET` → get/set metadata
- `IPC_RMID` → remove; blocked `semop` gets `EIDRM`

**Errors**:
- `EACCES` — insufficient permission
- `EFAULT` — bad pointer
- `EIDRM` — set removed
- `EINVAL` — invalid ID, cmd, or `semnum`
- `EPERM` — `IPC_SET`/`IPC_RMID` without ownership
- `ERANGE` — `SETVAL` out of range
