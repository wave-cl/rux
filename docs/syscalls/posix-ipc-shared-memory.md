## POSIX IPC — Shared Memory

### shmget

`shmget(key, size, shmflg) → shmid`

**Success**: Returns shared memory ID.

**Errors**:
- `EACCES` — segment exists but caller lacks permission
- `EEXIST` — `IPC_CREAT | IPC_EXCL` and segment exists
- `EINVAL` — `size` < `SHMMIN` or > `SHMMAX`; or exists with smaller size
- `ENFILE` — system limit on segments reached
- `ENOENT` — no segment for key and `IPC_CREAT` not set
- `ENOMEM` — insufficient memory
- `ENOSPC` — total shared memory (`SHMALL`) exceeded

### shmat

`shmat(shmid, shmaddr, shmflg) → address`

**Success**: Returns address.
- `shmaddr = NULL` → kernel chooses
- `SHM_RDONLY` → read-only (write → `SIGSEGV`)
- `SHM_REMAP` → replace existing mapping at addr

**Errors**:
- `EACCES` — insufficient permission
- `EIDRM` — marked for removal
- `EINVAL` — invalid ID; unaligned addr; `SHM_REMAP` without addr
- `ENOMEM` — insufficient memory

### shmdt

`shmdt(shmaddr) → 0`

**Success**: Returns 0.

**Errors**:
- `EINVAL` — `shmaddr` not a valid attachment

### shmctl

`shmctl(shmid, cmd, buf) → 0`

**Success**: Returns 0.
- `IPC_STAT`/`IPC_SET`/`IPC_RMID`/`SHM_LOCK`/`SHM_UNLOCK`

**Errors**:
- `EACCES` — `IPC_STAT` without read permission
- `EFAULT` — bad pointer
- `EIDRM` — removed
- `EINVAL` — invalid ID or cmd
- `ENOMEM` — `SHM_LOCK` insufficient memory
- `EOVERFLOW` — `IPC_STAT` values too large
- `EPERM` — command requires ownership or `CAP_IPC_LOCK`
