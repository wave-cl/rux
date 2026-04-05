## POSIX IPC — Message Queues

### msgget

`msgget(key, msgflg) → msqid`

**Success**: Returns message queue ID.

**Errors**:
- `EACCES` — queue exists but caller lacks permission
- `EEXIST` — `IPC_CREAT | IPC_EXCL` and queue exists
- `ENOENT` — no queue for key and `IPC_CREAT` not set
- `ENOMEM` — insufficient memory
- `ENOSPC` — system limit (`MSGMNI`) reached

### msgsnd

`msgsnd(msqid, msgp, msgsz, msgflg) → 0`

**Success**: Returns 0.
- `mtype > 0` required
- Blocks if queue full; `IPC_NOWAIT` → `EAGAIN`

**Errors**:
- `EACCES` — write permission denied
- `EAGAIN` — `IPC_NOWAIT` and queue full
- `EFAULT` — bad pointer
- `EIDRM` — queue removed while blocked
- `EINTR` — interrupted by signal
- `EINVAL` — invalid ID; `mtype ≤ 0`; `msgsz < 0` or > `MSGMAX`
- `ENOMEM` — insufficient memory

### msgrcv

`msgrcv(msqid, msgp, msgsz, msgtyp, msgflg) → bytes_received`

**Success**: Returns message body size.
- `msgtyp = 0` → any; `> 0` → that type; `< 0` → lowest ≤ |msgtyp|
- `MSG_NOERROR` → truncate oversized; `MSG_EXCEPT` → first NOT of type; `MSG_COPY` → copy without removing

**Errors**:
- `E2BIG` — message > `msgsz` and no `MSG_NOERROR`
- `EACCES` — read permission denied
- `EFAULT` — bad pointer
- `EIDRM` — queue removed while blocked
- `EINTR` — interrupted by signal
- `EINVAL` — invalid ID; `msgsz < 0`
- `ENOMSG` — `IPC_NOWAIT` and no matching message

### msgctl

`msgctl(msqid, cmd, buf) → 0`

**Success**: Returns 0.
- `IPC_STAT`/`IPC_SET`/`IPC_RMID`
- `IPC_RMID` → blocked senders/receivers get `EIDRM`

**Errors**:
- `EACCES` — `IPC_STAT` without read permission
- `EFAULT` — bad pointer
- `EIDRM` — already removed
- `EINVAL` — invalid ID or cmd; or `msg_qbytes` exceeds limit
- `EPERM` — `IPC_SET`/`IPC_RMID` without permission
