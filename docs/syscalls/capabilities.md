## Capabilities

### capget

`capget(hdrp, datap) → 0`

**Success**: Returns 0. Fills permitted, effective, and inheritable sets.
- `pid = 0` → caller's capabilities

**Errors**:
- `EFAULT` — bad pointer
- `EINVAL` — bad version in header struct
- `EPERM` — tried to query other process without permission
- `ESRCH` — no process with given PID

### capset

`capset(hdrp, datap) → 0`

**Success**: Returns 0.
- Cannot set capability not in own permitted set
- `pid = 0` → caller's capabilities

**Errors**:
- `EFAULT` — bad pointer
- `EINVAL` — bad version; or tried to set capability not in permitted set
- `EPERM` — insufficient privilege (need `CAP_SETPCAP` for another process)
