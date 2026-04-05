## Process Groups & Sessions

### setpgid

`setpgid(pid, pgid) → 0`

**Success**: Returns 0. Sets PGID of process `pid` to `pgid`.
- `pid == 0` → calling process
- `pgid == 0` → PGID set to PID of target process

**Errors**:
- `EACCES` — child has already called `execve`
- `EINVAL` — `pgid < 0`
- `EPERM` — moving process to different session; target already session leader; or target is not caller or caller's child
- `ESRCH` — `pid` does not match caller or caller's child

### getpgid

`getpgid(pid) → pgid`

**Success**: Returns PGID of process `pid`. `pid == 0` → returns caller's PGID.

**Errors**:
- `EPERM` — process exists but in different session (some implementations)
- `ESRCH` — no process with that PID

### setsid

`setsid() → new_sid`

**Success**: Returns new session ID (equals caller's PID). Caller becomes session leader and process group leader. No controlling terminal.

**Errors**:
- `EPERM` — caller is already a process group leader (PID == existing PGID)

### getsid

`getsid(pid) → sid`

**Success**: Returns session ID of process `pid`. `pid == 0` → caller's SID.

**Errors**:
- `EPERM` — process in different session (some implementations)
- `ESRCH` — no process with that PID
