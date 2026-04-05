## Security

### seccomp

`seccomp(operation, flags, args) → 0`

**Success**: Returns 0 (or positive for `SECCOMP_GET_ACTION_AVAIL`).
- `SECCOMP_SET_MODE_STRICT` → only `read`, `write`, `_exit`, `sigreturn`; all others → `SIGKILL`
- `SECCOMP_SET_MODE_FILTER` → install BPF filter deciding per-syscall action
- Filter actions: `ALLOW`, `KILL`, `KILL_PROCESS`, `TRAP`, `ERRNO(val)`, `TRACE`, `LOG`
- Filters inherited by children; cannot be removed once installed

**Errors**:
- `EACCES` — `SECCOMP_SET_MODE_FILTER` and caller lacks `CAP_SYS_ADMIN` and `PR_SET_NO_NEW_PRIVS` not set
- `EFAULT` — bad `args` pointer; or BPF filter has bad pointer
- `EINVAL` — unknown `operation`; or bad `flags`; or BPF filter invalid
- `ENOMEM` — insufficient memory
- `ENOSYS` — seccomp not compiled into kernel
- `ESRCH` — thread synchronization failed (with `SECCOMP_FILTER_FLAG_TSYNC`)
