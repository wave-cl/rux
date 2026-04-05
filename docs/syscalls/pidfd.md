## PID File Descriptors

### pidfd_open

`pidfd_open(pid, flags) → fd`

**Success**: Returns fd referring to process.
- fd remains valid even after process exits (race-free PID handling)

**Errors**:
- `EINVAL` — invalid flags; or PID ≤ 0
- `EMFILE` — process fd limit
- `ENFILE` — system fd limit
- `ENOMEM` — insufficient memory
- `ESRCH` — process with given PID not found

### pidfd_send_signal

`pidfd_send_signal(pidfd, sig, info, flags) → 0`

**Success**: Returns 0. Race-free signal delivery.
- `info = NULL` → default `siginfo_t` filled automatically
- Custom `info.si_code` must be `SI_QUEUE` or similar

**Errors**:
- `EBADF` — pidfd not valid
- `EINVAL` — invalid signal; or invalid `flags`; or `info.si_code` invalid
- `EPERM` — no permission to send signal to target
- `ESRCH` — process referred to by pidfd has already exited

### pidfd_getfd

`pidfd_getfd(pidfd, targetfd, flags) → fd`

**Success**: Returns new fd in caller, duplicated from target process.
- `targetfd` → fd number in target process to duplicate

**Errors**:
- `EBADF` — pidfd not valid; or `targetfd` not valid in target
- `EINVAL` — invalid `flags`
- `EMFILE` — process fd limit
- `ENFILE` — system fd limit
- `EPERM` — insufficient privilege (needs `PTRACE_MODE_ATTACH_REALCREDS`)
- `ESRCH` — target process has exited
