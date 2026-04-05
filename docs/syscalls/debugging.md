## Debugging & Tracing

### ptrace

`ptrace(request, pid, addr, data) → varies`

**Success**: Returns 0 or requested data depending on request.
- `PTRACE_TRACEME` → process becomes traceable by parent
- `PTRACE_ATTACH` → attaches to process; sends `SIGSTOP`
- `PTRACE_SEIZE` → like ATTACH but doesn't send SIGSTOP
- `PTRACE_DETACH` → detaches and resumes
- `PTRACE_PEEKDATA` → returns word from tracee memory at `addr`
- `PTRACE_POKEDATA` → writes word to tracee memory at `addr`
- `PTRACE_GETREGS` / `PTRACE_SETREGS` → get/set general registers
- `PTRACE_GETFPREGS` / `PTRACE_SETFPREGS` → get/set FP registers
- `PTRACE_CONT` → resume; optionally deliver signal
- `PTRACE_SINGLESTEP` → execute one instruction then stop
- `PTRACE_SYSCALL` → run until next syscall entry/exit
- `PTRACE_KILL` → sends `SIGKILL`
- `PTRACE_GETEVENTMSG` → get auxiliary event data

**Errors**:
- `EBUSY` — resource busy (e.g. certain PTRACE operations on running thread)
- `EFAULT` — bad `addr` or `data` pointer
- `EINVAL` — invalid request or option
- `EIO` — request invalid for this process state
- `EPERM` — no permission (target has higher privilege; or `/proc/sys/kernel/yama/ptrace_scope` restricts); or `PTRACE_TRACEME` but parent is not tracer
- `ESRCH` — target doesn't exist; or target not stopped when required; or target not being traced for operations requiring it

### kcmp

`kcmp(pid1, pid2, type, idx1, idx2) → 0 | ordering`

**Success**: Returns 0 if resources are equal; or ordering value.
- `KCMP_FILE`, `KCMP_VM`, `KCMP_FS`, `KCMP_FILES`, `KCMP_SIGHAND`, `KCMP_IO`, `KCMP_SYSVSEM`, `KCMP_EPOLL_TFD`

**Errors**:
- `EBADF` — bad fd for `KCMP_FILE`
- `EINVAL` — unknown `type`
- `EPERM` — insufficient privilege (needs `CAP_SYS_PTRACE`)
- `ESRCH` — PID not found

### process_vm_readv / process_vm_writev

`process_vm_readv(pid, local_iov, liovcnt, remote_iov, riovcnt, flags) → bytes_transferred`
`process_vm_writev(pid, local_iov, liovcnt, remote_iov, riovcnt, flags) → bytes_transferred`

**Success**: Returns bytes transferred. Reads/writes across process boundaries.

**Errors**:
- `EFAULT` — bad local or remote iov pointer
- `EINVAL` — `liovcnt` or `riovcnt` > `UIO_MAXIOV`; or count < 0; or `flags` != 0
- `ENOMEM` — insufficient memory for internal copies
- `EPERM` — insufficient privilege (needs ptrace access)
- `ESRCH` — no process with given PID
