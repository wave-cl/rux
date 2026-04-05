## Process Management

### getpid

`getpid() → pid`

**Success**: Returns process ID. Never fails.

### getppid

`getppid() → pid`

**Success**: Returns parent's PID. Never fails. Returns 1 if parent has exited (re-parented to init).

### gettid

`gettid() → tid`

**Success**: Returns thread ID of calling thread. Never fails.

### set_tid_address

`set_tid_address(tidptr) → tid`

**Success**: Returns caller's thread ID. Sets `clear_child_tid` pointer; kernel writes 0 there and wakes futex when thread exits.

No errors.

### fork

`fork() → child_pid | 0`

**Success**: Returns child PID in parent; 0 in child. Child is copy of parent (copy-on-write for `MAP_PRIVATE` mappings; `MAP_SHARED` mappings remain shared). All fds duplicated.

**Errors**:
- `EAGAIN` — process limit (`RLIMIT_NPROC`) reached; or system-wide process limit
- `ENOMEM` — insufficient memory for kernel structures or to copy page tables
- `ENOSYS` — not supported on this platform

### vfork

`vfork() → child_pid | 0`

**Success**: Returns child PID in parent; 0 in child. Parent suspended until child calls `execve` or `_exit`. Child shares parent's address space.

**Errors**: Same as `fork`.

### clone3

`clone3(cl_args, size) → child_tid | 0`

**Success**: Returns child TID in parent; 0 in child. Flexible process/thread creation via `clone_args` struct.
- `CLONE_VM` → shares address space
- `CLONE_FS` → shares root, cwd, umask
- `CLONE_FILES` → shares fd table
- `CLONE_SIGHAND` → shares signal handlers (requires `CLONE_VM`)
- `CLONE_THREAD` → same thread group (requires `CLONE_SIGHAND`)
- `CLONE_NEWNS`, `CLONE_NEWPID`, etc. → new namespaces
- `exit_signal` → signal sent to parent on child death
- `stack` + `stack_size` → child stack

**Errors**:
- `EAGAIN` — process limit reached
- `EBUSY` — `CLONE_THREAD` with conflicting PID/TID requests
- `EEXIST` — PID already exists in PID namespace (with `set_tid`)
- `EINVAL` — conflicting flags (e.g. `CLONE_THREAD` without `CLONE_SIGHAND`; `CLONE_SIGHAND` without `CLONE_VM`; `CLONE_FS` with `CLONE_NEWNS`); or bad `clone_args` size; or invalid signal; or `stack_size` is 0 with `stack` set
- `ENOMEM` — insufficient memory
- `ENOSPC` — `CLONE_NEWPID` and PID namespace limit reached
- `ENOSYS` — `clone3` not supported; kernel too old
- `EOPNOTSUPP` — `CLONE_NEWNS` combined with `CLONE_FS`; or unsupported flag
- `EPERM` — `CLONE_NEWNS`, `CLONE_NEWPID`, etc. without `CAP_SYS_ADMIN`; or `CLONE_NEWUSER` without permission
- `EUSERS` — `CLONE_NEWUSER` and user namespace limit reached

### execve

`execve(pathname, argv[], envp[]) → (no return on success)`

**Success**: Does not return. Process image replaced by new program. PID, open fds (without `FD_CLOEXEC`), signal mask preserved. Pending signals cleared. Signal handlers reset to `SIG_DFL`.

**Errors**:
- `E2BIG` — total argument + environment list too large
- `EACCES` — execute permission denied; or file is on `noexec` filesystem; or not a regular file
- `EFAULT` — bad pathname, argv, or envp pointer
- `EINVAL` — ELF binary has more than one `PT_INTERP` segment
- `EIO` — I/O error
- `EISDIR` — interpreter is a directory
- `ELIBBAD` — ELF interpreter not in recognizable format
- `ELOOP` — too many symlinks; or too many interpreter recursions
- `EMFILE` — process fd limit hit (internally needs fds for interpreter)
- `ENAMETOOLONG` — pathname too long
- `ENOENT` — file does not exist; or interpreter does not exist
- `ENOEXEC` — file not in recognizable executable format; no interpreter found
- `ENOMEM` — insufficient kernel memory
- `ENOTDIR` — path component not a directory
- `EPERM` — file has setuid/setgid but filesystem is `nosuid`; or process is being traced; or security module denies
- `ETXTBSY` — file open for writing by another process

### execveat

`execveat(dirfd, pathname, argv[], envp[], flags) → (no return on success)`

**Success**: Same as `execve` but resolves path relative to `dirfd`.
- `AT_FDCWD` → same as `execve`
- `AT_EMPTY_PATH` with fd pointing to executable → executes the fd itself
- `AT_SYMLINK_NOFOLLOW` → `ELOOP` if final component is symlink

**Errors**: Same as `execve` plus:
- `EBADF` — dirfd not valid (with relative path)
- `ELOOP` — `AT_SYMLINK_NOFOLLOW` and final component is symlink
- `ENOTDIR` — dirfd not a directory (with relative path)

### exit / exit_group

`exit(status) → (no return)`
`exit_group(status) → (no return)`

**Success**: Does not return. Process terminated. Exit status (low 8 bits) available to parent via `wait`. All fds closed, memory freed, children re-parented to init. `exit_group` terminates all threads.

No errors (never returns).

### wait4 / waitpid

`waitpid(pid, wstatus, options) → child_pid`
`wait4(pid, wstatus, options, rusage) → child_pid`

**Success**: Returns PID of child whose state changed. Fills `status` with exit info. `WIFEXITED`, `WIFSIGNALED`, `WIFSTOPPED`, `WIFCONTINUED` macros decode status.
- `WNOHANG` → returns 0 immediately if no child has changed state
- `WUNTRACED` → also report stopped children
- `WCONTINUED` → also report continued children
- `wait4` additionally fills `rusage` struct

**Errors**:
- `ECHILD` — no child matching spec exists; or `WNOHANG` with no waitable children
- `EFAULT` — bad `status` or `rusage` pointer
- `EINTR` — interrupted by signal (`WNOHANG` was not set)
- `EINVAL` — invalid options flags

### waitid

`waitid(idtype, id, infop, options) → 0`

**Success**: Returns 0. Fills `siginfo_t` with: `si_pid`, `si_uid`, `si_status`, `si_code` (`CLD_EXITED`, `CLD_KILLED`, `CLD_STOPPED`, `CLD_CONTINUED`).
- `P_PID` → wait for specific PID
- `P_PGID` → wait for any child in process group
- `P_ALL` → wait for any child
- `P_PIDFD` → wait for process referred to by pidfd
- `WNOHANG` → non-blocking
- `WNOWAIT` → peek without reaping

**Errors**:
- `ECHILD` — no matching child
- `EFAULT` — bad `siginfo` pointer
- `EINTR` — interrupted by signal
- `EINVAL` — invalid `idtype` or `options`
- `ESRCH` — `P_PIDFD` and pidfd not valid

### kill

`kill(pid, sig) → 0`

**Success**: Returns 0. Signal delivered or queued.
- `pid > 0` → send to that process
- `pid == 0` → send to all processes in caller's process group
- `pid == -1` → send to all processes caller can signal (except init)
- `pid < -1` → send to process group `|pid|`
- `sig == 0` → no signal sent; permission and existence check only

**Errors**:
- `EINVAL` — signal number invalid (< 0 or > max signal)
- `EPERM` — caller does not have permission to send to target (different real/saved UID and not root)
- `ESRCH` — no process or process group matching pid; or process is zombie

### tgkill

`tgkill(tgid, tid, sig) → 0`

**Success**: Returns 0. Sends signal to specific thread (`tid`) within thread group (`tgid`).

**Errors**:
- `EAGAIN` — resource limit on queued signals reached
- `EINVAL` — invalid signal number; or `tid`/`tgid` ≤ 0
- `EPERM` — no permission
- `ESRCH` — no thread with that `tid` in thread group `tgid`

### tkill

`tkill(tid, sig) → 0`

**Success**: Returns 0. Sends signal to thread `tid` (deprecated; use `tgkill`).

**Errors**: Same as `tgkill` minus `tgid` checks.

### getpriority

`getpriority(which, who) → nice_value + 20`

**Success**: Returns nice value + 20 (to make it always non-negative). Actual nice = return value - 20. Range: -20 (highest) to 19 (lowest).
- `PRIO_PROCESS`, `PRIO_PGRP`, `PRIO_USER` specify which entities

**Errors**:
- `EINVAL` — `which` not one of `PRIO_PROCESS`, `PRIO_PGRP`, `PRIO_USER`
- `ESRCH` — no matching process

### setpriority

`setpriority(which, who, prio) → 0`

**Success**: Returns 0.

**Errors**:
- `EACCES` — non-root caller attempted to lower nice value (raise priority) beyond current minimum
- `EINVAL` — `which` not valid
- `EPERM` — caller tried to change priority of process owned by different user (and is not root)
- `ESRCH` — no matching process

### getrusage

`getrusage(who, usage) → 0`

**Success**: Returns 0. Fills `rusage` struct with resource usage: user/system time, max RSS, page faults, block I/O, context switches.
- `RUSAGE_SELF` → calling process
- `RUSAGE_CHILDREN` → waited-for children
- `RUSAGE_THREAD` → calling thread only

**Errors**:
- `EFAULT` — bad `usage` pointer
- `EINVAL` — invalid `who`
