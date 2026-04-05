## Signals

### sigaction (rt_sigaction)

`sigaction(signum, act, oldact) → 0`

**Success**: Returns 0. Installs, queries, or removes signal handler for signal `signum`.
- `SIG_DFL` → default action
- `SIG_IGN` → ignore signal
- Custom handler → function called with signal number, `siginfo_t`, context
- `sa_mask` → signals blocked during handler execution
- `SA_RESETHAND` → reset to `SIG_DFL` after first delivery
- `SA_RESTART` → restart interrupted syscalls automatically
- `SA_NOCLDSTOP` → don't generate `SIGCHLD` for stopped children
- `SA_NOCLDWAIT` → don't create zombies for dead children
- `SA_SIGINFO` → handler receives full `siginfo_t`
- `SA_ONSTACK` → use alternate signal stack

**Errors**:
- `EFAULT` — bad `act` or `oldact` pointer
- `EINVAL` — invalid signal number; or signal is `SIGKILL` or `SIGSTOP` (cannot be caught/ignored)

### sigprocmask (rt_sigprocmask)

`sigprocmask(how, set, oldset) → 0`

**Success**: Returns 0. Modifies blocked signal mask.
- `SIG_BLOCK` → adds set to current mask
- `SIG_UNBLOCK` → removes set from current mask
- `SIG_SETMASK` → replaces mask with set
- `SIGKILL` and `SIGSTOP` silently ignored if included (cannot be blocked)

**Errors**:
- `EFAULT` — bad `set` or `oldset` pointer
- `EINVAL` — invalid `how` value; or invalid `sigsetsize`

### sigpending (rt_sigpending)

`sigpending(set) → 0`

**Success**: Returns 0. Fills set with signals that are both pending and blocked.

**Errors**:
- `EFAULT` — bad `set` pointer

### sigtimedwait (rt_sigtimedwait)

`sigtimedwait(set, info, timeout) → signum`

**Success**: Returns signal number. Dequeues a pending signal from `set`. Fills `info` with signal details.

**Errors**:
- `EAGAIN` — timeout elapsed with no pending signal from `set`
- `EFAULT` — bad pointer
- `EINTR` — interrupted by an unblocked signal (not in `set`)
- `EINVAL` — invalid timeout (negative `tv_nsec`); or `sigsetsize` invalid

### sigaltstack

`sigaltstack(ss, old_ss) → 0`

**Success**: Returns 0. Configures alternate signal stack.
- `ss = NULL` → query only (fills `old_ss`)
- `ss->ss_flags = SS_DISABLE` → disable alternate stack
- Otherwise: `ss->ss_sp` and `ss->ss_size` define new stack

**Errors**:
- `EFAULT` — bad pointer
- `EINVAL` — `ss->ss_flags` has invalid bits; or `ss->ss_size` < `MINSIGSTKSZ`
- `ENOMEM` — insufficient size for alternate stack
- `EPERM` — currently executing on the alternate stack (cannot change it)

### sigreturn (rt_sigreturn)

`sigreturn() → (no return — restores interrupted context)`

**Success**: Does not return normally. Restores saved register state, signal mask, and stack pointer from signal frame. Execution resumes at point of interruption.

No user-visible errors (kernel internal).
