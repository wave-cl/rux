## Pipes

### pipe / pipe2

`pipe(pipefd[2]) → 0`
`pipe2(pipefd[2], flags) → 0`

**Success**: Returns 0. Creates pipe. `pipefd[0]` = read end, `pipefd[1]` = write end.
- Data written to write end readable from read end in FIFO order
- `pipe2` accepts `O_CLOEXEC`, `O_NONBLOCK`, `O_DIRECT` flags
- Pipe has a finite capacity (`/proc/sys/fs/pipe-max-size`; typically 64 KiB)
- Read from empty pipe with writers → blocks (or `EAGAIN` if `O_NONBLOCK`)
- Read from empty pipe with no writers → returns 0 (EOF)
- Write to pipe with no readers → `EPIPE` + `SIGPIPE`
- Write to full pipe → blocks (or `EAGAIN` if `O_NONBLOCK`)
- Writes ≤ `PIPE_BUF` (4096) are atomic

**Errors**:
- `EFAULT` — bad `pipefd` pointer
- `EINVAL` — `pipe2`: invalid flags
- `EMFILE` — process fd limit (need two fds)
- `ENFILE` — system fd limit
