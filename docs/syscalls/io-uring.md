## Async I/O (io_uring)

### io_uring_setup

`io_uring_setup(entries, params) → fd`

**Success**: Returns fd. Creates submission and completion queues.
- `entries` → desired SQ depth (rounded to power of 2)
- `params` filled with sizes, offsets, features
- `IORING_SETUP_SQPOLL` → kernel polls SQ (reduces syscalls)
- `IORING_SETUP_IOPOLL` → busy-poll for completions

**Errors**:
- `EFAULT` — bad `params` pointer
- `EINVAL` — `entries` = 0 or > max; or unsupported flags; or `sq_thread_cpu` invalid with SQPOLL
- `EMFILE` — process fd limit
- `ENFILE` — system fd limit
- `ENOMEM` — insufficient memory
- `ENOSYS` — kernel doesn't support io_uring
- `EPERM` — `IORING_SETUP_SQPOLL` without `CAP_SYS_NICE`

### io_uring_enter

`io_uring_enter(fd, to_submit, min_complete, flags, sig) → sqes_consumed`

**Success**: Returns number of SQEs consumed.
- `to_submit` → SQEs to submit
- `min_complete` with `IORING_ENTER_GETEVENTS` → wait for CQEs
- `IORING_ENTER_SQ_WAKEUP` → wake SQPOLL thread

**Errors**:
- `EAGAIN` — CQ overflowed
- `EBADF` — fd not valid io_uring
- `EBUSY` — io_uring shutting down
- `EFAULT` — bad pointer in SQE or sig
- `EINTR` — interrupted while waiting
- `EINVAL` — flags invalid; or index out of bounds
- `EOPNOTSUPP` — unknown opcode in SQE

### io_uring_register

`io_uring_register(fd, opcode, arg, nr_args) → 0`

**Success**: Returns 0.
- `IORING_REGISTER_BUFFERS` / `IORING_UNREGISTER_BUFFERS` → fixed buffers
- `IORING_REGISTER_FILES` / `IORING_UNREGISTER_FILES` → fixed file table
- `IORING_REGISTER_EVENTFD` / `IORING_UNREGISTER_EVENTFD` → CQ eventfd

**Errors**:
- `EBADF` — fd not valid io_uring
- `EFAULT` — bad pointer
- `EINVAL` — unknown opcode; too many entries; already registered
- `EMFILE` — too many registered files
- `ENOMEM` — insufficient memory
- `ENXIO` — unregister when not registered
