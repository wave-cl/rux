## Memory Management

### mmap

`mmap(addr, length, prot, flags, fd, offset) → address`

**Success**: Returns address of mapped region. Mapping has requested protection and flags.
- `MAP_ANONYMOUS | MAP_PRIVATE` → zero-filled private pages
- `MAP_ANONYMOUS | MAP_SHARED` → shared anonymous pages (inherited across fork)
- File-backed `MAP_PRIVATE` → copy-on-write; writes don't affect file
- File-backed `MAP_SHARED` → writes visible in file and to other mappers
- `MAP_FIXED` → mapping at exact address; replaces any existing mapping in range
- `MAP_POPULATE` → prefault pages into memory

**Errors**:
- `EACCES` — file not open for reading; or `MAP_SHARED | PROT_WRITE` but file not open for writing; or file is append-only but `PROT_WRITE` requested
- `EAGAIN` — file locked, and too many locked pages
- `EBADF` — fd not valid (and not `MAP_ANONYMOUS`)
- `EEXIST` — `MAP_FIXED_NOREPLACE` and address range already occupied
- `EINVAL` — length is 0; or addr not page-aligned for `MAP_FIXED`; or invalid flags (neither `MAP_SHARED` nor `MAP_PRIVATE`); or `offset` not page-aligned
- `ENFILE` — system file table limit
- `ENODEV` — underlying filesystem does not support memory mapping
- `ENOMEM` — insufficient memory; or process mapping count exceeds `vm.max_map_count`; or address space would exceed `RLIMIT_AS`
- `EOVERFLOW` — on 32-bit: file offset + length exceeds 2^32
- `EPERM` — `PROT_EXEC` denied by file seal or mount flags; operation locked by `mlock`

### munmap

`munmap(addr, length) → 0`

**Success**: Returns 0. Unmaps pages in given address range. Accessing unmapped pages → `SIGSEGV`.

**Errors**:
- `EINVAL` — addr not page-aligned; or length is 0; or range not within valid process address space

### mprotect

`mprotect(addr, len, prot) → 0`

**Success**: Returns 0. Changes protection on pages in address range.
- `PROT_NONE` — no access
- `PROT_READ` — read
- `PROT_WRITE` — write
- `PROT_EXEC` — execute
- Violation of protection → `SIGSEGV`

**Errors**:
- `EACCES` — cannot grant requested protection (e.g. `PROT_WRITE` on `MAP_PRIVATE` mapping of read-only file when writes would need write-back)
- `EINVAL` — addr not page-aligned; or invalid prot flags
- `ENOMEM` — range includes unmapped pages; or would exceed process memory limits

### mremap

`mremap(old_address, old_size, new_size, flags[, new_address]) → address`

**Success**: Returns new address of mapping. May differ from old if `MREMAP_MAYMOVE`.

**Errors**:
- `EAGAIN` — locked pages cannot be moved
- `EFAULT` — old address range includes unmapped pages
- `EINVAL` — old_address not page-aligned; or invalid flags; or new_size is 0
- `ENOMEM` — cannot grow in place and `MREMAP_MAYMOVE` not set; or process address space limit reached

### msync

`msync(addr, length, flags) → 0`

**Success**: Returns 0. Flushes changes to `MAP_SHARED` mapping back to file.
- `MS_SYNC` → synchronous flush; blocks until complete
- `MS_ASYNC` → initiates flush; returns immediately
- `MS_INVALIDATE` → invalidates cached copies

**Errors**:
- `EBUSY` — `MS_INVALIDATE` but range has locked pages
- `EINVAL` — addr not page-aligned; or invalid flags (both `MS_SYNC` and `MS_ASYNC`)
- `ENOMEM` — range includes unmapped pages

### mlock / munlock

`mlock(addr, len) → 0`
`munlock(addr, len) → 0`

**Success**: Returns 0.
- `mlock` → locks pages in RAM; no swapping
- `munlock` → pages eligible for swapping again

**Errors**:
- `EAGAIN` — some pages could not be locked (e.g. mapped from file with holes)
- `EINVAL` — addr + len wraps around; or len ≤ 0
- `ENOMEM` — would exceed `RLIMIT_MEMLOCK`; or range includes unmapped pages
- `EPERM` — caller not privileged and exceeds lock limit

### mlock2

`mlock2(addr, len, flags) → 0`

**Success**: Returns 0. Like `mlock` with flags.
- `MLOCK_ONFAULT` → pages locked on first access rather than immediately

**Errors**: Same as `mlock` plus:
- `EINVAL` — unknown flags

### mlockall / munlockall

`mlockall(flags) → 0`
`munlockall() → 0`

**Success**: Returns 0.
- `mlockall(MCL_CURRENT)` → locks all currently mapped pages
- `mlockall(MCL_FUTURE)` → future mappings also locked
- `munlockall` → unlocks everything

**Errors (mlockall)**:
- `EINVAL` — unknown flags
- `ENOMEM` — would exceed `RLIMIT_MEMLOCK`
- `EPERM` — not privileged and exceeds lock limit

**Errors (munlockall)**: None on Linux.

### madvise

`madvise(addr, length, advice) → 0`

**Success**: Returns 0. Advisory hint about expected access pattern.
- `MADV_NORMAL` — default behavior
- `MADV_SEQUENTIAL` — expect sequential access
- `MADV_RANDOM` — expect random access
- `MADV_WILLNEED` — expect access soon; prefetch
- `MADV_DONTNEED` — not needed soon; kernel may free pages; next access re-faults zero pages (anonymous) or re-reads from file (file-backed)
- `MADV_FREE` — pages may be freed when under memory pressure (lazy)
- `MADV_REMOVE` — free underlying swap/file space (shared mapping only)

**Errors**:
- `EACCES` — `MADV_REMOVE` on non-shared mapping
- `EAGAIN` — kernel resources temporarily unavailable
- `EBADF` — mapping exists but not file-backed (for some advice)
- `EINVAL` — addr not page-aligned; or len negative; or unknown advice
- `EIO` — paging error on `MADV_WILLNEED`
- `ENOMEM` — range includes unmapped pages; or `MADV_WILLNEED` and insufficient memory to fault in

### mincore

`mincore(addr, length, vec) → 0`

**Success**: Returns 0. Fills vector with page residency (1 = in RAM, 0 = not).

**Errors**:
- `EAGAIN` — kernel resources not available
- `EFAULT` — bad vec pointer
- `EINVAL` — addr not page-aligned
- `ENOMEM` — range includes unmapped pages

### brk

`brk(addr) → new_break`

**Success**: Returns new program break. On failure, returns current break unchanged.
- Requesting address at or below current break → returns current break
- Growing break allocates zero-filled memory

**Errors**: Returns current break unchanged on failure (not `MAP_FAILED`; check return vs. requested).

### membarrier

`membarrier(cmd, flags, cpu_id) → 0`

**Success**: Returns 0 for barrier commands. Returns bitmask for `MEMBARRIER_CMD_QUERY`.
- `MEMBARRIER_CMD_QUERY` → returns supported commands
- `MEMBARRIER_CMD_GLOBAL` → system-wide memory barrier
- `MEMBARRIER_CMD_PRIVATE_EXPEDITED` → barrier in calling process threads

**Errors**:
- `EINVAL` — unknown command
- `ENOSYS` — not supported
- `EPERM` — `MEMBARRIER_CMD_GLOBAL_EXPEDITED` requires registration first
