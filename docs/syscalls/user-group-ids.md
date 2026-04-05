## User & Group IDs

### getuid / geteuid / getgid / getegid

`getuid() → uid`
`geteuid() → euid`
`getgid() → gid`
`getegid() → egid`

**Success**: Returns real/effective UID/GID respectively. Never fail.

### getresuid / getresgid

`getresuid(ruid, euid, suid) → 0`
`getresgid(rgid, egid, sgid) → 0`

**Success**: Returns 0. Writes real, effective, and saved-set UID/GID into three pointers.

**Errors**:
- `EFAULT` — bad pointer

### setuid

`setuid(uid) → 0`

**Success**: Returns 0.
- Root: sets real, effective, and saved UID all to given value
- Non-root: may only set effective UID to real or saved UID

**Errors**:
- `EAGAIN` — temporarily unable (e.g. `RLIMIT_NPROC` would be exceeded by new UID)
- `EINVAL` — UID not valid in this user namespace
- `EPERM` — non-root and uid doesn't match real or saved UID

### setgid

`setgid(gid) → 0`

**Success/errors**: Same as `setuid` but for GID.

### setreuid / setregid

`setreuid(ruid, euid) → 0`
`setregid(rgid, egid) → 0`

**Success**: Returns 0. Sets real and effective UID/GID. `-1` means "no change".
- If real UID is set (or effective changes), saved UID becomes new effective UID

**Errors**:
- `EAGAIN` — `RLIMIT_NPROC` exceeded
- `EINVAL` — UID/GID not valid
- `EPERM` — non-root and target UID/GID not among current real, effective, or saved values

### setresuid / setresgid

`setresuid(ruid, euid, suid) → 0`
`setresgid(rgid, egid, sgid) → 0`

**Success**: Returns 0. Sets real, effective, and saved UID/GID independently. `-1` means "no change".

**Errors**:
- `EAGAIN` — `RLIMIT_NPROC` exceeded
- `EINVAL` — UID/GID not valid
- `EPERM` — non-root and any given value not among current real, effective, or saved values

### getgroups

`getgroups(size, list[]) → count`

**Success**: Returns number of supplemental group IDs. If `size > 0`, fills array. If `size == 0`, returns count without filling.

**Errors**:
- `EFAULT` — bad list pointer
- `EINVAL` — `size` < number of supplemental groups and `size` > 0

### setgroups

`setgroups(size, list[]) → 0`

**Success**: Returns 0. Replaces supplemental group list.

**Errors**:
- `EFAULT` — bad list pointer
- `EINVAL` — `size` > `NGROUPS_MAX`
- `ENOMEM` — out of memory
- `EPERM` — caller lacks `CAP_SETGID`

### setfsuid

`setfsuid(fsuid) → previous_fsuid`

**Success**: Returns previous filesystem UID. Sets UID used for filesystem permission checks.
- Succeeds only if new value matches real, effective, saved UID, or current fsuid (or caller is root)
- On failure, still returns previous fsuid (no error indicator)

### setfsgid

`setfsgid(fsgid) → previous_fsgid`

**Success/errors**: Same semantics as `setfsuid` but for GID.
