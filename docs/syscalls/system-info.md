## System Information & Control

### uname

`uname(buf) → 0`

**Success**: Returns 0. Fills `utsname`: `sysname`, `nodename`, `release`, `version`, `machine`, `domainname`.

**Errors**:
- `EFAULT` — bad pointer

### sysinfo

`sysinfo(info) → 0`

**Success**: Returns 0. Fills struct: `uptime`, `loads[3]`, `totalram`, `freeram`, `sharedram`, `bufferram`, `totalswap`, `freeswap`, `procs`, `totalhigh`, `freehigh`, `mem_unit`.

**Errors**:
- `EFAULT` — bad pointer

### gethostname

`gethostname(name, len) → 0`

**Success**: Returns 0. Null-terminated hostname in buffer.

**Errors**:
- `EFAULT` — bad pointer
- `EINVAL` — `len` < 0
- `ENAMETOOLONG` — hostname exceeds `len`

### sethostname

`sethostname(name, len) → 0`

**Success**: Returns 0.

**Errors**:
- `EFAULT` — bad pointer
- `EINVAL` — `len` < 0 or > max hostname length
- `EPERM` — caller lacks `CAP_SYS_ADMIN`

### getdomainname / setdomainname

`getdomainname(name, len) → 0`
`setdomainname(name, len) → 0`

**Success/Errors**: Same as hostname equivalents.

### syslog (klogctl)

`klogctl(type, bufp, len) → bytes | size`

**Success**: Returns bytes read or buffer size, depending on `type`.
- Type 2 → read and clear ring buffer
- Type 3 → read entire ring buffer
- Type 4 → read and clear
- Type 5 → clear
- Type 6 / 7 → disable/enable console logging
- Type 8 → set console log level
- Type 9 → return buffer size
- Type 10 → return unread count

**Errors**:
- `EFAULT` — bad buffer pointer
- `EINVAL` — bad `type`; or `len` negative; or bad log level
- `ENOSYS` — not implemented
- `EPERM` — caller lacks `CAP_SYSLOG` or `CAP_SYS_ADMIN`

### reboot

`reboot(magic, magic2, cmd, arg) → 0 | (no return)`

**Success**: Does not return (system reboots/halts/powers off). Or returns 0 for `CAD_ON`/`CAD_OFF`.
- Requires magic numbers: `LINUX_REBOOT_MAGIC1` (0xfee1dead) and one of MAGIC2 variants
- `LINUX_REBOOT_CMD_RESTART` → reboot
- `LINUX_REBOOT_CMD_HALT` → halt
- `LINUX_REBOOT_CMD_POWER_OFF` → power off
- `LINUX_REBOOT_CMD_CAD_ON` / `CAD_OFF` → enable/disable Ctrl-Alt-Del

**Errors**:
- `EFAULT` — bad pointer (for `RESTART2` with custom command)
- `EINVAL` — bad magic numbers or command
- `EPERM` — caller lacks `CAP_SYS_BOOT`
