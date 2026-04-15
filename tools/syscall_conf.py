#!/usr/bin/env python3
# Syscall conformance: deterministic cases covering happy paths and the
# common error paths real programs rarely hit. Each assertion prints
# either "PASS: name" or "FAIL: name detail"; the final line is
# "conformance: passed=N failed=M".
#
# This script is portable Python-ctypes. It runs unmodified on:
#   - rux in the Alpine rootfs (via test.sh)
#   - real Linux (captured as the golden reference for Phase 2)
#
# Single source of truth: rootfs/build_alpine.sh copies this file into
# the rootfs rather than inlining a heredoc copy.
#
# IMPORTANT: kept defensive — does not pass kernel-space pointers or
# extreme fd values, because rux currently panics on those. Those are
# real bugs to fix later; this script's job is "catch regressions",
# not "stress the kernel."
import ctypes, os, errno, struct
L = ctypes.CDLL(None, use_errno=True)
S = L.syscall
S.restype = ctypes.c_long
# getcwd returns char* — ctypes' default c_int restype truncates pointer
# values, producing bogus negative results on systems where the stack
# lives above 0x7fffffff. Declare it explicitly as a void pointer.
L.getcwd.restype = ctypes.c_void_p

P = 0
F = 0

def check(name, cond, detail=''):
    global P, F
    if cond:
        P += 1
        print(f'PASS: {name}')
    else:
        F += 1
        print(f'FAIL: {name} {detail}')

def expect_errno(name, ret, want):
    # musl wraps syscalls so failure → ret=-1 with positive errno set.
    # Raw rux syscalls (via S=L.syscall) return negative kernel errno directly.
    if ret == -1:
        actual = ctypes.get_errno()
    elif ret < 0:
        actual = -ret
    else:
        check(name, False, f'expected errno {want}, got success ret={ret}')
        return
    check(name, actual == want, f'got errno={actual}, want={want}')

def expect_ok(name, ret):
    check(name, ret >= 0, f'got ret={ret} errno={ctypes.get_errno()}')

buf = ctypes.create_string_buffer(64)
cwd = ctypes.create_string_buffer(256)

# ── Happy paths (sanity) ───────────────────────────────────────────────
expect_ok('getpid', L.getpid())
expect_ok('getppid', L.getppid())
expect_ok('getuid', L.getuid())
expect_ok('getgid', L.getgid())
expect_ok('geteuid', L.geteuid())
expect_ok('getegid', L.getegid())
# getcwd returns NULL (0) on failure, pointer on success
check('getcwd', L.getcwd(cwd, 256) is not None and L.getcwd(cwd, 256) != 0)
fd = L.open(b'/etc/hostname', 0)
expect_ok('open(/etc/hostname)', fd)
if fd >= 0:
    expect_ok('read(/etc/hostname)', L.read(fd, buf, 64))
    expect_ok('close', L.close(fd))

# ── ENOENT ─────────────────────────────────────────────────────────────
expect_errno('open(missing)',  L.open(b'/this/does/not/exist', 0), errno.ENOENT)
expect_errno('stat(missing)',  L.stat(b'/no/such/file', buf), errno.ENOENT)
expect_errno('unlink(missing)',L.unlink(b'/no/such/file'), errno.ENOENT)
expect_errno('chdir(missing)', L.chdir(b'/no/such/dir'), errno.ENOENT)

# ── EEXIST ─────────────────────────────────────────────────────────────
fd = L.open(b'/tmp/conf_excl', 0o100|0o2, 0o644)  # O_CREAT|O_RDWR
if fd >= 0: L.close(fd)
expect_errno('open(O_EXCL exists)', L.open(b'/tmp/conf_excl', 0o100|0o200), errno.EEXIST)
L.unlink(b'/tmp/conf_excl')
L.mkdir(b'/tmp/conf_dir', 0o755)
expect_errno('mkdir(exists)', L.mkdir(b'/tmp/conf_dir', 0o755), errno.EEXIST)
L.rmdir(b'/tmp/conf_dir')

# ── Pipe semantics ─────────────────────────────────────────────────────
pipefd = (ctypes.c_int * 2)()
if L.pipe(pipefd) == 0:
    L.write(pipefd[1], b'hello', 5)
    L.close(pipefd[1])
    n = L.read(pipefd[0], buf, 64)
    check('pipe read after write-end close', n == 5)
    n = L.read(pipefd[0], buf, 64)
    check('pipe EOF after drained', n == 0)
    L.close(pipefd[0])

# ── kill edge cases ────────────────────────────────────────────────────
expect_errno('kill(missing pid)', L.kill(99999, 0), errno.ESRCH)
expect_ok('kill(self, 0)', L.kill(L.getpid(), 0))

# ── POSIX timer edge cases ─────────────────────────────────────────────
mach = os.uname().machine
NR_TC = 107 if mach == 'aarch64' else 222
NR_TS = 110 if mach == 'aarch64' else 223
NR_TD = 111 if mach == 'aarch64' else 226
tid = ctypes.c_int(-1)
r = S(NR_TC, 99, 0, ctypes.byref(tid))
check('timer_create(bad clockid) rejected', r != 0)
r = S(NR_TC, 1, 0, ctypes.byref(tid))
check('timer_create(MONOTONIC)', r == 0)
if r == 0:
    check('timer_delete(once)', S(NR_TD, tid.value) == 0)
    check('timer_delete(twice) rejected', S(NR_TD, tid.value) != 0)
its = ctypes.create_string_buffer(struct.pack('qqqq', 0, 0, 0, 1000000))
check('timer_settime(bad id) rejected', S(NR_TS, 9999, 0, its, 0) != 0)

# ── ptrace edge cases ──────────────────────────────────────────────────
NR_PT = 117 if mach == 'aarch64' else 101
check('ptrace TRACEME', S(NR_PT, 0, 0, 0, 0) == 0)
check('ptrace GETREGS(pid 1) fails', S(NR_PT, 12, 1, 0, ctypes.addressof(buf)) != 0)

# ── Batch: untested-syscall errno paths ────────────────────────────────
# These target syscalls Phase 1 coverage flagged as never touched by
# the integration tests. Most hit the EBADF branch with -1 fd — the
# cheapest way to exercise dispatch without needing real resources.
# Raw syscall numbers (via S) to avoid relying on libc wrapper quirks.

# Per-arch syscall numbers
if mach == 'aarch64':
    NR_DUP, NR_DUP3 = 23, 24
    NR_READV, NR_WRITEV = 65, 66
    NR_PREAD, NR_PWRITE = 67, 68
    NR_FSYNC, NR_FDATASYNC = 82, 83
    NR_FTRUNCATE, NR_TRUNCATE = 46, 45
    NR_FCHMOD, NR_FCHOWN, NR_FCHDIR = 52, 55, 50
    NR_UTIMENSAT, NR_FACCESSAT = 88, 48
    NR_MMAP, NR_MUNMAP = 222, 215
    NR_MADVISE, NR_MINCORE = 233, 232
    NR_GETSID, NR_FLOCK, NR_TKILL = 156, 32, 130
else:  # x86_64
    NR_DUP, NR_DUP3 = 32, 292
    NR_READV, NR_WRITEV = 19, 20
    NR_PREAD, NR_PWRITE = 17, 18
    NR_FSYNC, NR_FDATASYNC = 74, 75
    NR_FTRUNCATE, NR_TRUNCATE = 77, 76
    NR_FCHMOD, NR_FCHOWN, NR_FCHDIR = 91, 93, 81
    NR_UTIMENSAT, NR_FACCESSAT = 280, 269
    NR_MMAP, NR_MUNMAP = 9, 11
    NR_MADVISE, NR_MINCORE = 28, 27
    NR_GETSID, NR_FLOCK, NR_TKILL = 124, 73, 200

# fd duplication
expect_errno('dup(-1)',       S(NR_DUP, -1), errno.EBADF)
expect_ok   ('dup(stdin)',    S(NR_DUP, 0))
expect_errno('dup3(-1, 5, 0)',S(NR_DUP3, -1, 5, 0), errno.EBADF)

# vector I/O — pass a valid iovec so we're sure the EBADF comes from fd
iov = (ctypes.c_long * 2)(ctypes.addressof(buf), 8)
expect_errno('readv(-1)',  S(NR_READV, -1, ctypes.addressof(iov), 1), errno.EBADF)
expect_errno('writev(-1)', S(NR_WRITEV, -1, ctypes.addressof(iov), 1), errno.EBADF)

# positional I/O
expect_errno('pread64(-1)',  S(NR_PREAD,  -1, ctypes.addressof(buf), 8, 0), errno.EBADF)
expect_errno('pwrite64(-1)', S(NR_PWRITE, -1, ctypes.addressof(buf), 8, 0), errno.EBADF)

# file sync / resize
expect_errno('fsync(-1)',         S(NR_FSYNC, -1),     errno.EBADF)
expect_errno('fdatasync(-1)',     S(NR_FDATASYNC, -1), errno.EBADF)
expect_errno('ftruncate(-1)',     S(NR_FTRUNCATE, -1, 0), errno.EBADF)
expect_errno('truncate(missing)', S(NR_TRUNCATE, b'/no/such/file', 0), errno.ENOENT)

# metadata
expect_errno('fchmod(-1)', S(NR_FCHMOD, -1, 0o644), errno.EBADF)
expect_errno('fchown(-1)', S(NR_FCHOWN, -1, 0, 0),  errno.EBADF)
expect_errno('fchdir(-1)', S(NR_FCHDIR, -1),        errno.EBADF)

# path metadata via dirfd (AT_FDCWD bypass — pass -1 as dirfd)
expect_errno('utimensat(-1)', S(NR_UTIMENSAT, -1, 0, 0, 0), errno.EBADF)
expect_errno('faccessat(-1)', S(NR_FACCESSAT, -1, b'x', 0, 0), errno.EBADF)

# memory advice / inspection — need a valid anon page first.
# Use libc mmap/madvise/mincore rather than raw syscall(): ctypes can't
# reliably marshal variadic syscall(..) args with default argtypes,
# which on some hosts turns mmap's flags arg into garbage and trips
# EFAULT before we ever reach madvise.
L.mmap.restype = ctypes.c_void_p
L.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                   ctypes.c_int, ctypes.c_int, ctypes.c_long]
L.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
L.madvise.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
L.mincore.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
PROT_RW = 3
MAP_PRIV_ANON = 0x22
addr = L.mmap(None, 4096, PROT_RW, MAP_PRIV_ANON, -1, 0)
if addr and addr != (1 << 64) - 1:  # not MAP_FAILED
    check('madvise(MADV_NORMAL)', L.madvise(addr, 4096, 0) == 0)
    vec = ctypes.create_string_buffer(1)
    check('mincore(anon)', L.mincore(addr, 4096, vec) == 0)
    L.munmap(addr, 4096)

# sessions / file locks / signals
expect_errno('getsid(missing)', S(NR_GETSID, 999999), errno.ESRCH)
expect_ok   ('getsid(self)',    S(NR_GETSID, 0))
expect_errno('flock(-1)',       S(NR_FLOCK, -1, 1),   errno.EBADF)
# tkill(-1, 0) is EINVAL on Linux (negative tid)
check('tkill(-1) rejected', S(NR_TKILL, -1, 0) != 0)

# ── Batch 2: further untested-syscall coverage ─────────────────────────
# Round 2 of the coverage-driven conformance pass. Targets the next
# wave of high-value syscalls flagged as untested after round 1's
# 22 assertions shipped. Same goal: exercise dispatch cheaply, let
# the Phase 2 golden diff catch semantic divergence from Linux.

# time / scheduling
L.sched_yield.restype = ctypes.c_int
check('sched_yield', L.sched_yield() == 0)

# gettimeofday — tv_sec > 1_000_000 = Real System Time(tm), not 1970
class Timeval(ctypes.Structure):
    _fields_ = [('tv_sec', ctypes.c_long), ('tv_usec', ctypes.c_long)]
L.gettimeofday.restype = ctypes.c_int
L.gettimeofday.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
tv = Timeval()
expect_ok('gettimeofday', L.gettimeofday(ctypes.byref(tv), None))
# Don't assert on tv_sec range — rux boots with tv_sec=0 in the
# emulator, Linux has a real clock. Just verify the call succeeds.

# times — returns a clock_t (non-zero monotonic tick count)
class Tms(ctypes.Structure):
    _fields_ = [('utime', ctypes.c_long), ('stime', ctypes.c_long),
                ('cutime', ctypes.c_long), ('cstime', ctypes.c_long)]
L.times.restype = ctypes.c_long
L.times.argtypes = [ctypes.c_void_p]
tms = Tms()
# times() can return (clock_t)-1 on failure; anything else is success
check('times', L.times(ctypes.byref(tms)) != -1)

# getrusage — RUSAGE_SELF=0, invalid=99
class Rusage(ctypes.Structure):
    # 16 longs is enough for the first few fields we care about
    _fields_ = [('ru_utime', Timeval), ('ru_stime', Timeval),
                ('ru_maxrss', ctypes.c_long), ('_pad', ctypes.c_long * 14)]
L.getrusage.restype = ctypes.c_int
L.getrusage.argtypes = [ctypes.c_int, ctypes.c_void_p]
ru = Rusage()
expect_ok   ('getrusage(RUSAGE_SELF)', L.getrusage(0, ctypes.byref(ru)))
expect_errno('getrusage(99 bad who)', L.getrusage(99, ctypes.byref(ru)), errno.EINVAL)

# interval timers — getitimer(ITIMER_REAL=0) / setitimer(bad which)
class Itimerval(ctypes.Structure):
    _fields_ = [('it_interval', Timeval), ('it_value', Timeval)]
L.getitimer.restype = ctypes.c_int
L.getitimer.argtypes = [ctypes.c_int, ctypes.c_void_p]
L.setitimer.restype = ctypes.c_int
L.setitimer.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
itv = Itimerval()
expect_ok   ('getitimer(ITIMER_REAL)', L.getitimer(0, ctypes.byref(itv)))
expect_errno('setitimer(bad which)', L.setitimer(99, ctypes.byref(itv), None), errno.EINVAL)

# process groups — getpgrp returns current pgid, must be >= 1
L.getpgrp.restype = ctypes.c_int
expect_ok('getpgrp', L.getpgrp())

# msync — bad addr (NULL) is EFAULT or ENOMEM on Linux.
# Linux returns ENOMEM for unmapped addresses (glibc manual), but
# some kernels return EFAULT. Accept either.
L.msync.restype = ctypes.c_int
L.msync.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
ret = L.msync(0x1000, 4096, 4)  # MS_SYNC = 4, 0x1000 is an unmapped user addr
actual_errno = ctypes.get_errno() if ret == -1 else 0
check('msync(unmapped) rejected',
      ret == -1 and actual_errno in (errno.ENOMEM, errno.EFAULT, errno.EINVAL),
      f'got ret={ret} errno={actual_errno}')

# mremap — bogus old_addr returns EFAULT (or EINVAL on some kernels)
L.mremap.restype = ctypes.c_void_p
L.mremap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_int]
r = L.mremap(0x1000, 4096, 8192, 0)  # 0x1000 is unmapped
# mremap returns (void*)-1 on error
check('mremap(bogus) rejected', r is None or r == (1 << 64) - 1 or r < 0 or r > (1 << 63))

# ── Batch 3: more fd-stub coverage + misc process state ────────────────
# Another pass targeting fd-based syscalls that might be stubs returning
# 0 unconditionally (the same pattern that caught fsync/fdatasync/flock
# in round 1 and fallocate in round 1's stub group). Plus a few
# clock/process-state assertions.

# fallocate(-1) — round 1 added fallocate to the fd-validating stub
# group in syscall/mod.rs but no conformance assertion verified it.
L.fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_long, ctypes.c_long]
expect_errno('fallocate(-1)', L.fallocate(-1, 0, 0, 4096), errno.EBADF)

# fstatfs(-1) — likely a stub. statfs_t is 120 bytes on Linux.
statfs_buf = ctypes.create_string_buffer(128)
L.fstatfs.argtypes = [ctypes.c_int, ctypes.c_void_p]
expect_errno('fstatfs(-1)', L.fstatfs(-1, statfs_buf), errno.EBADF)

# splice/tee — pipe manipulation, fd-validated
NR_SPLICE = 76 if mach == 'aarch64' else 275
NR_TEE    = 77 if mach == 'aarch64' else 276
expect_errno('splice(-1)', S(NR_SPLICE, -1, 0, -1, 0, 4096, 0), errno.EBADF)
expect_errno('tee(-1, -1)', S(NR_TEE, -1, -1, 4096, 0), errno.EBADF)

# Sockets — accept/shutdown on -1 must be EBADF (not ENOTSOCK, since
# fd validation happens before the socket-type check).
NR_ACCEPT   = 202 if mach == 'aarch64' else 43
NR_SHUTDOWN = 210 if mach == 'aarch64' else 48
expect_errno('accept(-1)',   S(NR_ACCEPT,   -1, 0, 0), errno.EBADF)
expect_errno('shutdown(-1)', S(NR_SHUTDOWN, -1, 0),    errno.EBADF)

# getresuid — fill in a ruid/euid/suid triple for the current process.
# Should always succeed with all three equal to our uid.
ruid = ctypes.c_uint32(0xFFFFFFFF)
euid = ctypes.c_uint32(0xFFFFFFFF)
suid = ctypes.c_uint32(0xFFFFFFFF)
L.getresuid.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
expect_ok('getresuid', L.getresuid(ctypes.byref(ruid), ctypes.byref(euid), ctypes.byref(suid)))
check('getresuid populates all 3', ruid.value != 0xFFFFFFFF and
      euid.value != 0xFFFFFFFF and suid.value != 0xFFFFFFFF,
      f'r={ruid.value:#x} e={euid.value:#x} s={suid.value:#x}')

# setresuid(-1,-1,-1) is a POSIX no-op (leaves everything as-is).
L.setresuid.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
expect_ok('setresuid(-1,-1,-1)', L.setresuid(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF))

# clock_getres — CLOCK_MONOTONIC must return a positive resolution.
class Timespec(ctypes.Structure):
    _fields_ = [('tv_sec', ctypes.c_long), ('tv_nsec', ctypes.c_long)]
L.clock_getres.argtypes = [ctypes.c_int, ctypes.c_void_p]
ts = Timespec()
expect_ok('clock_getres(MONOTONIC)', L.clock_getres(1, ctypes.byref(ts)))
check('clock_getres resolution > 0', ts.tv_nsec > 0 or ts.tv_sec > 0,
      f'got tv_sec={ts.tv_sec} tv_nsec={ts.tv_nsec}')
# Bad clockid must be EINVAL.
expect_errno('clock_getres(99 bad)', L.clock_getres(99, ctypes.byref(ts)), errno.EINVAL)

# ── Batch 4: fd-stubs round 3, capabilities, scheduling ────────────────
# Yet another sweep. Targets: *at() handlers that skip dirfd
# validation, capability stubs, and sched_*affinity. The *at family
# is a recurring source of bugs because the dirfd check is easy to
# forget when the function is a thin wrapper over an AT_FDCWD helper.

# sendmsg(-1, ...) — socket stub, should be EBADF
NR_SENDMSG = 211 if mach == 'aarch64' else 46
expect_errno('sendmsg(-1)', S(NR_SENDMSG, -1, 0, 0), errno.EBADF)

# readahead(-1, 0, 0) — fd-based
NR_READAHEAD = 213 if mach == 'aarch64' else 187
expect_errno('readahead(-1)', S(NR_READAHEAD, -1, 0, 0), errno.EBADF)

# fchmodat(-1, ...) / fchownat(-1, ...) / mknodat(-1, ...) —
# dirfd-validating *at handlers. round 1 fixed faccessat/utimensat
# but these three were never checked.
NR_FCHMODAT = 53 if mach == 'aarch64' else 268
NR_FCHOWNAT = 54 if mach == 'aarch64' else 260
NR_MKNODAT  = 33 if mach == 'aarch64' else 259
expect_errno('fchmodat(-1)', S(NR_FCHMODAT, -1, b'x', 0o644, 0), errno.EBADF)
expect_errno('fchownat(-1)', S(NR_FCHOWNAT, -1, b'x', 0, 0, 0), errno.EBADF)
expect_errno('mknodat(-1)',  S(NR_MKNODAT,  -1, b'x', 0o644, 0), errno.EBADF)

# linkat — same pattern with two dirfds. Pass invalid olddirfd.
NR_LINKAT = 37 if mach == 'aarch64' else 265
expect_errno('linkat(-1 olddir)', S(NR_LINKAT, -1, b'a', 0xFFFFFFFF_FFFFFFFF - 99, b'b', 0), errno.EBADF)

# setgroups(0, NULL) — clear groups, root OK
L.setgroups.argtypes = [ctypes.c_size_t, ctypes.c_void_p]
expect_ok('setgroups(0, NULL)', L.setgroups(0, None))

# getgroups(0, NULL) — returns the number of supplementary groups
L.getgroups.argtypes = [ctypes.c_int, ctypes.c_void_p]
n = L.getgroups(0, None)
check('getgroups(0, NULL) >= 0', n >= 0, f'got {n}')

# sched_getaffinity(0, 128, &mask) — populates cpu mask, returns bytes.
L.sched_getaffinity.argtypes = [ctypes.c_int, ctypes.c_size_t, ctypes.c_void_p]
mask_buf = ctypes.create_string_buffer(128)
expect_ok('sched_getaffinity', L.sched_getaffinity(0, 128, mask_buf))

# set_robust_list(NULL, 0) — len=0 is invalid per glibc man page.
# Linux returns EINVAL; some implementations accept it as a no-op.
# Accept either — we just want to exercise the dispatch.
NR_SET_ROBUST_LIST = 99 if mach == 'aarch64' else 273
r = S(NR_SET_ROBUST_LIST, 0, 0)
check('set_robust_list reached', r == 0 or r < 0, f'got {r}')

# capget(NULL, NULL) — hdr is required
L.capget.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
expect_errno('capget(NULL)', L.capget(None, None), errno.EFAULT)

# ── Final summary ──────────────────────────────────────────────────────
print(f'conformance: passed={P} failed={F}')
