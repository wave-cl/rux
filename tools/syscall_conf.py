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

# ── Final summary ──────────────────────────────────────────────────────
print(f'conformance: passed={P} failed={F}')
