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

# ── Final summary ──────────────────────────────────────────────────────
print(f'conformance: passed={P} failed={F}')
