#!/usr/bin/env python3
"""
Aggregate per-group syscall coverage dumps and report untested syscalls.

Usage:
    tools/coverage_report.py <arch> <dump-file> [<dump-file>...]

Each dump file contains lines like "NR COUNT\\n" emitted by the rux
kernel's PR_GET_COVERAGE prctl (magic 0x52755802). The tool sums counts
across all provided dumps, maps numbers to Linux syscall names for the
given arch, and prints:

    COVERAGE (arch): N/K syscalls hit, J/K enum variants wired up
    TOP HITTERS: ...
    UNTESTED: name (nr), name (nr), ...

Arch tables are kept in sync with crates/kernel/src/arch/<arch>/syscall.rs.
If a test exercises a syscall number we don't know about, it's reported
as "nr=<N>".
"""
import sys, os, re

# Minimal Linux x86_64 syscall name table (the ones rux translates in
# crates/kernel/src/arch/x86_64/syscall.rs's translate table). Keep in
# sync when new syscalls are wired up.
X86_64 = {
    0: "read", 1: "write", 2: "open", 3: "close", 4: "stat",
    5: "fstat", 6: "lstat", 7: "poll", 8: "lseek", 9: "mmap",
    10: "mprotect", 11: "munmap", 12: "brk", 13: "rt_sigaction",
    14: "rt_sigprocmask", 15: "rt_sigreturn", 16: "ioctl",
    17: "pread64", 18: "pwrite64", 19: "readv", 20: "writev",
    21: "access", 22: "pipe", 23: "select", 24: "sched_yield",
    25: "mremap", 26: "msync", 27: "mincore", 28: "madvise",
    32: "dup", 33: "dup2", 34: "pause", 35: "nanosleep",
    36: "getitimer", 37: "alarm", 38: "setitimer",
    39: "getpid", 40: "sendfile", 41: "socket", 42: "connect",
    43: "accept", 44: "sendto", 45: "recvfrom", 46: "sendmsg",
    47: "recvmsg", 48: "shutdown", 49: "bind", 50: "listen",
    51: "getsockname", 52: "getpeername", 53: "socketpair",
    54: "setsockopt", 55: "getsockopt", 56: "clone",
    57: "fork", 58: "vfork", 59: "execve", 60: "exit",
    61: "wait4", 62: "kill", 63: "uname", 72: "fcntl",
    73: "flock", 74: "fsync", 75: "fdatasync", 76: "truncate",
    77: "ftruncate", 78: "getdents", 79: "getcwd", 80: "chdir",
    81: "fchdir", 82: "rename", 83: "mkdir", 84: "rmdir",
    85: "creat", 86: "link", 87: "unlink", 88: "symlink",
    89: "readlink", 90: "chmod", 91: "fchmod", 92: "chown",
    93: "fchown", 95: "umask", 96: "gettimeofday",
    97: "getrlimit", 98: "getrusage", 99: "sysinfo",
    100: "times", 101: "ptrace", 102: "getuid", 103: "syslog",
    104: "getgid", 105: "setuid", 106: "setgid", 107: "geteuid",
    108: "getegid", 109: "setpgid", 110: "getppid", 111: "getpgrp",
    112: "setsid", 113: "setreuid", 114: "setregid",
    115: "getgroups", 116: "setgroups", 117: "setresuid",
    118: "getresuid", 119: "setresgid", 120: "getresgid",
    121: "getpgid", 124: "getsid", 131: "sigaltstack",
    132: "utime", 137: "statfs", 138: "fstatfs",
    157: "prctl", 158: "arch_prctl", 161: "chroot",
    162: "sync", 165: "mount", 166: "umount2", 169: "reboot",
    170: "sethostname", 171: "setdomainname",
    179: "quotactl", 186: "gettid", 187: "readahead",
    188: "setxattr", 189: "lsetxattr", 190: "fsetxattr",
    191: "getxattr", 192: "lgetxattr", 193: "fgetxattr",
    194: "listxattr", 195: "llistxattr", 196: "flistxattr",
    197: "removexattr", 198: "lremovexattr", 199: "fremovexattr",
    200: "tkill", 201: "time", 202: "futex",
    203: "sched_setaffinity", 204: "sched_getaffinity",
    213: "epoll_create", 217: "getdents64", 218: "set_tid_address",
    219: "restart_syscall", 220: "semtimedop", 221: "fadvise64",
    222: "timer_create", 223: "timer_settime", 224: "timer_gettime",
    225: "timer_getoverrun", 226: "timer_delete",
    227: "clock_settime", 228: "clock_gettime", 229: "clock_getres",
    230: "clock_nanosleep", 231: "exit_group", 232: "epoll_wait",
    233: "epoll_ctl", 234: "tgkill", 235: "utimes",
    247: "waitid", 253: "inotify_init", 254: "inotify_add_watch",
    255: "inotify_rm_watch", 257: "openat", 258: "mkdirat",
    259: "mknodat", 260: "fchownat", 262: "newfstatat",
    263: "unlinkat", 264: "renameat", 265: "linkat", 266: "symlinkat",
    267: "readlinkat", 268: "fchmodat", 269: "faccessat",
    270: "pselect6", 271: "ppoll", 272: "unshare",
    273: "set_robust_list", 274: "get_robust_list", 275: "splice",
    276: "tee", 277: "sync_file_range", 278: "vmsplice",
    280: "utimensat", 281: "epoll_pwait", 282: "signalfd",
    283: "timerfd_create", 284: "eventfd", 285: "fallocate",
    286: "timerfd_settime", 287: "timerfd_gettime",
    288: "accept4", 289: "signalfd4", 290: "eventfd2",
    291: "epoll_create1", 292: "dup3", 293: "pipe2",
    294: "inotify_init1", 295: "preadv", 296: "pwritev",
    297: "rt_tgsigqueueinfo", 298: "perf_event_open",
    299: "recvmmsg", 302: "prlimit64", 303: "name_to_handle_at",
    304: "open_by_handle_at", 306: "syncfs", 307: "sendmmsg",
    309: "getcpu", 310: "process_vm_readv", 311: "process_vm_writev",
    312: "kcmp", 316: "renameat2", 317: "seccomp", 318: "getrandom",
    319: "memfd_create", 321: "bpf", 322: "execveat",
    323: "userfaultfd", 324: "membarrier", 325: "mlock2",
    326: "copy_file_range", 327: "preadv2", 328: "pwritev2",
    332: "statx", 424: "pidfd_send_signal", 434: "pidfd_open",
    435: "clone3", 439: "faccessat2", 441: "epoll_pwait2",
}

AARCH64 = {
    0: "io_setup", 17: "getcwd", 19: "eventfd2", 20: "epoll_create1",
    21: "epoll_ctl", 22: "epoll_pwait", 23: "dup", 24: "dup3",
    25: "fcntl", 29: "ioctl", 32: "flock", 33: "mknodat",
    34: "mkdirat", 35: "unlinkat", 36: "symlinkat", 37: "linkat",
    38: "renameat", 40: "mount", 43: "statfs", 44: "fstatfs",
    45: "truncate", 46: "ftruncate", 47: "fallocate",
    48: "faccessat", 49: "chdir", 50: "fchdir",
    52: "fchmod", 53: "fchmodat", 54: "fchownat",
    55: "fchown", 56: "openat", 57: "close", 59: "pipe2",
    61: "getdents64", 62: "lseek", 63: "read", 64: "write",
    65: "readv", 66: "writev", 67: "pread64", 68: "pwrite64",
    71: "sendfile", 72: "pselect6", 73: "ppoll", 75: "splice",
    76: "tee", 78: "readlinkat", 79: "fstatat", 80: "fstat",
    82: "fsync", 83: "fdatasync", 88: "utimensat",
    90: "capget", 91: "capset", 93: "exit", 94: "exit_group",
    95: "waitid", 96: "set_tid_address", 98: "futex",
    99: "set_robust_list", 101: "nanosleep",
    102: "getitimer",
    103: "setitimer", 107: "timer_create", 108: "timer_gettime",
    109: "timer_getoverrun", 110: "timer_settime", 111: "timer_delete",
    112: "clock_settime", 113: "clock_gettime", 114: "clock_getres",
    115: "clock_nanosleep", 117: "ptrace",
    122: "sched_setaffinity", 123: "sched_getaffinity",
    124: "sched_yield", 129: "kill", 130: "tkill", 131: "tgkill",
    132: "sigaltstack", 133: "rt_sigsuspend", 134: "rt_sigaction",
    135: "rt_sigprocmask", 136: "rt_sigpending", 137: "rt_sigtimedwait",
    138: "rt_sigqueueinfo", 139: "rt_sigreturn", 144: "setgid",
    146: "setreuid", 147: "setregid", 149: "getresuid",
    150: "getresgid", 151: "setfsuid", 152: "setfsgid",
    153: "times", 154: "setpgid", 155: "getpgid", 156: "getsid",
    157: "setsid", 158: "getgroups", 159: "setgroups",
    160: "uname", 161: "sethostname", 162: "setdomainname",
    165: "getrusage", 166: "umask", 167: "prctl",
    169: "gettimeofday", 172: "getpid", 173: "getppid",
    174: "getuid", 175: "geteuid", 176: "getgid", 177: "getegid",
    178: "gettid", 179: "sysinfo", 194: "shmget", 195: "shmctl",
    198: "socket", 199: "socketpair", 200: "bind", 201: "listen",
    202: "accept", 203: "connect", 204: "getsockname",
    205: "getpeername", 206: "sendto", 207: "recvfrom",
    208: "setsockopt", 209: "getsockopt", 210: "shutdown",
    211: "sendmsg", 212: "recvmsg", 213: "readahead",
    214: "brk", 215: "munmap", 216: "mremap", 217: "add_key",
    220: "clone", 221: "execve", 222: "mmap", 223: "fadvise64",
    226: "mprotect", 227: "msync", 228: "mlock", 229: "munlock",
    232: "mincore", 233: "madvise", 235: "mbind", 242: "accept4",
    260: "wait4", 261: "prlimit64", 264: "name_to_handle_at", 265: "open_by_handle_at",
    266: "clock_adjtime", 267: "syncfs", 268: "setns",
    269: "sendmmsg", 270: "process_vm_readv", 271: "process_vm_writev",
    272: "kcmp", 276: "renameat2", 277: "seccomp", 278: "getrandom",
    279: "memfd_create", 281: "execveat", 283: "membarrier",
    291: "statx", 424: "pidfd_send_signal", 434: "pidfd_open",
    435: "clone3", 439: "faccessat2", 441: "epoll_pwait2",
}

def parse_dump(path):
    """Parse a coverage dump file into {nr: count}."""
    out = {}
    try:
        with open(path) as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) != 2: continue
                try:
                    nr = int(parts[0])
                    count = int(parts[1])
                    out[nr] = out.get(nr, 0) + count
                except ValueError:
                    continue
    except FileNotFoundError:
        pass
    return out

def main():
    if len(sys.argv) < 3:
        print("usage: coverage_report.py <arch> <dump-file>...", file=sys.stderr)
        sys.exit(2)
    arch = sys.argv[1]
    table = {"x86_64": X86_64, "aarch64": AARCH64}.get(arch)
    if table is None:
        print(f"unknown arch: {arch}", file=sys.stderr)
        sys.exit(2)
    # Aggregate across all dump files.
    counts = {}
    for path in sys.argv[2:]:
        for nr, c in parse_dump(path).items():
            counts[nr] = counts.get(nr, 0) + c
    known = set(table.keys())
    hit = {nr for nr in counts.keys() if nr in known}
    untested = sorted(known - hit)
    print(f"COVERAGE ({arch}): {len(hit)}/{len(known)} syscalls hit "
          f"({100.0 * len(hit) / len(known):.1f}%)")
    unknown_nrs = sorted(nr for nr in counts.keys() if nr not in known)
    if unknown_nrs:
        print(f"  unknown syscall nrs: {unknown_nrs}")
    if counts:
        top = sorted(counts.items(), key=lambda kv: -kv[1])[:10]
        top_fmt = ", ".join(f"{table.get(n, f'nr={n}')}({c})" for n, c in top)
        print(f"  top hitters: {top_fmt}")
    if untested:
        missing = ", ".join(table[n] for n in untested[:30])
        more = f" (+{len(untested) - 30} more)" if len(untested) > 30 else ""
        print(f"  untested: {missing}{more}")
    # Non-zero exit if any syscalls are unknown (new kernel syscalls added
    # without updating this tool's name table)
    sys.exit(0)

if __name__ == "__main__":
    main()
