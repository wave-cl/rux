#!/bin/sh
# QEMU integration tests for rux kernel.
set -e

QEMU_X86="${QEMU_X86:-/opt/local/bin/qemu-system-x86_64}"
QEMU_AA64="${QEMU_AA64:-/opt/local/bin/qemu-system-aarch64}"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); printf "  \033[32m✓\033[0m %s\n" "$1"; }
fail() { FAIL=$((FAIL + 1)); printf "  \033[31m✗\033[0m %s\n" "$1"; }
check() {
    if echo "$OUTPUT" | grep -qF "$2"; then
        pass "$1"
    else
        fail "$1: expected '$2'"
    fi
}

# ── Build ────────────────────────────────────────────────────────────
printf "\033[1mBuilding...\033[0m\n"
cargo build --target x86_64-unknown-none -p rux-kernel 2>&1 | tail -1
cargo build --target aarch64-unknown-none -p rux-kernel 2>&1 | tail -1
rust-objcopy --output-target=elf32-i386 \
    target/x86_64-unknown-none/debug/rux-kernel \
    target/x86_64-unknown-none/debug/rux-kernel.elf32

# Build initramfs if needed
[ -f initramfs/initramfs_x86_64.cpio ] || bash initramfs/build.sh

# ── x86_64 ───────────────────────────────────────────────────────────
printf "\n\033[1m── x86_64 ──\033[0m\n"

OUTPUT=$( { sleep 6; \
    printf 'uname -a\n'; sleep 1; \
    printf 'cat /proc/meminfo | head -1\n'; sleep 3; \
    printf 'env | head -1\n'; sleep 3; \
    printf 'top -b -n1 | head -5\n'; sleep 5; \
    printf 'cat /etc/passwd\n'; sleep 1; \
    printf 'cat /etc/os-release\n'; sleep 1; \
    printf 'whoami\n'; sleep 1; \
    printf 'hostname\n'; sleep 1; \
    printf 'pwd\n'; sleep 1; \
    printf 'ls /\n'; sleep 1; \
    printf 'echo test 123\n'; sleep 1; \
    printf 'cat /proc/version\n'; sleep 1; \
    printf 'free | head -2\n'; sleep 1; \
    printf 'readlink /bin/sh\n'; sleep 1; \
    printf 'ln -s /bin/sh /tmp/mvtest && mv /tmp/mvtest /tmp/mvdone && readlink /tmp/mvdone\n'; sleep 2; \
    printf 'echo hello | wc -w\n'; sleep 2; \
    printf 'grep root /etc/passwd\n'; sleep 1; \
    printf 'expr 2 + 3\n'; sleep 1; \
    printf 'id\n'; sleep 1; \
    printf 'ls /proc\n'; sleep 1; \
    printf 'ls /proc/1\n'; sleep 1; \
    printf 'ln -s /bin/busybox /tmp/mylink && readlink /tmp/mylink\n'; sleep 1; \
    printf 'mkdir /tmp/d && ls /tmp\n'; sleep 1; \
    printf 'echo -n abcd | wc -c\n'; sleep 2; \
    printf 'seq 1 3\n'; sleep 1; \
    printf '/bin/auxv\n'; sleep 2; \
    printf 'basename /usr/bin/id\n'; sleep 1; \
    printf 'cat /proc/self/status\n'; sleep 2; \
    printf 'true && echo ok42\n'; sleep 1; \
    printf 'echo redir_test > /tmp/r && cat /tmp/r\n'; sleep 2; \
    printf 'echo hi > /tmp/t && mv /tmp/t /tmp/t2 && cat /tmp/t2\n'; sleep 2; \
    printf 'printf "hello world\\n" | wc -w\n'; sleep 2; \
    printf 'cat /proc/uptime\n'; sleep 1; \
    printf 'cat /proc/loadavg\n'; sleep 1; \
    printf 'cat /proc/mounts\n'; sleep 1; \
    printf 'cat /proc/filesystems\n'; sleep 1; \
    printf 'cat /proc/cmdline\n'; sleep 1; \
    printf 'cat /proc/1/cmdline\n'; sleep 1; \
    printf 'stat /bin/sh\n'; sleep 2; \
    printf 'df /\n'; sleep 2; \
    printf 'uptime\n'; sleep 1; \
    printf 'touch /tmp/tfile && ls /tmp/tfile\n'; sleep 2; \
    printf 'sleep 0 && echo sleepdone\n'; sleep 2; \
    printf 'rm /tmp/tfile && echo rmdone\n'; sleep 2; \
    printf 'wc -l /etc/passwd\n'; sleep 2; \
    printf 'ln /bin/busybox /tmp/hl && ls /tmp/hl\n'; sleep 2; \
    printf 'chmod 777 /tmp/hl && stat /tmp/hl\n'; sleep 2; \
    printf 'echo test > /dev/null && echo devnull_ok\n'; sleep 2; \
    printf 'ls /dev\n'; sleep 1; \
    printf 'kill -0 1 && echo killcheck\n'; sleep 2; \
    printf 'kill -0 99 ; echo exitcode=$?\n'; sleep 2; \
    printf 'dd if=/dev/zero bs=4 count=1 2>/dev/null | wc -c\n'; sleep 2; \
    printf 'cat /dev/urandom | head -c 8 | wc -c\n'; sleep 2; \
    printf 'touch /tmp/ts && stat /tmp/ts | grep Modify\n'; sleep 2; \
    printf 'echo abc | cat\n'; sleep 2; \
    printf 'tail -c 8 /etc/passwd\n'; sleep 2; \
    printf 'find /etc -type f 2>/dev/null\n'; sleep 2; \
    printf 'sort /etc/passwd\n'; sleep 2; \
    printf 'date +%%s\n'; sleep 1; \
    printf 'echo mypid=$$ done\n'; sleep 1; \
    printf 'chown 0:0 /tmp/hl && stat /tmp/hl | grep Uid\n'; sleep 2; \
    printf 'stat /etc/passwd > /dev/null && echo accessok\n'; sleep 1; \
    printf 'cut -d: -f1 /etc/passwd\n'; sleep 2; \
    printf 'echo hello | tr a-z A-Z\n'; sleep 2; \
    printf 'trap "echo trapped_sig" TERM ; kill -15 $$ ; echo after_trap\n'; sleep 5; \
    printf 'tee /tmp/tee_out < /etc/passwd > /dev/null && cat /tmp/tee_out | head -1\n'; sleep 5; \
    printf 'cat /proc/$$/stat | cut -d" " -f5\n'; sleep 2; \
    printf 'exit\n'; sleep 1; \
    } | \
    "$QEMU_X86" -cpu Haswell -smp 2 \
    -kernel target/x86_64-unknown-none/debug/rux-kernel.elf32 \
    -initrd initramfs/initramfs_x86_64.cpio \
    -serial mon:stdio -display none \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -no-reboot -monitor none -m 128M 2>&1 || true )

# Boot
check "boot banner"             "rux 0.6.0 (x86_64)"
check "kernel page tables"      "CR3 switched to kernel page tables"
check "SMP CPUs online"          "CPUs online"
check "cpio unpacked"           "cpio: unpacked"
check "procfs mounted"          "procfs mounted at /proc"
check "exec init"               "exec /sbin/init"
check "shell prompt"            "/ # "

# Core commands
check "uname"                   "rux rux 0.6.0"
check "cat /etc/passwd"         "root:x:0:0:root:/root:/bin/sh"
check "cat /etc/os-release"     "NAME=\"rux\""
check "whoami"                  "root"
check "hostname"                "rux"
check "pwd"                     "/"
check "echo"                    "test 123"

# Rootfs structure
check "ls shows bin"            "bin"
check "ls shows etc"            "etc"
check "ls shows proc"           "proc"
check "ls shows tmp"            "tmp"

# procfs
check "proc/version"            "rux version"
check "free shows memory"       "Mem:"
check "ls /proc shows 1"        "1"
check "ls /proc/1 shows stat"   "stat"

# File operations
check "readlink"                "busybox"
check "rename (mv)"             "/bin/sh"
check "pipe (wc -w)"            "1"
check "grep"                    "root:x:0:0"
check "expr"                    "5"
check "id"                      "uid=0(root)"

# top
check "top shows process"       "PID"

# symlink + mkdir + file ops
check "symlink"                 "busybox"
check "mkdir"                   "d"
check "wc -c (pipe)"            "4"
check "seq"                     "3"
check "auxv verifier"           "auxv_ok"
check "basename"                "id"
check "proc/self/status"        "Pid:"
check "true && echo"            "ok42"
check "file redirect"           "redir_test"
check "rename (file)"           "hi"
check "printf pipe"             "2"

# procfs files
check "proc/uptime"             "0."
check "proc/meminfo"            "MemTotal:"
check "proc/loadavg"            "0.00"
check "proc/mounts"             "rootfs"
check "proc/filesystems"        "ramfs"
check "proc/cmdline"            "rux"
check "proc/1/cmdline"          "init"

# Syscall coverage
check "stat"                    "File:"
check "df"                      "rootfs"
check "uptime"                  "up"
check "touch + ls"              "tfile"
check "sleep + echo"            "sleepdone"
check "rm + echo"               "rmdone"
check "wc -l"                   "1"
check "env"                     "PATH="

# Hard links + chmod + /dev + signals
check "hard link"               "hl"
check "chmod (stat)"            "777"
check "dev/null"                "devnull_ok"
check "ls /dev shows null"      "null"
check "kill -0 self"            "killcheck"
check "kill -0 nonexist"        "exitcode=1"
check "dev/zero (dd)"          "4"
check "dev/urandom"            "8"
check "touch timestamp"        "Modify:"
check "pipe cat"               "abc"
check "signal trap"            "trapped_sig"

# Syscall coverage: lseek, find, sort, clock, pid, chown, access, cut, tr, tee
check "tail (lseek)"           "/bin/sh"
check "find /etc"              "passwd"
check "sort"                   "root"
check "date (clock)"           "0"
check "getpid"                  "mypid="
check "chown"                  "Uid"
check "test -f (access)"       "accessok"
check "cut"                    "root"
check "tr (uppercase)"         "HELLO"
check "tee"                    "root"
check "proc stat pgid"         "1"

# ── aarch64 ──────────────────────────────────────────────────────────
printf "\n\033[1m── aarch64 ──\033[0m\n"

OUTPUT=$( { sleep 12; \
    printf 'uname -a\n'; sleep 2; \
    printf 'cat /etc/passwd\n'; sleep 2; \
    printf 'cat /etc/os-release\n'; sleep 2; \
    printf 'whoami\n'; sleep 2; \
    printf 'hostname\n'; sleep 2; \
    printf 'pwd\n'; sleep 2; \
    printf 'ls /\n'; sleep 2; \
    printf 'echo test 123\n'; sleep 2; \
    printf 'cat /proc/version\n'; sleep 2; \
    printf 'free | head -2\n'; sleep 2; \
    printf 'readlink /bin/sh\n'; sleep 3; \
    printf 'echo hello | wc -w\n'; sleep 3; \
    printf 'id\n'; sleep 3; \
    printf 'ls /proc\n'; sleep 3; \
    printf 'ls /proc/1\n'; sleep 3; \
    printf 'grep root /etc/passwd\n'; sleep 3; \
    printf 'expr 2 + 3\n'; sleep 3; \
    printf 'ln -s /bin/busybox /tmp/mylink && readlink /tmp/mylink\n'; sleep 3; \
    printf 'mkdir /tmp/d && ls /tmp\n'; sleep 3; \
    printf 'echo -n abcd | wc -c\n'; sleep 3; \
    printf 'seq 1 3\n'; sleep 3; \
    printf '/bin/auxv\n'; sleep 3; \
    printf 'basename /usr/bin/id\n'; sleep 3; \
    printf 'cat /proc/self/status\n'; sleep 3; \
    printf 'true && echo ok42\n'; sleep 3; \
    printf 'echo redir_test > /tmp/r && cat /tmp/r\n'; sleep 3; \
    printf 'echo hi > /tmp/t && mv /tmp/t /tmp/t2 && cat /tmp/t2\n'; sleep 3; \
    printf 'printf "hello world\\n" | wc -w\n'; sleep 3; \
    printf 'top -b -n1 | head -5\n'; sleep 5; \
    printf 'cat /proc/uptime\n'; sleep 3; \
    printf 'cat /proc/meminfo\n'; sleep 3; \
    printf 'cat /proc/loadavg\n'; sleep 3; \
    printf 'cat /proc/mounts\n'; sleep 3; \
    printf 'cat /proc/filesystems\n'; sleep 3; \
    printf 'cat /proc/cmdline\n'; sleep 3; \
    printf 'cat /proc/1/cmdline\n'; sleep 3; \
    printf 'stat /bin/sh\n'; sleep 3; \
    printf 'df /\n'; sleep 3; \
    printf 'uptime\n'; sleep 3; \
    printf 'touch /tmp/tfile && ls /tmp/tfile\n'; sleep 3; \
    printf 'sleep 0 && echo sleepdone\n'; sleep 3; \
    printf 'rm /tmp/tfile && echo rmdone\n'; sleep 3; \
    printf 'wc -l /etc/passwd\n'; sleep 3; \
    printf 'env\n'; sleep 3; \
    printf 'ln /bin/busybox /tmp/hl && ls /tmp/hl\n'; sleep 3; \
    printf 'chmod 777 /tmp/hl && stat /tmp/hl\n'; sleep 3; \
    printf 'echo test > /dev/null && echo devnull_ok\n'; sleep 3; \
    printf 'ls /dev\n'; sleep 3; \
    printf 'kill -0 1 && echo killcheck\n'; sleep 3; \
    printf 'kill -0 99 ; echo exitcode=$?\n'; sleep 3; \
    printf 'dd if=/dev/zero bs=4 count=1 2>/dev/null | wc -c\n'; sleep 3; \
    printf 'cat /dev/urandom | head -c 8 | wc -c\n'; sleep 3; \
    printf 'touch /tmp/ts && stat /tmp/ts | grep Modify\n'; sleep 3; \
    printf 'echo abc | cat\n'; sleep 3; \
    printf 'tail -c 8 /etc/passwd\n'; sleep 3; \
    printf 'find /etc -type f 2>/dev/null\n'; sleep 3; \
    printf 'sort /etc/passwd\n'; sleep 3; \
    printf 'date +%%s\n'; sleep 3; \
    printf 'echo mypid=$$ done\n'; sleep 3; \
    printf 'chown 0:0 /tmp/hl && stat /tmp/hl | grep Uid\n'; sleep 3; \
    printf 'stat /etc/passwd > /dev/null && echo accessok\n'; sleep 3; \
    printf 'cut -d: -f1 /etc/passwd\n'; sleep 3; \
    printf 'echo hello | tr a-z A-Z\n'; sleep 3; \
    printf 'trap "echo trapped_sig" TERM ; kill -15 $$ ; echo after_trap\n'; sleep 6; \
    printf 'tee /tmp/tee_out < /etc/passwd > /dev/null && cat /tmp/tee_out | head -1\n'; sleep 5; \
    printf 'cat /proc/$$/stat | cut -d" " -f5\n'; sleep 3; \
    printf 'exit\n'; sleep 2; \
    } | \
    "$QEMU_AA64" -machine virt -cpu cortex-a72 -smp 2 \
    -kernel target/aarch64-unknown-none/debug/rux-kernel \
    -device loader,file=initramfs/initramfs_aarch64.cpio,addr=0x45000000,force-raw=on \
    -serial mon:stdio -display none \
    -semihosting -no-reboot -m 128M 2>&1 || true )

# Boot
check "boot banner"             "rux 0.6.0 (aarch64)"
check "MMU enabled"             "MMU enabled"
check "SMP CPUs online"          "CPUs online"
check "cpio unpacked"           "cpio: unpacked"
check "procfs mounted"          "procfs mounted at /proc"
check "exec init"               "exec /sbin/init"
check "shell prompt"            "/ # "

# Core commands
check "uname"                   "rux rux 0.6.0"
check "cat /etc/passwd"         "root:x:0:0:root:/root:/bin/sh"
check "cat /etc/os-release"     "NAME=\"rux\""
check "whoami"                  "root"
check "hostname"                "rux"
check "pwd"                     "/"
check "echo"                    "test 123"

# Rootfs structure
check "ls shows bin"            "bin"
check "ls shows etc"            "etc"
check "ls shows proc"           "proc"
check "ls shows tmp"            "tmp"

# procfs
check "proc/version"            "rux version"
check "free shows memory"       "Mem:"
check "ls /proc shows 1"        "1"
check "ls /proc/1 shows stat"   "stat"

# File operations
check "readlink"                "busybox"
check "pipe (wc -w)"            "1"
check "id"                      "uid=0(root)"
check "grep"                    "root:x:0:0"
check "expr"                    "5"

# symlink + mkdir + file ops
check "symlink"                 "busybox"
check "mkdir"                   "d"
check "wc -c (pipe)"            "4"
check "seq"                     "3"
check "auxv verifier"           "auxv_ok"
check "basename"                "id"
check "proc/self/status"        "Pid:"
check "true && echo"            "ok42"
check "file redirect"           "redir_test"
check "rename (file)"           "hi"
check "printf pipe"             "2"

# top
check "top shows process"       "PID"

# procfs files
check "proc/uptime"             "0."
check "proc/meminfo"            "MemTotal:"
check "proc/loadavg"            "0.00"
check "proc/mounts"             "rootfs"
check "proc/filesystems"        "ramfs"
check "proc/cmdline"            "rux"
check "proc/1/cmdline"          "init"

# Syscall coverage
check "stat"                    "File:"
check "df"                      "rootfs"
check "uptime"                  "up"
check "touch + ls"              "tfile"
check "sleep + echo"            "sleepdone"
check "rm + echo"               "rmdone"
check "wc -l"                   "1"
check "env"                     "PATH="

# Hard links + chmod + /dev + signals
check "hard link"               "hl"
check "chmod (stat)"            "777"
check "dev/null"                "devnull_ok"
check "ls /dev shows null"      "null"
check "kill -0 self"            "killcheck"
check "kill -0 nonexist"        "exitcode=1"
check "dev/zero (dd)"          "4"
check "dev/urandom"            "8"
check "touch timestamp"        "Modify:"
check "pipe cat"               "abc"
check "signal trap"            "trapped_sig"

# Syscall coverage: lseek, find, sort, clock, pid, chown, access, cut, tr, tee
check "tail (lseek)"           "/bin/sh"
check "find /etc"              "passwd"
check "sort"                   "root"
check "date (clock)"           "0"
check "getpid"                  "mypid="
check "chown"                  "Uid"
check "test -f (access)"       "accessok"
check "cut"                    "root"
check "tr (uppercase)"         "HELLO"
check "tee"                    "root"
check "proc stat pgid"         "1"

# ── Summary ──────────────────────────────────────────────────────────
printf "\n\033[1m%d passed, %d failed\033[0m\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
