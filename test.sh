#!/bin/sh
# QEMU integration tests for rux kernel.
# Usage:
#   bash test.sh                    # run both arches
#   TEST_ARCH=x86_64 bash test.sh   # x86_64 only
#   TEST_ARCH=aarch64 bash test.sh  # aarch64 only
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

# ── Arch selection ──────────────────────────────────────────────────
RUN_X86=true; RUN_AA64=true
[ "$TEST_ARCH" = "x86_64" ] && RUN_AA64=false
[ "$TEST_ARCH" = "aarch64" ] && RUN_X86=false

# ── Build ───────────────────────────────────────────────────────────
printf "\033[1mBuilding...\033[0m\n"
$RUN_X86 && {
    cargo build --target x86_64-unknown-none -p rux-kernel 2>&1 | tail -1
    rust-objcopy --output-target=elf32-i386 \
        target/x86_64-unknown-none/debug/rux-kernel \
        target/x86_64-unknown-none/debug/rux-kernel.elf32
}
$RUN_AA64 && cargo build --target aarch64-unknown-none -p rux-kernel 2>&1 | tail -1

[ -f initramfs/initramfs_x86_64.cpio ] || bash initramfs/build.sh

# ── x86_64 ──────────────────────────────────────────────────────────
if $RUN_X86; then
printf "\n\033[1m── x86_64 ──\033[0m\n"

OUTPUT=$( { sleep 8; cat <<'CMDS'
true
uname -a
cat /etc/passwd
cat /etc/os-release
whoami
hostname
pwd
ls /
echo test 123
cat /proc/version
free | head -2
readlink /bin/sh
cat /proc/meminfo | head -1
env | head -1
ln -s /bin/sh /tmp/mvtest && mv /tmp/mvtest /tmp/mvdone && readlink /tmp/mvdone
echo hello | wc -w
grep root /etc/passwd
expr 2 + 3
id
ls /proc
ls /proc/1
ln -s /bin/busybox /tmp/mylink && readlink /tmp/mylink
mkdir /tmp/d && ls /tmp
echo -n abcd | wc -c
seq 1 3
/bin/auxv
basename /usr/bin/id
cat /proc/self/status
true && echo ok42
echo redir_test > /tmp/r && cat /tmp/r
echo hi > /tmp/t && mv /tmp/t /tmp/t2 && cat /tmp/t2
printf "hello world\n" | wc -w
cat /proc/uptime
cat /proc/loadavg
cat /proc/mounts
cat /proc/filesystems
cat /proc/cmdline
cat /proc/1/cmdline
stat /bin/sh
df /
uptime
touch /tmp/tfile && ls /tmp/tfile
sleep 0 && echo sleepdone
rm /tmp/tfile && echo rmdone
wc -l /etc/passwd
ln /bin/busybox /tmp/hl && ls /tmp/hl
chmod 777 /tmp/hl && stat /tmp/hl
echo test > /dev/null && echo devnull_ok
ls /dev
kill -0 1 && echo killcheck
kill -0 99 ; echo exitcode=$?
dd if=/dev/zero bs=4 count=1 2>/dev/null | wc -c
cat /dev/urandom | head -c 8 | wc -c
touch /tmp/ts && stat /tmp/ts | grep Modify
echo abc | cat
ps aux | head -5
trap "echo trapped_sig" TERM ; kill -15 $$ ; echo after_trap
tail -c 8 /etc/passwd
find /etc -type f 2>/dev/null
sort /etc/passwd
date +%s
echo mypid=$$ done
chown 0:0 /tmp/hl && stat /tmp/hl | grep Uid
stat /etc/passwd > /dev/null && echo accessok
cut -d: -f1 /etc/passwd
echo hello | tr a-z A-Z
echo testdata | tee /tmp/tee_out > /dev/null && cat /tmp/tee_out
cat /proc/$$/stat | cut -d" " -f5
/bin/dynhello
exit
CMDS
} | \
    "$QEMU_X86" -cpu max -smp 2 \
    -kernel target/x86_64-unknown-none/debug/rux-kernel.elf32 \
    -initrd initramfs/initramfs_x86_64.cpio \
    -chardev stdio,id=char0,logfile=/tmp/rux_serial_x86_64.log \
    -serial chardev:char0 -display none \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -no-reboot -monitor none -net none -m 128M 2>&1 || true )

echo "$OUTPUT" > /tmp/rux_test_x86_64.log

# Boot
check "boot banner"             "rux 0.8.0 (x86_64)"
check "kernel page tables"      "CR3 switched to kernel page tables"
check "SMP CPUs online"          "CPUs online"
check "cpio unpacked"           "cpio: unpacked"
check "procfs mounted"          "procfs mounted at /proc"
check "exec init"               "exec /sbin/init"
check "shell prompt"            "/ # "

# Core commands
check "uname"                   "rux rux 0.8.0"
check "cat /etc/passwd"         "root:x:0:0:root:/root:/bin/sh"
check "cat /etc/os-release"     "NAME=\"rux\""
check "whoami"                  "root"
check "hostname"                "rux"
check "pwd"                     "/"
check "echo"                    "test 123"
check "ls shows bin"            "bin"
check "ls shows etc"            "etc"
check "ls shows proc"           "proc"
check "ls shows tmp"            "tmp"

# Procfs
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
check "proc/uptime"             "0."
check "proc/meminfo"            "MemTotal:"
check "proc/loadavg"            "0.00"
check "proc/mounts"             "rootfs"
check "proc/filesystems"        "ramfs"
check "proc/cmdline"            "rux"
check "proc/1/cmdline"          "init"
check "stat"                    "File:"
check "df"                      "rootfs"
check "uptime"                  "up"
check "touch + ls"              "tfile"
check "sleep + echo"            "sleepdone"
check "rm + echo"               "rmdone"
check "wc -l"                   "1"
check "env"                     "PATH="
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
check "tail (lseek)"           "/bin/sh"
check "find /etc"              "passwd"
check "sort"                   "root"
check "date (clock)"           "0"
check "getpid"                  "mypid="
check "chown"                  "Uid"
check "test -f (access)"       "accessok"
check "cut"                    "root"
check "tr (uppercase)"         "HELLO"
check "tee"                    "testdata"
check "ps shows process"       "PID"
check "proc stat pgid"         "1"
check "dynamic linking"        "dynlink_ok"

fi  # RUN_X86

# ── aarch64 ─────────────────────────────────────────────────────────
if $RUN_AA64; then
printf "\n\033[1m── aarch64 ──\033[0m\n"

OUTPUT=$( { sleep 18; cat <<'CMDS'
uname -a
cat /etc/passwd
cat /etc/os-release
whoami
hostname
pwd
ls /
echo test 123
cat /proc/version
free | head -2
readlink /bin/sh
echo hello | wc -w
id
grep root /etc/passwd
expr 2 + 3
ln -s /bin/busybox /tmp/mylink && readlink /tmp/mylink
mkdir /tmp/d && ls /tmp
echo -n abcd | wc -c
seq 1 3
/bin/auxv
basename /usr/bin/id
cat /proc/self/status
true && echo ok42
echo redir_test > /tmp/r && cat /tmp/r
echo hi > /tmp/t && mv /tmp/t /tmp/t2 && cat /tmp/t2
printf "hello world\n" | wc -w
ps aux | head -5
cat /proc/uptime
cat /proc/meminfo
cat /proc/loadavg
cat /proc/mounts
cat /proc/filesystems
cat /proc/cmdline
cat /proc/1/cmdline
stat /bin/sh
df /
uptime
touch /tmp/tfile && ls /tmp/tfile
sleep 0 && echo sleepdone
rm /tmp/tfile && echo rmdone
wc -l /etc/passwd
env | head -1
ln /bin/busybox /tmp/hl && ls /tmp/hl
chmod 777 /tmp/hl && stat /tmp/hl
echo test > /dev/null && echo devnull_ok
ls /dev
kill -0 1 && echo killcheck
kill -0 99 ; echo exitcode=$?
dd if=/dev/zero bs=4 count=1 2>/dev/null | wc -c
cat /dev/urandom | head -c 8 | wc -c
touch /tmp/ts && stat /tmp/ts | grep Modify
echo abc | cat
tail -c 8 /etc/passwd
find /etc -type f 2>/dev/null
sort /etc/passwd
date +%s
echo mypid=$$ done
chown 0:0 /tmp/hl && stat /tmp/hl | grep Uid
stat /etc/passwd > /dev/null && echo accessok
cut -d: -f1 /etc/passwd
echo hello | tr a-z A-Z
echo testdata | tee /tmp/tee_out > /dev/null && cat /tmp/tee_out
ps aux | head -5
trap "echo trapped_sig" TERM ; kill -15 $$ ; echo after_trap
cat /proc/$$/stat | cut -d" " -f5
/bin/dynhello
exit
CMDS
} | \
    "$QEMU_AA64" -machine virt -cpu max -smp 2 \
    -kernel target/aarch64-unknown-none/debug/rux-kernel \
    -device loader,file=initramfs/initramfs_aarch64.cpio,addr=0x45000000,force-raw=on \
    -chardev stdio,id=char0,logfile=/tmp/rux_serial_aarch64.log \
    -serial chardev:char0 -display none \
    -semihosting -no-reboot -m 128M 2>&1 || true )

echo "$OUTPUT" > /tmp/rux_test_aarch64.log

# Boot
check "boot banner"             "rux 0.8.0 (aarch64)"
check "MMU enabled"             "MMU enabled"
check "SMP CPUs online"          "CPUs online"
check "cpio unpacked"           "cpio: unpacked"
check "procfs mounted"          "procfs mounted at /proc"
check "exec init"               "exec /sbin/init"
check "shell prompt"            "/ # "

# Core commands
check "uname"                   "rux rux 0.8.0"
check "cat /etc/passwd"         "root:x:0:0:root:/root:/bin/sh"
check "cat /etc/os-release"     "NAME=\"rux\""
check "whoami"                  "root"
check "hostname"                "rux"
check "pwd"                     "/"
check "echo"                    "test 123"
check "ls shows bin"            "bin"
check "ls shows etc"            "etc"
check "ls shows proc"           "proc"
check "ls shows tmp"            "tmp"

# Procfs
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
check "ps shows process"        "PID"
check "proc/uptime"             "0."
check "proc/meminfo"            "MemTotal:"
check "proc/loadavg"            "0.00"
check "proc/mounts"             "rootfs"
check "proc/filesystems"        "ramfs"
check "proc/cmdline"            "rux"
check "proc/1/cmdline"          "init"
check "stat"                    "File:"
check "df"                      "rootfs"
check "uptime"                  "up"
check "touch + ls"              "tfile"
check "sleep + echo"            "sleepdone"
check "rm + echo"               "rmdone"
check "wc -l"                   "1"
check "env"                     "PATH="
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
check "tail (lseek)"           "/bin/sh"
check "find /etc"              "passwd"
check "sort"                   "root"
check "date (clock)"           "0"
check "getpid"                  "mypid="
check "chown"                  "Uid"
check "test -f (access)"       "accessok"
check "cut"                    "root"
check "tr (uppercase)"         "HELLO"
check "tee"                    "testdata"
check "ps shows process"       "PID"
check "proc stat pgid"         "1"
check "dynamic linking"        "dynlink_ok"

fi  # RUN_AA64

# ── aarch64 networking tests (opt-in: TEST_NET=1) ─────────────────
if $RUN_AA64 && [ "${TEST_NET:-0}" = "1" ]; then
printf "\n\033[1m── aarch64 networking ──\033[0m\n"
# Rebuild with net feature
cargo build --target aarch64-unknown-none -p rux-kernel --features net 2>&1 | tail -1

OUTPUT=$( { sleep 18; cat <<'CMDS'
true
ping -c 1 -W 5 10.0.2.2
echo ping_done
exit
CMDS
} | \
    "$QEMU_AA64" -machine virt -cpu max -smp 2 \
    -kernel target/aarch64-unknown-none/debug/rux-kernel \
    -device loader,file=initramfs/initramfs_aarch64.cpio,addr=0x45000000,force-raw=on \
    -netdev user,id=net0 -device virtio-net-device,netdev=net0 \
    -chardev stdio,id=char0,logfile=/tmp/rux_serial_net.log \
    -serial chardev:char0 -display none \
    -semihosting -no-reboot -m 128M 2>&1 || true )

echo "$OUTPUT" > /tmp/rux_test_net.log

check "net: virtio-net detected"   "virtio-net: MAC="
check "net: ping reply"            "1 packets received"
check "net: ping done"             "ping_done"

# Rebuild WITHOUT net for subsequent tests
cargo build --target aarch64-unknown-none -p rux-kernel 2>&1 | tail -1
fi

# ── Summary ─────────────────────────────────────────────────────────
printf "\n\033[1m%d passed, %d failed\033[0m\n" "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
    printf "Logs: /tmp/rux_test_*.log /tmp/rux_serial_*.log\n"
fi
[ "$FAIL" -eq 0 ] || exit 1
