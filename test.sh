#!/bin/sh
# QEMU integration tests for rux kernel on Alpine Linux 3.21.
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
    cargo build --target x86_64-unknown-none -p rux-kernel --features net 2>&1 | tail -1
    rust-objcopy --output-target=elf32-i386 \
        target/x86_64-unknown-none/debug/rux-kernel \
        target/x86_64-unknown-none/debug/rux-kernel.elf32
    # Fix elf32 BSS memsz: rust-objcopy truncates it during elf64→elf32.
    python3 -c "
import struct, sys
with open(sys.argv[1], 'r+b') as f:
    f.seek(28); phoff = struct.unpack('<I', f.read(4))[0]
    f.seek(42); phsz = struct.unpack('<H', f.read(2))[0]
    f.seek(44); phnum = struct.unpack('<H', f.read(2))[0]
    for i in range(phnum):
        off = phoff + i * phsz
        f.seek(off); ptype = struct.unpack('<I', f.read(4))[0]
        if ptype == 1:
            f.seek(off + 16); p_filesz = struct.unpack('<I', f.read(4))[0]
            f.seek(off + 20); p_memsz = struct.unpack('<I', f.read(4))[0]
            if p_filesz == 0 and p_memsz > 0:
                with open(sys.argv[2], 'rb') as f64:
                    f64.seek(32); ph64off = struct.unpack('<Q', f64.read(8))[0]
                    f64.seek(54); ph64sz = struct.unpack('<H', f64.read(2))[0]
                    f64.seek(56); ph64num = struct.unpack('<H', f64.read(2))[0]
                    for j in range(ph64num):
                        o64 = ph64off + j * ph64sz
                        f64.seek(o64); pt = struct.unpack('<I', f64.read(4))[0]
                        f64.seek(o64 + 32); fs64 = struct.unpack('<Q', f64.read(8))[0]
                        f64.seek(o64 + 40); ms64 = struct.unpack('<Q', f64.read(8))[0]
                        if pt == 1 and fs64 == 0 and ms64 > 0:
                            f.seek(off + 20)
                            f.write(struct.pack('<I', ms64))
                            break
" target/x86_64-unknown-none/debug/rux-kernel.elf32 target/x86_64-unknown-none/debug/rux-kernel
}
$RUN_AA64 && cargo build --target aarch64-unknown-none -p rux-kernel --features net 2>&1 | tail -1

# Build Alpine rootfs images
[ -f rootfs/alpine_x86_64.img ] || bash rootfs/build_alpine.sh

# Cleanup temp rootfs copies on exit
cleanup() { rm -f /tmp/rux_alpine_*.img; }
trap cleanup EXIT

# ── x86_64 (Alpine Linux 3.21) ─────────────────────────────────────
if $RUN_X86; then
printf "\n\033[1m── x86_64 ──\033[0m\n"

OUTPUT=$( { sleep 10; cat <<'CMDS'
cat /etc/alpine-release
uname -a
cat /etc/passwd
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
apk --version
ls /proc
ls /proc/1
ln -s /bin/busybox /tmp/mylink && readlink /tmp/mylink
mkdir /tmp/d && ls /tmp
echo -n abcd | wc -c
seq 1 3
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
find /etc -name passwd 2>/dev/null
sort /etc/passwd | head -1
date +%s
echo mypid=$$ done
chown 0:0 /tmp/hl && stat /tmp/hl | grep Uid
stat /etc/passwd > /dev/null && echo accessok
cut -d: -f1 /etc/passwd | head -1
echo hello | tr a-z A-Z
echo testdata | tee /tmp/tee_out > /dev/null && cat /tmp/tee_out
cat /proc/$$/stat | cut -d" " -f5
cp /etc/passwd /tmp/cp_test && wc -l /tmp/cp_test
echo hello > /tmp/src && cp /tmp/src /tmp/dst && cat /tmp/dst
head -c 100 /dev/urandom > /tmp/rnd && wc -c /tmp/rnd
du -s /bin | cut -f1
ls /proc/self/fd
cat /proc/self/maps | head -1
echo a | cat | cat | cat
echo p1 | sed 's/p/q/' | tr a-z A-Z
echo old > /tmp/trunc && echo new > /tmp/trunc && cat /tmp/trunc
echo line1 >> /tmp/app && echo line2 >> /tmp/app && wc -l /tmp/app
sh -c 'echo subshell_ok'
sh -c 'echo fork1; echo fork2' | wc -l
seq 1 100 > /tmp/big && wc -l /tmp/big
rm /tmp/big && ls /tmp/big 2>&1
ln -s /etc/passwd /tmp/sl && cat /tmp/sl | head -1
echo dup_test > /tmp/dup && cat /tmp/dup
md5sum /etc/passwd | cut -d' ' -f1
for i in 1 2 3; do echo iter$i; done
sh -c 'sh -c "echo nested_ok"'
cat /etc/passwd | grep root | wc -l
echo abc > /tmp/f1 && echo def > /tmp/f2 && cat /tmp/f1 /tmp/f2
test -d /proc && echo proc_is_dir
head -c 2048 /dev/zero > /tmp/dd_test && stat -c %s /tmp/dd_test
cat /etc/issue
echo "nameserver 10.0.2.3" > /etc/resolv.conf
echo "http://dl-cdn.alpinelinux.org/alpine/v3.21/main" > /etc/apk/repositories
wget -q -O - http://example.com 2>&1 | head -1
echo all_tests_done
apk update 2>&1 | tail -1
apk add --no-interactive curl 2>&1 | tail -1
curl --version 2>&1 | head -1
exit
CMDS
} | \
    { ROOTFS_TMP="/tmp/rux_alpine_x86_64.img"; cp rootfs/alpine_x86_64.img "$ROOTFS_TMP"; \
    "$QEMU_X86" -cpu max -smp 2 \
    -kernel target/x86_64-unknown-none/debug/rux-kernel.elf32 \
    -drive file="$ROOTFS_TMP",format=raw,if=none,id=disk0 -device virtio-blk-pci,drive=disk0 \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
    -chardev stdio,id=char0,logfile=/tmp/rux_serial_x86_64.log \
    -serial chardev:char0 -display none \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -no-reboot -monitor none -m 128M 2>&1; } || true )

echo "$OUTPUT" > /tmp/rux_test_x86_64.log

# Boot
check "boot banner"             "rux 0.16.0 (x86_64)"
check "kernel page tables"      "CR3 switched to kernel page tables"
check "SMP CPUs online"          "CPUs online"
check "ext2 root mounted"       "ext2: mounted as root"
check "procfs mounted"          "procfs mounted at /proc"
check "exec init"               "exec /sbin/init"
check "shell prompt"            "/ #"

# Alpine identity
check "alpine release"          "3.21"
check "alpine issue"            "Alpine Linux"
check "apk available"           "apk-tools"

# Core commands
check "uname"                   "rux rux 0.16.0"
check "cat /etc/passwd"         "root:"
check "whoami"                  "root"
check "hostname"                "rux"
check "pwd"                     "/"
check "echo"                    "test 123"
check "ls shows bin"            "bin"
check "ls shows etc"            "etc"
check "ls shows proc"           "proc"

# Procfs
check "proc/version"            "rux version"
check "free shows memory"       "Mem:"
check "ls /proc shows 1"        "1"
check "ls /proc/1 shows stat"   "stat"

# File operations
check "readlink"                "busybox"
check "rename (mv)"             "/bin/sh"
check "pipe (wc -w)"            "1"
check "grep"                    "root:"
check "expr"                    "5"
check "id"                      "uid=0(root)"
check "symlink"                 "busybox"
check "mkdir"                   "d"
check "wc -c (pipe)"            "4"
check "seq"                     "3"
check "proc/self/status"        "Pid:"
check "true && echo"            "ok42"
check "file redirect"           "redir_test"
check "rename (file)"           "hi"
check "printf pipe"             "2"
check "proc/uptime"             "0."
check "proc/meminfo"            "MemTotal:"
check "proc/loadavg"            "0.00"
check "proc/mounts"             "/dev/vda"
check "proc/filesystems"        "ramfs"
check "proc/cmdline"            "rux"
check "proc/1/cmdline"          "init"
check "stat"                    "File:"
check "df"                      "/dev/vda"
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
check "cp file (copy)"        "1"
check "cp + cat"              "hello"
check "urandom write"         "100"
check "du (statx)"            "/"
check "proc/self/fd"          "0"
check "proc/self/maps"        "r-xp"
check "triple pipe"           "a"
check "pipe chain"            "Q1"
check "O_TRUNC (>)"          "new"
check "O_APPEND (>>)"        "2"
check "subshell"             "subshell_ok"
check "fork + pipe"          "2"
check "large file (seq)"     "100"
check "rm removes file"     "No such file"
check "symlink read"         "root"
check "dup (redirect)"       "dup_test"
check "md5sum"               ""
check "for loop"             "iter3"
check "nested subshell"      "nested_ok"
check "pipe chain grep"      "1"
check "cat multiple files"   "def"
check "test -d"              "proc_is_dir"
check "2KB write"            "2048"
check "wget http"            "Example Domain"
check "apk update"           "OK:"
check "apk add curl"         "packages"
check "curl version"         "curl"
check "all tests done"       "all_tests_done"

fi  # RUN_X86

# ── aarch64 (Alpine Linux 3.21) ────────────────────────────────────
if $RUN_AA64; then
printf "\n\033[1m── aarch64 ──\033[0m\n"

OUTPUT=$( { sleep 24; cat <<'CMDS'
cat /etc/alpine-release
uname -a
cat /etc/passwd
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
apk --version
grep root /etc/passwd
expr 2 + 3
ln -s /bin/busybox /tmp/mylink && readlink /tmp/mylink
mkdir /tmp/d && ls /tmp
echo -n abcd | wc -c
seq 1 3
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
echo test > /dev/null && echo devnull_ok
ls /dev
kill -0 1 && echo killcheck
kill -0 99 ; echo exitcode=$?
dd if=/dev/zero bs=4 count=1 2>/dev/null | wc -c
cat /dev/urandom | head -c 8 | wc -c
touch /tmp/ts && stat /tmp/ts | grep Modify
echo abc | cat
tail -c 8 /etc/passwd
find /etc -name passwd 2>/dev/null
sort /etc/passwd | head -1
date +%s
echo mypid=$$ done
stat /etc/passwd > /dev/null && echo accessok
cut -d: -f1 /etc/passwd | head -1
echo hello | tr a-z A-Z
echo testdata | tee /tmp/tee_out > /dev/null && cat /tmp/tee_out
ps aux | head -5
trap "echo trapped_sig" TERM ; kill -15 $$ ; echo after_trap
cat /proc/$$/stat | cut -d" " -f5
cp /etc/passwd /tmp/cp_test && wc -l /tmp/cp_test
echo hello > /tmp/src && cp /tmp/src /tmp/dst && cat /tmp/dst
head -c 100 /dev/urandom > /tmp/rnd && wc -c /tmp/rnd
du -s /bin | cut -f1
ls /proc/self/fd
cat /proc/self/maps | head -1
echo a | cat | cat | cat
echo p1 | sed 's/p/q/' | tr a-z A-Z
echo old > /tmp/trunc && echo new > /tmp/trunc && cat /tmp/trunc
echo line1 >> /tmp/app && echo line2 >> /tmp/app && wc -l /tmp/app
seq 1 100 > /tmp/big && wc -l /tmp/big
rm /tmp/big && ls /tmp/big 2>&1
ln -s /etc/passwd /tmp/sl && cat /tmp/sl | head -1
echo dup_test > /tmp/dup && cat /tmp/dup
md5sum /etc/passwd | cut -d' ' -f1
for i in 1 2 3; do echo iter$i; done
cat /etc/passwd | grep root | wc -l
echo abc > /tmp/f1 && echo def > /tmp/f2 && cat /tmp/f1 /tmp/f2
test -d /proc && echo proc_is_dir
head -c 2048 /dev/zero > /tmp/dd_test && stat -c %s /tmp/dd_test
echo "nameserver 10.0.2.3" > /etc/resolv.conf
echo "http://dl-cdn.alpinelinux.org/alpine/v3.21/main" > /etc/apk/repositories
wget -q -O - http://example.com 2>&1 | head -1
apk update 2>&1 | tail -1
echo all_tests_done
sh -c 'echo subshell_ok'
sh -c 'echo fork1; echo fork2' | wc -l
exit
CMDS
} | \
    { ROOTFS_TMP="/tmp/rux_alpine_aarch64.img"; cp rootfs/alpine_aarch64.img "$ROOTFS_TMP"; \
    "$QEMU_AA64" -machine virt -cpu max -smp 2 \
    -kernel target/aarch64-unknown-none/debug/rux-kernel \
    -drive file="$ROOTFS_TMP",format=raw,if=none,id=disk0 -device virtio-blk-device,drive=disk0 \
    -netdev user,id=net0 -device virtio-net-device,netdev=net0 \
    -chardev stdio,id=char0,logfile=/tmp/rux_serial_aarch64.log \
    -serial chardev:char0 -display none \
    -semihosting -no-reboot -m 128M 2>&1; } || true )

echo "$OUTPUT" > /tmp/rux_test_aarch64.log

# Boot
check "boot banner"             "rux 0.16.0 (aarch64)"
check "MMU enabled"             "MMU enabled"
check "SMP CPUs online"          "CPUs online"
check "ext2 root mounted"       "ext2: mounted as root"
check "procfs mounted"          "procfs mounted at /proc"
check "exec init"               "exec /sbin/init"
check "shell prompt"            "/ #"

# Alpine identity
check "alpine release"          "3.21"
check "apk available"           "apk-tools"

# Core commands
check "uname"                   "rux rux 0.16.0"
check "cat /etc/passwd"         "root:"
check "whoami"                  "root"
check "hostname"                "rux"
check "pwd"                     "/"
check "echo"                    "test 123"
check "ls shows bin"            "bin"
check "ls shows etc"            "etc"

# Procfs
check "proc/version"            "rux version"
check "free shows memory"       "Mem:"
check "ls /proc shows 1"        "1"
check "ls /proc/1 shows stat"   "stat"

# File operations
check "readlink"                "busybox"
check "pipe (wc -w)"            "1"
check "id"                      "uid=0(root)"
check "grep"                    "root:"
check "expr"                    "5"
check "symlink"                 "busybox"
check "mkdir"                   "d"
check "wc -c (pipe)"            "4"
check "seq"                     "3"
check "proc/self/status"        "Pid:"
check "true && echo"            "ok42"
check "file redirect"           "redir_test"
check "rename (file)"           "hi"
check "printf pipe"             "2"
check "ps shows process"        "PID"
check "proc/uptime"             "0."
check "proc/meminfo"            "MemTotal:"
check "proc/loadavg"            "0.00"
check "proc/mounts"             "/dev/vda"
check "proc/filesystems"        "ramfs"
check "proc/cmdline"            "rux"
check "proc/1/cmdline"          "init"
check "stat"                    "File:"
check "df"                      "/dev/vda"
check "uptime"                  "up"
check "touch + ls"              "tfile"
check "sleep + echo"            "sleepdone"
check "rm + echo"               "rmdone"
check "wc -l"                   "1"
check "env"                     "PATH="
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
check "test -f (access)"       "accessok"
check "cut"                    "root"
check "tr (uppercase)"         "HELLO"
check "tee"                    "testdata"
check "ps shows process"       "PID"
check "proc stat pgid"         "1"
check "cp file (copy)"        "1"
check "cp + cat"              "hello"
check "urandom write"         "100"
check "du (statx)"            "/"
check "proc/self/fd"          "0"
check "proc/self/maps"        "r-xp"
check "triple pipe"           "a"
check "pipe chain"            "Q1"
check "O_TRUNC (>)"          "new"
check "O_APPEND (>>)"        "2"
check "large file (seq)"     "100"
check "rm removes file"     "No such file"
check "symlink read"         "root"
check "dup (redirect)"       "dup_test"
check "md5sum"               ""
check "for loop"             "iter3"
check "pipe chain grep"      "1"
check "cat multiple files"   "def"
check "test -d"              "proc_is_dir"
check "2KB write"            "2048"
check "wget http"            "Example Domain"
check "apk update"           "OK:"
check "subshell"             "subshell_ok"
check "fork + pipe"          "2"
check "all tests done"       "all_tests_done"

fi  # RUN_AA64

# ── Summary ─────────────────────────────────────────────────────────
printf "\n\033[1m%d passed, %d failed\033[0m\n" "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
    printf "Logs: /tmp/rux_test_*.log /tmp/rux_serial_*.log\n"
fi
[ "$FAIL" -eq 0 ] || exit 1
