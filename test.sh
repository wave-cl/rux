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

OUTPUT=$( { sleep 3; \
    printf 'uname -a\n'; sleep 1; \
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
    printf 'echo hi > /tmp/t && mv /tmp/t /tmp/t2 && cat /tmp/t2\n'; sleep 2; \
    printf 'echo hello | wc -w\n'; sleep 2; \
    printf 'grep root /etc/passwd\n'; sleep 1; \
    printf 'expr 2 + 3\n'; sleep 1; \
    printf 'id\n'; sleep 1; \
    printf 'ls /proc\n'; sleep 1; \
    printf 'ls /proc/1\n'; sleep 1; \
    printf 'top -b -n1 | head -5\n'; sleep 2; \
    } | \
    "$QEMU_X86" -cpu Haswell \
    -kernel target/x86_64-unknown-none/debug/rux-kernel.elf32 \
    -initrd initramfs/initramfs_x86_64.cpio \
    -serial mon:stdio -display none \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -no-reboot -monitor none -m 128M 2>&1 || true )

# Boot
check "boot banner"             "rux 0.1.0 (x86_64)"
check "kernel page tables"      "CR3 switched to kernel page tables"
check "cpio unpacked"           "cpio: unpacked"
check "procfs mounted"          "procfs mounted at /proc"
check "exec init"               "exec /sbin/init"
check "shell prompt"            "/ # "

# Core commands
check "uname"                   "rux rux 0.1.0"
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
check "rename (mv)"             "hi"
check "pipe (wc -w)"            "1"
check "grep"                    "root:x:0:0"
check "expr"                    "5"
check "id"                      "uid=0(root)"

# top
check "top shows process"       "PID"

# ── aarch64 ──────────────────────────────────────────────────────────
printf "\n\033[1m── aarch64 ──\033[0m\n"

OUTPUT=$( { sleep 8; \
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
    } | \
    "$QEMU_AA64" -machine virt -cpu cortex-a72 \
    -kernel target/aarch64-unknown-none/debug/rux-kernel \
    -device loader,file=initramfs/initramfs_aarch64.cpio,addr=0x45000000,force-raw=on \
    -serial mon:stdio -display none \
    -semihosting -no-reboot -m 128M 2>&1 || true )

# Boot
check "boot banner"             "rux 0.1.0 (aarch64)"
check "MMU enabled"             "MMU enabled"
check "cpio unpacked"           "cpio: unpacked"
check "procfs mounted"          "procfs mounted at /proc"
check "exec init"               "exec /sbin/init"
check "shell prompt"            "/ # "

# Core commands
check "uname"                   "rux rux 0.1.0"
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

# procfs
check "proc/version"            "rux version"
check "free shows memory"       "Mem:"
check "ls /proc shows 1"        "1"

# File operations
check "readlink"                "busybox"
check "pipe (wc -w)"            "1"
check "id"                      "uid=0(root)"

# ── Summary ──────────────────────────────────────────────────────────
printf "\n\033[1m%d passed, %d failed\033[0m\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
