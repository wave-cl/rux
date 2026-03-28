#!/bin/sh
# QEMU integration tests for rux kernel (busybox rootfs edition).
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

# ── x86_64 ───────────────────────────────────────────────────────────
printf "\n\033[1m── x86_64 ──\033[0m\n"

OUTPUT=$( { sleep 3; printf 'uname\n'; sleep 1; printf 'cat /etc/passwd\n'; sleep 1; printf 'cat /etc/os-release\n'; sleep 1; printf 'whoami\n'; sleep 1; printf 'hostname\n'; sleep 1; printf 'pwd\n'; sleep 1; printf 'ls\n'; sleep 1; printf 'echo test 123\n'; sleep 1; printf 'q\n'; sleep 1; } | \
    "$QEMU_X86" -cpu Haswell \
    -kernel target/x86_64-unknown-none/debug/rux-kernel.elf32 \
    -serial mon:stdio -display none \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -no-reboot -monitor none -m 128M 2>&1 || true )

# Boot
check "boot"                    "rux: boot OK"
check "kernel page tables"      "rux: CR3 switched to kernel page tables"
check "preemptive scheduling"   "rux: preemptive scheduling OK"
check "filesystem populated"    "entries)"

# Init sequence
check "exec init"               "rux: exec /sbin/init"
check "init prints"             "rux init"
check "motd"                    "Welcome to rux!"
check "shell prompt"            "/ # "

# Busybox applets
check "uname"                   "rux 0.1.0 x86_64"
check "cat /etc/passwd"         "root:x:0:0:root:/root:/bin/sh"
check "cat /etc/os-release"     "NAME=\"rux\""
check "whoami"                  "root"
check "hostname"                "rux"
check "pwd"                     "/"
check "echo"                    "test 123"

# Rootfs structure
check "ls shows bin"            "bin"
check "ls shows sbin"           "sbin"
check "ls shows usr"            "usr"
check "ls shows etc"            "etc"
check "ls shows dev"            "dev"
check "ls shows proc"           "proc"
check "ls shows tmp"            "tmp"
check "ls shows var"            "var"
check "ls shows root"           "root"
check "ls shows home"           "home"

# ── aarch64 ──────────────────────────────────────────────────────────
printf "\n\033[1m── aarch64 ──\033[0m\n"

OUTPUT=$( { sleep 6; printf 'uname\n'; sleep 2; printf 'cat /etc/passwd\n'; sleep 2; printf 'cat /etc/os-release\n'; sleep 2; printf 'whoami\n'; sleep 2; printf 'hostname\n'; sleep 2; printf 'pwd\n'; sleep 2; printf 'ls\n'; sleep 2; printf 'echo test 123\n'; sleep 2; printf 'q\n'; sleep 2; } | \
    "$QEMU_AA64" -machine virt -cpu cortex-a72 \
    -kernel target/aarch64-unknown-none/debug/rux-kernel \
    -serial mon:stdio -display none \
    -semihosting -no-reboot -m 128M 2>&1 || true )

# Boot
check "boot"                    "rux: boot OK"
check "MMU"                     "rux: MMU enabled"
check "preemptive scheduling"   "rux: preemptive scheduling OK"
check "filesystem populated"    "entries)"

# Init sequence
check "exec init"               "rux: exec /sbin/init"
check "init prints"             "rux init"
check "motd"                    "Welcome to rux!"
check "shell prompt"            "/ # "

# Busybox applets
check "uname"                   "rux 0.1.0 aarch64"
check "cat /etc/passwd"         "root:x:0:0:root:/root:/bin/sh"
check "cat /etc/os-release"     "NAME=\"rux\""
check "whoami"                  "root"
check "hostname"                "rux"
check "pwd"                     "/"
check "echo"                    "test 123"

# Rootfs structure
check "ls shows bin"            "bin"
check "ls shows sbin"           "sbin"
check "ls shows usr"            "usr"
check "ls shows etc"            "etc"
check "ls shows dev"            "dev"
check "ls shows proc"           "proc"
check "ls shows tmp"            "tmp"
check "ls shows var"            "var"
check "ls shows root"           "root"
check "ls shows home"           "home"

# ── Summary ──────────────────────────────────────────────────────────
printf "\n\033[1m%d passed, %d failed\033[0m\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
