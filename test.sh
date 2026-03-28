#!/bin/sh
# QEMU integration tests for rux kernel.
# Runs both x86_64 and aarch64, validates boot, subsystems, and shell.
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

OUTPUT=$( { sleep 3; printf 'ls\n'; sleep 1; printf 'hello\n'; sleep 1; printf 'count\n'; sleep 1; printf 'q\n'; sleep 1; } | \
    "$QEMU_X86" -cpu Haswell \
    -kernel target/x86_64-unknown-none/debug/rux-kernel.elf32 \
    -serial mon:stdio -display none \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -no-reboot -monitor none -m 128M 2>&1 || true )

# Boot & init
check "boot"                    "rux: boot OK"
check "GDT"                     "rux: GDT + TSS loaded"
check "IDT"                     "rux: IDT loaded"
check "timer"                   "rux: timer OK"
check "frame allocator"         "rux: init done"
check "slab"                    "rux: slab OK"
check "page table"              "rux: translate OK"
check "kernel page tables"      "rux: CR3 switched to kernel page tables"

# Scheduling
check "context switch"          "rux: back in main task"
check "preemptive scheduling"   "rux: preemptive scheduling OK"

# Process lifecycle
check "fork/exit/wait"          "rux: process lifecycle OK"

# VFS
check "ramfs"                   "rux: ramfs: 3 files"

# Interactive shell + exec
check "shell prompt"            "rux$ "
check "ls lists hello"          "hello"
check "ls lists count"          "count"
check "ls lists ls"             "ls"
check "exec /hello"             "Hello, world!"
check "exec /count"             "1"
check "count output"            "2"
check "shell exit"              "rux: user exit(0)"

# ── aarch64 ──────────────────────────────────────────────────────────
printf "\n\033[1m── aarch64 ──\033[0m\n"

OUTPUT=$( { sleep 5; printf 'ls\n'; sleep 1; printf 'hello\n'; sleep 1; printf 'count\n'; sleep 1; printf 'q\n'; sleep 1; } | \
    "$QEMU_AA64" -machine virt -cpu cortex-a72 \
    -kernel target/aarch64-unknown-none/debug/rux-kernel \
    -serial mon:stdio -display none \
    -semihosting -no-reboot -m 128M 2>&1 || true )

# Boot & init
check "boot"                    "rux: boot OK"
check "exception vectors"       "rux: exception vectors installed"
check "GIC"                     "rux: GIC initialized"
check "timer"                   "rux: timer OK"
check "frame allocator"         "rux: frame allocator ready"
check "slab"                    "rux: slab OK"
check "page table"              "rux: page table OK"
check "MMU"                     "rux: MMU enabled"

# Scheduling
check "context switch"          "rux: back in main task"
check "preemptive scheduling"   "rux: preemptive scheduling OK"

# Process lifecycle
check "process lifecycle"       "rux: process lifecycle OK"

# VFS
check "ramfs"                   "rux: ramfs: 3 files"

# Interactive shell + exec
check "shell prompt"            "rux$ "
check "ls lists hello"          "hello"
check "ls lists count"          "count"
check "ls lists ls"             "ls"
check "exec /hello"             "Hello, world!"
check "exec /count"             "1"
check "count output"            "2"
check "shell exit"              "rux: user exit(0)"

# ── Summary ──────────────────────────────────────────────────────────
printf "\n\033[1m%d passed, %d failed\033[0m\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
