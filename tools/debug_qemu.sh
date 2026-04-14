#!/bin/sh
# Interactive kernel debugger for rux. Launches one QEMU instance with the
# gdbstub enabled (-s) and paused at the reset vector (-S), then prints a
# ready-to-paste gdb command for you to attach.
#
# Usage:
#   tools/debug_qemu.sh                # x86_64 (default), pipes a shell in
#   tools/debug_qemu.sh aarch64        # aarch64
#   tools/debug_qemu.sh x86_64 "<cmd>" # custom command stream (default = /bin/sh)
#
# Typical workflow for debugging a test failure:
#   1. Identify the failing test from test.sh output
#   2. tools/debug_qemu.sh
#   3. In another terminal: rust-gdb -ex 'target remote :1234' \
#          target/x86_64-unknown-none/debug/rux-kernel
#   4. Set breakpoints (e.g., `b rust_begin_unwind` to catch panics,
#      `b crate::syscall::dispatch` to step through syscalls)
#   5. `continue` in gdb — kernel boots, shell runs, reproduce the bug
#   6. When gdb hits a breakpoint you can inspect state, step, etc.
#   7. Quit gdb (detach with `d`), then Ctrl-C QEMU to exit
#
# Notes:
# - QEMU listens on :1234 for the gdbstub protocol (standard port)
# - Paused at start (-S) so gdb has time to attach before the CPU runs
# - Uses the same rootfs and kernel as test.sh

set -e

ARCH="${1:-x86_64}"
CMDS="${2:-/bin/sh}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

QEMU_X86="${QEMU_X86:-/opt/local/bin/qemu-system-x86_64}"
QEMU_AA64="${QEMU_AA64:-/opt/local/bin/qemu-system-aarch64}"

if [ "$ARCH" = "x86_64" ]; then
    KERNEL=target/x86_64-unknown-none/debug/rux-kernel.elf32
    if [ ! -f "$KERNEL" ]; then
        echo "Building x86_64 kernel..."
        cargo build --target x86_64-unknown-none -p rux-kernel --features net
        rust-objcopy --output-target=elf32-i386 \
            target/x86_64-unknown-none/debug/rux-kernel "$KERNEL"
    fi
    [ -f rootfs/alpine_x86_64.img ] || bash rootfs/build_alpine.sh
    ROOTFS=/tmp/rux_debug_x86_64.img
    cp rootfs/alpine_x86_64.img "$ROOTFS"
    debugfs -w -R "rm /etc/inittab" "$ROOTFS" 2>/dev/null

    printf '\n\033[1m[debug] QEMU paused at reset vector.\033[0m\n'
    printf '[debug] Attach with:\n'
    printf '    rust-gdb -ex "target remote :1234" %s\n' \
        target/x86_64-unknown-none/debug/rux-kernel
    printf '[debug] Useful breakpoints:\n'
    printf '    b rust_begin_unwind      # any panic\n'
    printf '    b crate::syscall::dispatch\n'
    printf '    b crate::task_table::wake_sleepers\n'
    printf '[debug] Then `continue` to run the kernel.\n\n'

    printf '%s\n' "$CMDS" | "$QEMU_X86" -cpu max -smp 2 \
        -s -S \
        -kernel "$KERNEL" \
        -drive file="$ROOTFS",format=raw,if=none,id=disk0 -device virtio-blk-pci,drive=disk0 \
        -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
        -serial stdio -display none \
        -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
        -no-reboot -monitor none -m 128M
elif [ "$ARCH" = "aarch64" ]; then
    KERNEL=target/aarch64-unknown-none/debug/rux-kernel
    if [ ! -f "$KERNEL" ]; then
        echo "Building aarch64 kernel..."
        cargo build --target aarch64-unknown-none -p rux-kernel --features net
    fi
    [ -f rootfs/alpine_aarch64.img ] || bash rootfs/build_alpine.sh
    ROOTFS=/tmp/rux_debug_aarch64.img
    cp rootfs/alpine_aarch64.img "$ROOTFS"
    debugfs -w -R "rm /etc/inittab" "$ROOTFS" 2>/dev/null

    printf '\n\033[1m[debug] QEMU paused at reset vector.\033[0m\n'
    printf '[debug] Attach with:\n'
    printf '    rust-gdb -ex "target remote :1234" %s\n' "$KERNEL"
    printf '[debug] Useful breakpoints:\n'
    printf '    b rust_begin_unwind      # any panic\n'
    printf '    b crate::syscall::dispatch\n'
    printf '[debug] Then `continue` to run the kernel.\n\n'

    printf '%s\n' "$CMDS" | "$QEMU_AA64" -machine virt -cpu max -smp 2 \
        -s -S \
        -kernel "$KERNEL" \
        -drive file="$ROOTFS",format=raw,if=none,id=disk0 -device virtio-blk-device,drive=disk0 \
        -netdev user,id=net0 -device virtio-net-device,netdev=net0 \
        -serial stdio -display none \
        -semihosting -no-reboot -m 128M
else
    echo "unknown arch: $ARCH (expected x86_64 or aarch64)" >&2
    exit 2
fi
