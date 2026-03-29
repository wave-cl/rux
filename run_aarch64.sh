#!/bin/sh
set -e

[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

QEMU="${QEMU:-/opt/local/bin/qemu-system-aarch64}"
TARGET="aarch64-unknown-none"
KERNEL="target/${TARGET}/debug/rux-kernel"

rustup run nightly cargo build -p rux-kernel --target ${TARGET}

exec ${QEMU} -machine virt -cpu cortex-a72 \
  -kernel ${KERNEL} \
  -serial mon:stdio -display none \
  -semihosting -no-reboot -m 128M
