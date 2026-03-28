#!/bin/sh
set -e

QEMU="${QEMU:-/opt/local/bin/qemu-system-x86_64}"
TARGET="x86_64-unknown-none"
KERNEL="target/${TARGET}/debug/rux-kernel"

# Build
cargo build -p rux-kernel --target ${TARGET}

# Convert to 32-bit ELF for QEMU multiboot
rust-objcopy --output-target=elf32-i386 ${KERNEL} ${KERNEL}.elf32

# Run
exec ${QEMU} \
  -kernel ${KERNEL}.elf32 \
  -serial mon:stdio \
  -display none \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  -no-reboot \
  -monitor none \
  -m 128M
