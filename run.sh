#!/bin/sh
set -e

# Ensure rustup environment is loaded
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

QEMU="${QEMU:-/opt/local/bin/qemu-system-x86_64}"
TARGET="x86_64-unknown-none"
KERNEL="target/${TARGET}/debug/rux-kernel"

INITRD="initramfs/initramfs_x86_64.cpio"

# Build initramfs if needed
[ -f "${INITRD}" ] || bash initramfs/build.sh

# Build with nightly toolchain
rustup run nightly cargo build -p rux-kernel --target ${TARGET}

# Convert to 32-bit ELF for QEMU multiboot
rust-objcopy --output-target=elf32-i386 ${KERNEL} ${KERNEL}.elf32

# Run
exec ${QEMU} \
  -cpu Haswell \
  -kernel ${KERNEL}.elf32 \
  -initrd ${INITRD} \
  -serial mon:stdio \
  -display none \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  -no-reboot \
  -monitor none \
  -m 128M
