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

# Optional ext2 root disk
DISK_ARGS=""
ROOTFS="rootfs/rootfs_x86_64.img"
if [ -f "${ROOTFS}" ]; then
  DISK_ARGS="-drive file=${ROOTFS},format=raw,if=none,id=disk0 -device virtio-blk-pci,drive=disk0"
fi

# Run
exec ${QEMU} \
  -cpu max -smp 2 \
  -kernel ${KERNEL}.elf32 \
  -initrd ${INITRD} \
  ${DISK_ARGS} \
  -serial mon:stdio \
  -display none \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  -no-reboot \
  -monitor none \
  -m 128M
