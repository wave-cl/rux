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
FEATURES="${FEATURES:-net}"
rustup run nightly cargo build -p rux-kernel --target ${TARGET} --features "${FEATURES}"

# Convert to 32-bit ELF for QEMU multiboot
rust-objcopy --output-target=elf32-i386 ${KERNEL} ${KERNEL}.elf32

# Optional ext2 root disk (when present, skip initrd — ext2 has the full rootfs)
DISK_ARGS=""
ROOTFS="${ROOTFS:-rootfs/rootfs_x86_64.img}"
if [ -f "${ROOTFS}" ]; then
  DISK_ARGS="-drive file=${ROOTFS},format=raw,if=none,id=disk0 -device virtio-blk-pci,drive=disk0"
  INITRD=""  # ext2 root has all files; initrd causes dynamic linker hangs
fi

# Networking (virtio-net PCI) — QEMU user-mode NAT with SSH port forwarding
NET_ARGS="-netdev user,id=net0,hostfwd=tcp::2222-:22 -device virtio-net-pci,netdev=net0"

# Run
INITRD_ARGS=""
[ -n "${INITRD}" ] && INITRD_ARGS="-initrd ${INITRD}"

# Use KVM if available for ~10x speedup over TCG
ACCEL=""
if [ -e /dev/kvm ] && [ -w /dev/kvm ]; then
  ACCEL="-accel kvm"
fi

exec ${QEMU} \
  ${ACCEL} -cpu max -smp 1 \
  -kernel ${KERNEL}.elf32 \
  ${INITRD_ARGS} \
  ${DISK_ARGS} \
  ${NET_ARGS} \
  -append "init=/sbin/init" \
  -chardev stdio,id=char0,logfile=/tmp/rux_run_serial.log \
  -serial chardev:char0 \
  -display none \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  -no-reboot \
  -monitor none \
  -m 128M
