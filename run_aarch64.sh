#!/bin/sh
set -e

[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

QEMU="${QEMU:-/opt/local/bin/qemu-system-aarch64}"
TARGET="aarch64-unknown-none"
KERNEL="target/${TARGET}/debug/rux-kernel"

INITRD="initramfs/initramfs_aarch64.cpio"

# Build initramfs if needed
[ -f "${INITRD}" ] || bash initramfs/build.sh

FEATURES="${FEATURES:-net}"
rustup run nightly cargo build -p rux-kernel --target ${TARGET} --features "${FEATURES}"

# Optional ext2 root disk
DISK_ARGS=""
ROOTFS="${ROOTFS:-rootfs/rootfs_aarch64.img}"
if [ -f "${ROOTFS}" ]; then
  DISK_ARGS="-drive file=${ROOTFS},format=raw,if=none,id=disk0 -device virtio-blk-device,drive=disk0"
fi

# Networking (virtio-net MMIO) — QEMU user-mode NAT
NET_ARGS="-netdev user,id=net0 -device virtio-net-device,netdev=net0"

# Load initrd to a known physical address (0x45000000) using generic loader.
# QEMU's -initrd doesn't work reliably with bare ELF kernels on aarch64.
exec ${QEMU} -machine virt -cpu max -smp 2 \
  -kernel ${KERNEL} \
  -device loader,file=${INITRD},addr=0x45000000,force-raw=on \
  ${DISK_ARGS} \
  ${NET_ARGS} \
  -serial mon:stdio -display none \
  -semihosting -no-reboot -m 128M
