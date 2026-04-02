#!/bin/sh
set -e

[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

QEMU="${QEMU:-/opt/local/bin/qemu-system-aarch64}"
TARGET="aarch64-unknown-none"
KERNEL="target/${TARGET}/debug/rux-kernel"

INITRD="initramfs/initramfs_aarch64.cpio"

# Build initramfs if needed
[ -f "${INITRD}" ] || bash initramfs/build.sh

rustup run nightly cargo build -p rux-kernel --target ${TARGET}

# Load initrd to a known physical address (0x45000000) using generic loader.
# QEMU's -initrd doesn't work reliably with bare ELF kernels on aarch64.
exec ${QEMU} -machine virt -cpu cortex-a72 -smp 2 \
  -kernel ${KERNEL} \
  -device loader,file=${INITRD},addr=0x45000000,force-raw=on \
  -serial mon:stdio -display none \
  -semihosting -no-reboot -m 128M
