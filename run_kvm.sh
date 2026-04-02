#!/bin/sh
# Run rux kernel with KVM acceleration (requires Linux host with /dev/kvm).
# Uses -cpu host to expose real CPU features (FSGSBASE, SMAP, etc.)
# so the kernel can detect KVM and enable swapgs + gs:[offset].
set -e

[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

QEMU="${QEMU:-qemu-system-x86_64}"
TARGET="x86_64-unknown-none"
KERNEL="target/${TARGET}/debug/rux-kernel"
INITRD="initramfs/initramfs_x86_64.cpio"

[ -f "${INITRD}" ] || bash initramfs/build.sh

rustup run nightly cargo build -p rux-kernel --target ${TARGET}
rust-objcopy --output-target=elf32-i386 ${KERNEL} ${KERNEL}.elf32

exec ${QEMU} \
  -enable-kvm -cpu host -smp 2 \
  -kernel ${KERNEL}.elf32 \
  -initrd ${INITRD} \
  -serial mon:stdio \
  -display none \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  -no-reboot \
  -monitor none \
  -m 128M
