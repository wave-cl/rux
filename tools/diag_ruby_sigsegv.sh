#!/bin/sh
# Minimal reproducer for the ruby post-exit SIGSEGV bug.
#
# Runs a small Alpine command sequence in QEMU on the chosen arch and
# greps the serial log for "SIGSEGV". Non-zero exit = SIGSEGV reproduced.
#
# Usage:
#   tools/diag_ruby_sigsegv.sh x86_64 [commands-file]
#   tools/diag_ruby_sigsegv.sh aarch64
#
# If no commands-file is given, the default "ruby then echo done"
# sequence is used. Otherwise the file is piped into the VM's shell.
set -u  # no -e: qemu's isa-debug-exit can return nonzero, don't abort

ARCH="${1:-x86_64}"
CMDS_FILE="${2:-}"
cd "$(dirname "$0")/.."

QEMU_X86="${QEMU_X86:-/opt/local/bin/qemu-system-x86_64}"
QEMU_AA64="${QEMU_AA64:-/opt/local/bin/qemu-system-aarch64}"

TAG="diag"
ROOTFS="/tmp/rux_alpine_${ARCH}.img"
SERIAL="/tmp/rux_serial_${ARCH}_${TAG}.log"

cp "rootfs/alpine_${ARCH}.img" "$ROOTFS"
debugfs -w -R "rm /etc/inittab" "$ROOTFS" 2>/dev/null || true

# Default command sequence — minimal ruby repro + a marker that will
# only print if the shell is still alive AFTER ruby exits.
default_cmds() {
    # Mirrors a shrunk version of the ext-group lead-in plus ruby.
    # If this reproduces, we can bisect inward.
    cat <<'EOF'
echo BEFORE_LOAD
python3 --version 2>&1
python3 -c "print(sum(range(100)))" 2>&1
sh -c 'echo inner1' && sh -c 'echo inner2' && echo sigchain_ok
python3 -c "import os; os.fstat(0); os.fstat(1); print('fstat_ok')" 2>&1
echo BEFORE_RUBY
ruby -e 'puts "ruby:" + (6*7).to_s; puts (1..10).reduce(:+); puts RUBY_PLATFORM' 2>&1
echo AFTER_RUBY
echo AFTER_RUBY_ECHO2
exit
EOF
}

feed_cmds() {
    sleep_time=5
    [ "$ARCH" = "aarch64" ] && sleep_time=30
    sleep "$sleep_time"
    if [ -n "$CMDS_FILE" ]; then
        cat "$CMDS_FILE"
    else
        default_cmds
    fi
}

if [ "$ARCH" = "x86_64" ]; then
    feed_cmds | "$QEMU_X86" -cpu max -smp 2 \
        -kernel target/x86_64-unknown-none/debug/rux-kernel.elf32 \
        -drive file="$ROOTFS",format=raw,if=none,id=disk0 \
        -device virtio-blk-pci,drive=disk0 \
        -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
        -chardev stdio,id=char0,logfile="$SERIAL" \
        -serial chardev:char0 -display none \
        -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
        -no-reboot -monitor none -m 128M 2>&1 >/dev/null
else
    feed_cmds | "$QEMU_AA64" -machine virt -cpu max -smp 2 \
        -kernel target/aarch64-unknown-none/debug/rux-kernel \
        -drive file="$ROOTFS",format=raw,if=none,id=disk0 \
        -device virtio-blk-device,drive=disk0 \
        -netdev user,id=net0 -device virtio-net-device,netdev=net0 \
        -chardev stdio,id=char0,logfile="$SERIAL" \
        -serial chardev:char0 -display none \
        -semihosting -no-reboot -m 128M 2>&1 >/dev/null
fi

printf '\n== %s diag result ==\n' "$ARCH"
if grep -q 'SIGSEGV' "$SERIAL"; then
    printf '\033[31mREPRODUCED\033[0m — SIGSEGV in %s:\n' "$SERIAL"
    grep -B 2 -A 1 'SIGSEGV' "$SERIAL" | sed 's/^/    /'
    exit 1
else
    printf '\033[32mNO REPRO\033[0m — last 10 log lines:\n'
    tail -10 "$SERIAL" | sed 's/^/    /'
    exit 0
fi
