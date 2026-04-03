#!/bin/bash
# Test rux kernel on all available QEMU CPU models.
# Quick smoke test: boot + shell prompt + uname + echo
set -e

QEMU_X86="/opt/local/bin/qemu-system-x86_64"
QEMU_AA64="/opt/local/bin/qemu-system-aarch64"

source "$HOME/.cargo/env"

# Build once
printf "\033[1mBuilding...\033[0m\n"
rustup run nightly cargo build -p rux-kernel --target x86_64-unknown-none 2>/dev/null
rustup run nightly cargo build -p rux-kernel --target aarch64-unknown-none 2>/dev/null

run_x86() {
    local cpu="$1"
    local out
    out=$( { cat <<'CMDS'
true
uname -a
echo smoke_ok
exit
CMDS
    } | "$QEMU_X86" -cpu "$cpu" -smp 2 \
        -kernel target/x86_64-unknown-none/debug/rux-kernel.elf32 \
        -initrd initramfs/initramfs_x86_64.cpio \
        -chardev stdio,id=c0,logfile=/dev/null \
        -serial chardev:c0 -display none \
        -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
        -no-reboot -monitor none -m 128M 2>&1 || true )

    local boot=0 prompt=0 uname=0 echo_ok=0
    echo "$out" | grep -qF "exec /sbin/init" && boot=1
    echo "$out" | grep -qF "/ # " && prompt=1
    echo "$out" | grep -qF "rux rux" && uname=1
    echo "$out" | grep -qF "smoke_ok" && echo_ok=1

    local total=$((boot + prompt + uname + echo_ok))
    if [ $total -eq 4 ]; then
        printf "  \033[32m✓\033[0m %-30s  %d/4\n" "$cpu" "$total"
    elif [ $total -eq 0 ]; then
        local reason="no boot"
        echo "$out" | grep -qi "fault\|panic\|abort" && reason="crash"
        echo "$out" | grep -qi "triple\|shutdown" && reason="triple fault"
        printf "  \033[31m✗\033[0m %-30s  %d/4  (%s)\n" "$cpu" "$total" "$reason"
    else
        local details=""
        [ $boot -eq 1 ] && details="${details}boot " || details="${details}- "
        [ $prompt -eq 1 ] && details="${details}prompt " || details="${details}- "
        [ $uname -eq 1 ] && details="${details}uname " || details="${details}- "
        [ $echo_ok -eq 1 ] && details="${details}echo" || details="${details}-"
        printf "  \033[33m~\033[0m %-30s  %d/4  (%s)\n" "$cpu" "$total" "$details"
    fi
}

run_aa64() {
    local cpu="$1"
    local out
    out=$( { cat <<'CMDS'
true
uname -a
echo smoke_ok
exit
CMDS
    } | "$QEMU_AA64" -machine virt -cpu "$cpu" -smp 2 \
        -kernel target/aarch64-unknown-none/debug/rux-kernel \
        -device loader,file=initramfs/initramfs_aarch64.cpio,addr=0x45000000,force-raw=on \
        -chardev stdio,id=c0,logfile=/dev/null \
        -serial chardev:c0 -display none \
        -semihosting -no-reboot -m 128M 2>&1 || true )

    local boot=0 prompt=0 uname=0 echo_ok=0
    echo "$out" | grep -qF "exec /sbin/init" && boot=1
    echo "$out" | grep -qF "/ # " && prompt=1
    echo "$out" | grep -qF "rux rux" && uname=1
    echo "$out" | grep -qF "smoke_ok" && echo_ok=1

    local total=$((boot + prompt + uname + echo_ok))
    if [ $total -eq 4 ]; then
        printf "  \033[32m✓\033[0m %-30s  %d/4\n" "$cpu" "$total"
    elif [ $total -eq 0 ]; then
        local reason="no boot"
        echo "$out" | grep -qi "fault\|panic\|abort\|exception" && reason="crash"
        printf "  \033[31m✗\033[0m %-30s  %d/4  (%s)\n" "$cpu" "$total" "$reason"
    else
        local details=""
        [ $boot -eq 1 ] && details="${details}boot " || details="${details}- "
        [ $prompt -eq 1 ] && details="${details}prompt " || details="${details}- "
        [ $uname -eq 1 ] && details="${details}uname " || details="${details}- "
        [ $echo_ok -eq 1 ] && details="${details}echo" || details="${details}-"
        printf "  \033[33m~\033[0m %-30s  %d/4  (%s)\n" "$cpu" "$total" "$details"
    fi
}

# ── x86_64 CPUs ────────────────────────────────────────────────────
printf "\n\033[1m=== x86_64 CPUs ===\033[0m\n"

X86_CPUS=(
    max
    qemu64
    Nehalem
    Westmere
    SandyBridge
    IvyBridge
    Haswell
    Broadwell
    Skylake-Client
    Skylake-Server
    Cascadelake-Server
    Icelake-Server
    SapphireRapids
    GraniteRapids
    EPYC
    EPYC-Rome
    EPYC-Milan
    EPYC-Genoa
    Opteron_G5
    Denverton
    Snowridge
    Cooperlake
    SierraForest
    ClearwaterForest
    Penryn
    Conroe
    phenom
)

for cpu in "${X86_CPUS[@]}"; do
    run_x86 "$cpu"
done

# ── aarch64 CPUs ───────────────────────────────────────────────────
printf "\n\033[1m=== aarch64 CPUs ===\033[0m\n"

AA64_CPUS=(
    max
    cortex-a53
    cortex-a55
    cortex-a57
    cortex-a72
    cortex-a76
    cortex-a710
    cortex-a78ae
    neoverse-n1
    neoverse-n2
    neoverse-v1
    a64fx
    cortex-a35
)

for cpu in "${AA64_CPUS[@]}"; do
    run_aa64 "$cpu"
done

printf "\n\033[1mDone.\033[0m\n"
