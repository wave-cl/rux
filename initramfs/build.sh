#!/bin/sh
# Build initramfs cpio archives for rux.
# Creates one per architecture: initramfs_x86_64.cpio, initramfs_aarch64.cpio
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
USER_DIR="$ROOT/user"
OUT_DIR="$ROOT/initramfs"

build_initramfs() {
    local ARCH="$1"
    local BUSYBOX="$USER_DIR/busybox_${ARCH}"
    local STAGING="$OUT_DIR/staging_${ARCH}"
    local OUTPUT="$OUT_DIR/initramfs_${ARCH}.cpio"

    if [ ! -f "$BUSYBOX" ]; then
        echo "ERROR: $BUSYBOX not found"
        exit 1
    fi

    echo "Building initramfs for $ARCH..."

    rm -rf "$STAGING"
    mkdir -p "$STAGING"

    # ── Directories ──────────────────────────────────────────────
    mkdir -p "$STAGING/bin" "$STAGING/sbin"
    mkdir -p "$STAGING/usr/bin" "$STAGING/usr/sbin" "$STAGING/usr/lib"
    mkdir -p "$STAGING/etc/init.d"
    mkdir -p "$STAGING/dev" "$STAGING/proc" "$STAGING/sys"
    mkdir -p "$STAGING/tmp" "$STAGING/var/log" "$STAGING/var/run" "$STAGING/var/tmp"
    mkdir -p "$STAGING/root" "$STAGING/home" "$STAGING/lib" "$STAGING/mnt" "$STAGING/opt" "$STAGING/run"

    # ── Busybox binary ───────────────────────────────────────────
    cp "$BUSYBOX" "$STAGING/bin/busybox"
    chmod 755 "$STAGING/bin/busybox"

    # ── auxv verifier (test binary) ─────────────────────────────
    local AUXV="$USER_DIR/auxv_${ARCH}.elf"
    if [ -f "$AUXV" ]; then
        cp "$AUXV" "$STAGING/bin/auxv"
        chmod 755 "$STAGING/bin/auxv"
    fi

    # ── Dynamic linking test binary + musl ld.so ─────────────────
    local DYNHELLO="$USER_DIR/dynhello_${ARCH}.elf"
    local LDMUSL="$USER_DIR/ld-musl-${ARCH}.so.1"
    if [ -f "$DYNHELLO" ] && [ -f "$LDMUSL" ]; then
        cp "$DYNHELLO" "$STAGING/bin/dynhello"
        chmod 755 "$STAGING/bin/dynhello"
        cp "$LDMUSL" "$STAGING/lib/ld-musl-${ARCH}.so.1"
        chmod 755 "$STAGING/lib/ld-musl-${ARCH}.so.1"
        # musl ld.so IS libc.so — create symlink for ld.so resolution
        ln -sf "ld-musl-${ARCH}.so.1" "$STAGING/lib/libc.so"
        echo "  + dynhello + ld-musl-${ARCH}.so.1"
    fi

    # ── /bin symlinks ────────────────────────────────────────────
    for cmd in sh ash cat cp date dd df dmesg hostname echo ed egrep false fgrep grep \
               gunzip gzip kill ln ls mkdir mknod mktemp more mount mv nice nohup \
               pidof ping printenv printf ps pwd rm rmdir sed sleep sort stat stty \
               sync tail tar tee test '[' touch tr true umount uname uniq vi \
               wc which xargs yes zcat; do
        ln -sf busybox "$STAGING/bin/$cmd"
    done

    # ── /sbin symlinks ───────────────────────────────────────────
    for cmd in halt ifconfig init insmod lsmod modprobe poweroff reboot rmmod route \
               swapon swapoff sysctl; do
        ln -sf /bin/busybox "$STAGING/sbin/$cmd"
    done

    # ── /usr/bin symlinks ────────────────────────────────────────
    for cmd in awk basename clear cut dirname du env expr find fold free head id \
               install killall less logger md5sum mkfifo nohup od paste patch pgrep \
               readlink realpath seq sha1sum sha256sum sha512sum shuf split strings tac \
               time top tty uptime wget whoami; do
        ln -sf /bin/busybox "$STAGING/usr/bin/$cmd"
    done

    # ── /usr/sbin symlinks ───────────────────────────────────────
    for cmd in addgroup adduser chroot crond delgroup deluser; do
        ln -sf /bin/busybox "$STAGING/usr/sbin/$cmd"
    done

    # ── Config files ─────────────────────────────────────────────
    cat > "$STAGING/etc/passwd" << 'CONF'
root:x:0:0:root:/root:/bin/sh
CONF

    cat > "$STAGING/etc/group" << 'CONF'
root:x:0:
CONF

    echo "rux" > "$STAGING/etc/hostname"

    cat > "$STAGING/etc/hosts" << 'CONF'
127.0.0.1	localhost
::1	localhost
CONF

    cat > "$STAGING/etc/profile" << 'CONF'
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
export HOME=/root
echo 'profile loaded'
CONF

    cat > "$STAGING/etc/inittab" << 'CONF'
::sysinit:/etc/init.d/rcS
::respawn:/bin/sh
CONF

    echo "# /etc/fstab" > "$STAGING/etc/fstab"

    cat > "$STAGING/etc/os-release" << 'CONF'
NAME="rux"
VERSION="0.1.0"
ID=rux
CONF

    echo "/bin/sh" > "$STAGING/etc/shells"
    echo "/bin/ash" >> "$STAGING/etc/shells"

    cat > "$STAGING/etc/init.d/rcS" << 'CONF'
#!/bin/sh
echo "rux init"
CONF
    chmod 755 "$STAGING/etc/init.d/rcS"

    cat > "$STAGING/etc/motd" << 'CONF'
Welcome to rux!
Type 'ls' for commands, 'q' to quit.
CONF

    # ── Pack cpio archive ────────────────────────────────────────
    cd "$STAGING"
    find . | cpio -H newc --quiet -o > "$OUTPUT"
    cd "$ROOT"

    local SIZE=$(wc -c < "$OUTPUT" | tr -d ' ')
    echo "  → $OUTPUT ($SIZE bytes)"

    rm -rf "$STAGING"
}

build_initramfs x86_64
build_initramfs aarch64

echo "Done."
