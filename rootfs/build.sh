#!/bin/sh
# Build ext2 root filesystem images for rux.
# Requires: e2fsprogs (mke2fs)
#   macOS: sudo port install e2fsprogs
# Creates one image per architecture: rootfs_x86_64.img, rootfs_aarch64.img
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
USER_DIR="$ROOT/user"
OUT_DIR="$ROOT/rootfs"

# Find mke2fs
MKE2FS=""
for p in mke2fs /opt/local/sbin/mke2fs /usr/local/sbin/mke2fs /usr/sbin/mke2fs; do
    if command -v "$p" >/dev/null 2>&1; then
        MKE2FS="$p"
        break
    fi
done
if [ -z "$MKE2FS" ]; then
    echo "ERROR: mke2fs not found. Install e2fsprogs:"
    echo "  macOS:  sudo port install e2fsprogs"
    echo "  Linux:  sudo apt install e2fsprogs"
    exit 1
fi

build_rootfs() {
    local ARCH="$1"
    local BUSYBOX="$USER_DIR/busybox_${ARCH}"
    local STAGING="$OUT_DIR/staging_${ARCH}"
    local OUTPUT="$OUT_DIR/rootfs_${ARCH}.img"
    local IMG_SIZE_MB=16

    if [ ! -f "$BUSYBOX" ]; then
        echo "ERROR: $BUSYBOX not found"
        exit 1
    fi

    echo "Building ext2 rootfs for $ARCH..."

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

    # ── Create ext2 image ────────────────────────────────────────
    # -d populates from the staging directory
    rm -f "$OUTPUT"
    dd if=/dev/zero of="$OUTPUT" bs=1M count=$IMG_SIZE_MB 2>/dev/null
    "$MKE2FS" -t ext2 -b 1024 -d "$STAGING" -L rux-root "$OUTPUT" 2>/dev/null

    # Fix file ownership: mke2fs -d preserves host UIDs (e.g., 501 on macOS).
    echo "  Fixing file ownership..."
    python3 -c "
import struct
with open('$OUTPUT', 'r+b') as f:
    f.seek(1024)
    sb = f.read(1024)
    log_bs = struct.unpack_from('<I', sb, 24)[0]
    bs = 1024 << log_bs
    ipg = struct.unpack_from('<I', sb, 40)[0]
    ino_sz = struct.unpack_from('<H', sb, 88)[0]
    n_ino = struct.unpack_from('<I', sb, 0)[0]
    n_bg = (n_ino + ipg - 1) // ipg
    for bg in range(n_bg):
        f.seek(2 * bs + bg * 32)
        bgd = f.read(32)
        it_block = struct.unpack_from('<I', bgd, 8)[0]
        for i in range(ipg):
            off = it_block * bs + i * ino_sz
            f.seek(off + 2)
            f.write(struct.pack('<H', 0))
            f.seek(off + 24)
            f.write(struct.pack('<H', 0))
" 2>/dev/null

    local SIZE=$(wc -c < "$OUTPUT" | tr -d ' ')
    echo "  → $OUTPUT ($SIZE bytes)"

    rm -rf "$STAGING"
}

build_rootfs x86_64
build_rootfs aarch64

echo "Done."
