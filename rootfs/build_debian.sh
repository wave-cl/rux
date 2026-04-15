#!/bin/sh
# Build Debian rootfs images for rux. Phase A: minimal boot to /bin/sh.
#
# Strategy: debootstrap doesn't run on macOS, and it needs a Linux
# environment with mknod permissions. We use Docker + the matching-arch
# `debian:stable-slim` image to stage the rootfs, then mke2fs on the
# host (same final-image step as build_alpine.sh).
#
# Each arch runs debootstrap in a container of its own architecture
# (Docker Desktop transparently uses qemu-user for the non-native one),
# which keeps postinst scripts native to the target libc.
#
# Output:
#   rootfs/debian_x86_64.img
#   rootfs/debian_aarch64.img
#
# Phase A success criterion: rux boots either image and reaches a
# /bin/sh prompt. No SSH, no test scripts, no LTP — those land in
# Phase B and C of plans/majestic-launching-whisper.md.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$ROOT/rootfs"
DEBIAN_SUITE="${DEBIAN_SUITE:-stable}"
IMG_SIZE_MB="${DEBIAN_IMG_SIZE_MB:-512}"

# Find mke2fs (same probe as build_alpine.sh)
MKE2FS=""
for p in mke2fs /opt/local/sbin/mke2fs /usr/local/sbin/mke2fs /usr/sbin/mke2fs; do
    if command -v "$p" >/dev/null 2>&1; then
        MKE2FS="$p"
        break
    fi
done
if [ -z "$MKE2FS" ]; then
    echo "ERROR: mke2fs not found. Install e2fsprogs."
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker not found. Install Docker Desktop."
    exit 1
fi

# Map rux arch name → docker --platform flag → debootstrap --arch flag.
# Docker uses linux/amd64 + linux/arm64; debootstrap uses amd64 + arm64.
#
# We can't bind-mount the host staging dir into the container because
# Docker Desktop on macOS mounts host volumes with noexec, and
# debootstrap has to exec dpkg (and the postinst scripts run real
# binaries from inside the staged tree). Instead we stage entirely
# inside the container (/var/staging) and stream the result back out
# as a tarball over stdout — host then untars into the staging dir.
debootstrap_in_docker() {
    local ARCH="$1"          # x86_64 | aarch64 (rux naming)
    local DEB_ARCH="$2"      # amd64    | arm64    (debian naming)
    local STAGING_HOST="$3"  # path on host where we untar the result

    rm -rf "$STAGING_HOST"
    mkdir -p "$STAGING_HOST"

    local LOG="$OUT_DIR/debian_build_${ARCH}.log"
    : > "$LOG"

    echo "  Running debootstrap (Docker linux/$DEB_ARCH) → $LOG"
    # The build script writes a tarball to /tmp/staging.tar inside the
    # container, then `cat`s it to stdout as the very last command.
    # All build output (debootstrap chatter, du, etc.) is redirected
    # to fd 2 so it doesn't pollute the tarball stream on fd 1.
    set +e
    docker run --rm -i --platform "linux/$DEB_ARCH" \
        debian:stable-slim \
        sh -c '
set -e
exec 3>&1 1>&2
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq debootstrap
# --include=python3 pulls in cpython + stdlib (~30 MB) so we can run
# tools/syscall_conf.py inside the Debian VM during Phase B. Keeping
# the package list short (just python3) holds the image at ~210 MB.
debootstrap --variant=minbase --arch='"$DEB_ARCH"' \
    --include=python3 \
    '"$DEBIAN_SUITE"' /var/staging http://deb.debian.org/debian | tail -5

# ── Customisation inside the staged tree ──────────────────────────
echo rux > /var/staging/etc/hostname
sed -i "s|^root:[^:]*:|root::|" /var/staging/etc/shadow

# Replace /sbin/init (or rather /usr/sbin/init under the merged-/usr
# layout — /sbin is a symlink to usr/sbin in modern Debian) with a
# symlink to /usr/bin/dash. rux execs /sbin/init at boot; with no
# /etc/inittab the kernel sets argv[0]=/bin/sh so dash runs in shell
# mode reading from stdin, which is exactly how the test.sh pipeline
# drives the Alpine image. No init script, no shebang resolution
# layer, no surprises with mount-of-/dev/null in init context.
rm -f /var/staging/usr/sbin/init
ln -s /usr/bin/dash /var/staging/usr/sbin/init

# Phase B runner: a non-interactive init that just runs the
# conformance script with a start sentinel and exits. The test.sh
# debian-conf group passes init=/sbin/phase-b on the kernel cmdline
# so we never fight the dash-stdin terminal echo race for the
# non-interactive workloads. (No apostrophes in this comment block:
# we are inside a single-quoted sh -c body and a stray apostrophe
# closes it, breaking the host parser.)
echo "#!/bin/sh"                                              > /var/staging/usr/sbin/phase-b
echo "echo ===PHASE_B_START==="                              >> /var/staging/usr/sbin/phase-b
echo "/usr/bin/python3 /usr/share/rux-tests/syscall_conf.py" >> /var/staging/usr/sbin/phase-b
echo "echo ===PHASE_B_END==="                                >> /var/staging/usr/sbin/phase-b
chmod 755 /var/staging/usr/sbin/phase-b

mkdir -p /var/staging/proc /var/staging/sys /var/staging/dev/pts /var/staging/run
: > /var/staging/etc/fstab

# Strip the bits we do not need for Phase A:
rm -rf /var/staging/usr/share/man /var/staging/usr/share/doc /var/staging/usr/share/info
rm -rf /var/staging/var/lib/apt/lists/*
rm -rf /var/staging/var/cache/apt/archives/*.deb
rm -rf /var/staging/var/cache/debconf/*-old
rm -rf /var/staging/var/lib/dpkg/*-old
find /var/staging/usr/share/locale -mindepth 1 -maxdepth 1 -type d \
    ! -name "en" ! -name "en_US*" ! -name "C*" -exec rm -rf {} + 2>/dev/null || true

echo "rux-debian-phase-a" > /var/staging/etc/rux-rootfs-id
du -sh /var/staging

# Stream tarball back to host on fd 1 (which we redirected to fd 3).
tar -C /var/staging -cf - . >&3
' >"$STAGING_HOST/staging.tar" 2>"$LOG"
    local rc=$?
    set -e
    if [ $rc -ne 0 ]; then
        echo "ERROR: debootstrap container failed (exit $rc). See $LOG:"
        tail -20 "$LOG" | sed 's/^/    /'
        return $rc
    fi
    if [ ! -s "$STAGING_HOST/staging.tar" ]; then
        echo "ERROR: empty tarball from container. See $LOG:"
        tail -20 "$LOG" | sed 's/^/    /'
        return 1
    fi

    echo "  Extracting staging tarball ($(wc -c < "$STAGING_HOST/staging.tar") bytes)..."
    tar -C "$STAGING_HOST" -xf "$STAGING_HOST/staging.tar" 2>/dev/null || {
        # Some entries (devices, special perms) may need sudo on macOS.
        # mke2fs -d will reject them anyway — strip with --exclude on
        # retry. For Phase A we don't need /dev/* in the staging tree
        # since the kernel populates devtmpfs at boot.
        echo "  (retrying without /dev entries)"
        tar -C "$STAGING_HOST" --exclude='./dev/*' -xf "$STAGING_HOST/staging.tar"
    }
    rm -f "$STAGING_HOST/staging.tar"
}

# Patch every inode in an ext2 image to uid=0, gid=0. mke2fs -d
# preserves host uids on macOS; rux has no user table so it needs
# root-owned files. Same routine as build_alpine.sh.
fix_ownership() {
    local IMG="$1"
    python3 -c "
import struct
with open('$IMG', 'r+b') as f:
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
}

# Build a single ext2 image from a staging tree.
mkimg() {
    local IMG="$1" STAGING="$2" LABEL="$3"
    rm -f "$IMG"
    dd if=/dev/zero of="$IMG" bs=1M count=$IMG_SIZE_MB 2>/dev/null
    "$MKE2FS" -t ext2 -b 1024 -d "$STAGING" -L "$LABEL" "$IMG" 2>/dev/null
    fix_ownership "$IMG"
    local SIZE=$(wc -c < "$IMG" | tr -d ' ')
    echo "  → $IMG ($SIZE bytes)"
}

build_debian() {
    local ARCH="$1"
    local DEB_ARCH="$2"
    local OUTPUT="$OUT_DIR/debian_${ARCH}.img"
    local OUTPUT_PHASEB="$OUT_DIR/debian_phaseb_${ARCH}.img"
    local STAGING="$OUT_DIR/debian_staging_${ARCH}"

    echo "Building Debian rootfs for $ARCH..."

    debootstrap_in_docker "$ARCH" "$DEB_ARCH" "$STAGING"

    # Phase B: ship tools/syscall_conf.py into the rootfs so the
    # debian conformance group can run the same script the glibc
    # golden was captured from.
    mkdir -p "$STAGING/usr/share/rux-tests"
    cp "$ROOT/tools/syscall_conf.py" "$STAGING/usr/share/rux-tests/syscall_conf.py"

    # Image 1: interactive Debian. /sbin/init -> dash, no Phase B
    # runner. This is the image plain `TEST_ROOTFS=debian` will use.
    echo "  Building interactive image..."
    mkimg "$OUTPUT" "$STAGING" debian-root

    # Image 2: Phase B conformance runner. Re-point /sbin/init at
    # /sbin/phase-b so the kernel boots straight into the conformance
    # script with no shell/stdin in the loop. We need a separate
    # image because rux currently ignores the multiboot/PVH cmdline,
    # so init=... cannot select between them at boot time.
    rm -f "$STAGING/usr/sbin/init"
    ln -s /usr/sbin/phase-b "$STAGING/usr/sbin/init"
    echo "  Building phase-b runner image..."
    mkimg "$OUTPUT_PHASEB" "$STAGING" debian-phaseb

    if [ "${KEEP_STAGING:-0}" != "1" ]; then
        rm -rf "$STAGING"
    fi
}

build_debian x86_64 amd64
build_debian aarch64 arm64

echo "Done."
