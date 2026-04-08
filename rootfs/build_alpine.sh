#!/bin/sh
# Build Alpine Linux rootfs images for rux.
# Downloads Alpine minirootfs and packages it into ext2 images.
# Requires: e2fsprogs (mke2fs), wget or curl
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$ROOT/rootfs"
ALPINE_VERSION="3.21"
ALPINE_MIRROR="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION}/releases"

# Find mke2fs
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

install_apk() {
    local ROOT_DIR="$1"
    local ARCH="$2"
    local MIRROR="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION}/main/${ARCH}"
    local TMP_DIR="$ROOT_DIR/../apk_tmp_${ARCH}"
    mkdir -p "$TMP_DIR"

    # Fetch the APKINDEX to resolve package names → filenames
    curl -sL "$MIRROR/APKINDEX.tar.gz" -o "$TMP_DIR/APKINDEX.tar.gz"
    tar xzf "$TMP_DIR/APKINDEX.tar.gz" -C "$TMP_DIR" 2>/dev/null || true

    # Parse APKINDEX to find package filenames
    find_pkg() {
        local name="$1"
        awk -v pkg="$name" '
            /^P:/ { p = substr($0, 3) }
            /^V:/ { v = substr($0, 3) }
            /^$/ { if (p == pkg) { print p "-" v ".apk"; exit } }
        ' "$TMP_DIR/APKINDEX"
    }

    # Download and extract a single package (no dependency resolution — just extract)
    fetch_and_extract() {
        local pkg_file="$1"
        if [ -z "$pkg_file" ]; then return; fi
        local url="$MIRROR/$pkg_file"
        local dest="$TMP_DIR/$pkg_file"
        if [ ! -f "$dest" ]; then
            curl -sL "$url" -o "$dest" 2>/dev/null || return
        fi
        # APK files are gzipped tar with a signature + data tarball
        # Extract directly — tar handles the dual-layer
        tar xzf "$dest" -C "$ROOT_DIR" 2>/dev/null || true
    }

    # Core packages needed for python3, perl, ruby, git, curl, sqlite
    for pkg in libgcc musl libstdc++ libbz2 libffi gdbm \
               mpdecimal readline sqlite-libs xz-libs zlib \
               python3 python3-pycache-pyc0 pyc \
               perl \
               yaml gmp libucontext ruby-libs ruby \
               ncurses-terminfo-base ncurses-libs libncursesw sqlite \
               c-ares nghttp2-libs brotli-libs libidn2 libunistring libpsl zstd-libs libcurl curl ca-certificates \
               pcre2 git; do
        local f=$(find_pkg "$pkg")
        if [ -n "$f" ]; then
            fetch_and_extract "$f"
        fi
    done

    rm -rf "$TMP_DIR"
}

build_alpine() {
    local ARCH="$1"
    local ALPINE_ARCH="$2"  # Alpine arch name (x86_64 or aarch64)
    local OUTPUT="$OUT_DIR/alpine_${ARCH}.img"
    local IMG_SIZE_MB=256
    local STAGING="$OUT_DIR/alpine_staging_${ARCH}"
    local TARBALL="$OUT_DIR/alpine-minirootfs-${ALPINE_VERSION}.0-${ALPINE_ARCH}.tar.gz"

    echo "Building Alpine rootfs for $ARCH..."

    # Download minirootfs if not cached
    if [ ! -f "$TARBALL" ]; then
        echo "  Downloading Alpine minirootfs..."
        curl -L -o "$TARBALL" \
            "${ALPINE_MIRROR}/${ALPINE_ARCH}/alpine-minirootfs-${ALPINE_VERSION}.0-${ALPINE_ARCH}.tar.gz" \
            2>/dev/null || {
            echo "ERROR: Failed to download Alpine minirootfs"
            echo "URL: ${ALPINE_MIRROR}/${ALPINE_ARCH}/alpine-minirootfs-${ALPINE_VERSION}.0-${ALPINE_ARCH}.tar.gz"
            exit 1
        }
    fi

    rm -rf "$STAGING"
    mkdir -p "$STAGING"

    # Extract minirootfs
    echo "  Extracting..."
    tar xzf "$TARBALL" -C "$STAGING"

    # Configure for rux
    # Console on serial
    cat > "$STAGING/etc/inittab" << 'CONF'
::sysinit:/sbin/openrc sysinit
::sysinit:/sbin/openrc boot
::wait:/sbin/openrc default
::respawn:/sbin/getty 0 console
::shutdown:/sbin/openrc shutdown
CONF

    # Hostname
    echo "rux" > "$STAGING/etc/hostname"

    # Network (QEMU user-mode defaults)
    mkdir -p "$STAGING/etc/network"
    cat > "$STAGING/etc/network/interfaces" << 'CONF'
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
    address 10.0.2.15
    netmask 255.255.255.0
    gateway 10.0.2.2
CONF

    # DNS resolver (QEMU user-mode DNS)
    echo "nameserver 10.0.2.3" > "$STAGING/etc/resolv.conf"

    # Enable serial console
    echo "console" >> "$STAGING/etc/securetty"

    # Set root password to empty (login without password)
    sed -i '' 's|^root:.*|root::0:0:root:/root:/bin/sh|' "$STAGING/etc/passwd" 2>/dev/null || \
    sed -i 's|^root:.*|root::0:0:root:/root:/bin/sh|' "$STAGING/etc/passwd"
    sed -i '' 's|^root:.*|root:::0:::::|' "$STAGING/etc/shadow" 2>/dev/null || \
    sed -i 's|^root:.*|root:::0:::::|' "$STAGING/etc/shadow"

    # APK repository configuration (HTTP for now — our TCP stack doesn't do TLS)
    mkdir -p "$STAGING/etc/apk"
    cat > "$STAGING/etc/apk/repositories" << CONF
http://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION}/main
http://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION}/community
CONF

    # APK needs these directories
    mkdir -p "$STAGING/var/lib/apk"
    mkdir -p "$STAGING/var/cache/apk"
    mkdir -p "$STAGING/tmp"

    # Pre-install Python3 and Perl (avoids slow apk add during test runs)
    echo "  Pre-installing python3 and perl..."
    install_apk "$STAGING" "$ALPINE_ARCH"

    # Disable busybox trigger — it runs busybox --install + find|awk pipeline
    # which hangs on rux (complex fork/exec chains). Busybox symlinks are
    # already correct from the minirootfs tarball.
    : > "$STAGING/lib/apk/db/triggers" 2>/dev/null || true

    # Disable services that need features we don't have yet
    for svc in hwclock modules sysctl bootmisc hostname networking; do
        rm -f "$STAGING/etc/runlevels/boot/$svc" 2>/dev/null
    done
    for svc in crond; do
        rm -f "$STAGING/etc/runlevels/default/$svc" 2>/dev/null
    done

    # Simple /sbin/init fallback: just spawn a shell
    cat > "$STAGING/sbin/rux-init" << 'INITSCRIPT'
#!/bin/sh
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
mount -t devtmpfs dev /dev 2>/dev/null
echo "Alpine Linux on rux"
exec /bin/sh
INITSCRIPT
    chmod 755 "$STAGING/sbin/rux-init"

    # Create ext2 image
    rm -f "$OUTPUT"
    dd if=/dev/zero of="$OUTPUT" bs=1M count=$IMG_SIZE_MB 2>/dev/null
    "$MKE2FS" -t ext2 -b 1024 -d "$STAGING" -L alpine-root "$OUTPUT" 2>/dev/null

    # Fix file ownership: mke2fs -d preserves host UIDs (e.g., 501 on macOS).
    # Patch all inodes to uid=0, gid=0 so the kernel can access everything.
    echo "  Fixing file ownership..."
    python3 -c "
import struct, sys
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
            f.seek(off + 2)  # uid field at offset 2
            f.write(struct.pack('<H', 0))
            f.seek(off + 24) # gid field at offset 24
            f.write(struct.pack('<H', 0))
" 2>/dev/null

    local SIZE=$(wc -c < "$OUTPUT" | tr -d ' ')
    echo "  → $OUTPUT ($SIZE bytes)"

    rm -rf "$STAGING"
}

build_alpine x86_64 x86_64
build_alpine aarch64 aarch64

echo "Done."
