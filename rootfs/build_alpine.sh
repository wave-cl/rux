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
               pcre2 git \
               lua5.4 lua5.4-libs \
               htop \
               openssh-server openssh-keygen openssh-sftp-server \
               libedit \
               dropbear dropbear-dbclient dropbear-scp \
               utmps-libs skalibs-libs; do
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

    # Configure for rux — busybox init starts sshd and shell
    # Both ::respawn: entries run concurrently
    cat > "$STAGING/etc/inittab" << 'CONF'
::respawn:/usr/sbin/sshd -D -e 2>/dev/null
::respawn:/sbin/getty -n -l /bin/sh 0 console
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

    # Enable sshd in default runlevel (OpenRC)
    mkdir -p "$STAGING/etc/runlevels/default"
    ln -sf /etc/init.d/sshd "$STAGING/etc/runlevels/default/sshd" 2>/dev/null || true

    # ── SSH server setup ─────────────────────────────────────────────
    mkdir -p "$STAGING/etc/ssh"
    mkdir -p "$STAGING/root/.ssh"
    chmod 700 "$STAGING/root/.ssh"

    # Pre-generate host keys — ED25519 only (fast on TCG, no RSA keygen)
    ssh-keygen -t ed25519 -f "$STAGING/etc/ssh/ssh_host_ed25519_key" -N "" -q

    # sshd_config: allow root login with key auth
    cat > "$STAGING/etc/ssh/sshd_config" << 'SSHCONF'
Port 22
PermitRootLogin yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication yes
PermitEmptyPasswords yes
HostKey /etc/ssh/ssh_host_ed25519_key
KexAlgorithms curve25519-sha256
Ciphers chacha20-poly1305@openssh.com
MACs hmac-sha2-256-etm@openssh.com
Subsystem sftp /usr/lib/ssh/sftp-server
UseDNS no
SSHCONF

    # Authorize the host user's public key
    if [ -f "$HOME/.ssh/id_ed25519.pub" ]; then
        cat "$HOME/.ssh/id_ed25519.pub" > "$STAGING/root/.ssh/authorized_keys"
    elif [ -f "$HOME/.ssh/id_rsa.pub" ]; then
        cat "$HOME/.ssh/id_rsa.pub" > "$STAGING/root/.ssh/authorized_keys"
    fi
    chmod 600 "$STAGING/root/.ssh/authorized_keys" 2>/dev/null || true

    # Dropbear host key dir (keys generated at first boot with -R flag)
    mkdir -p "$STAGING/etc/dropbear"

    # TCP shell server: accept→fork→pipe-based I/O with /bin/sh
    cat > "$STAGING/usr/bin/tcp-shell" << 'TCPSH'
#!/usr/bin/python3
"""TCP shell server — each connection gets its own /bin/sh via subprocess."""
import socket, os, sys, subprocess
port = int(sys.argv[1]) if len(sys.argv) > 1 else 22
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', port))
s.listen(5)
sys.stderr.write(f'rux: tcp-shell listening on port {port}\n')
sys.stderr.flush()
while True:
    conn, addr = s.accept()
    sys.stderr.write(f'rux: tcp-shell connection from {addr}\n')
    sys.stderr.flush()
    pid = os.fork()
    if pid == 0:
        s.close()
        fd = conn.fileno()
        os.dup2(fd, 0)
        os.dup2(fd, 1)
        os.dup2(fd, 2)
        if fd > 2:
            os.close(fd)
        os.execlp('/bin/sh', 'sh')
    else:
        conn.close()
TCPSH
    chmod 755 "$STAGING/usr/bin/tcp-shell"

    # Boot script: starts sshd
    mkdir -p "$STAGING/etc/init.d"
    cat > "$STAGING/etc/init.d/rux-boot" << 'SCRIPT'
#!/bin/sh
mkdir -p /run /var/run
echo "Starting sshd..." > /dev/console
/usr/sbin/sshd -D -e &
echo "Alpine Linux on rux — ssh root@localhost -p 2222" > /dev/console
SCRIPT
    chmod 755 "$STAGING/etc/init.d/rux-boot"

    # Test scripts for QEMU integration tests
    mkdir -p "$STAGING/usr/share/rux-tests"
    cat > "$STAGING/usr/share/rux-tests/tcp_loopback.py" << 'PYTEST'
import socket,os,time
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("10.0.2.15",7777))
s.listen(1)
pid=os.fork()
if pid==0:
    time.sleep(0.5)
    c=socket.socket()
    c.connect(("10.0.2.15",7777))
    c.send(b"ping")
    c.close()
    os._exit(0)
conn,_=s.accept()
d=conn.recv(16)
conn.close()
s.close()
os.waitpid(pid,0)
print("tcp_"+d.decode())
PYTEST
    cat > "$STAGING/usr/share/rux-tests/http_server.py" << 'PYTEST'
import http.server,threading,time
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"hello_from_rux")
    def log_message(self,*a):pass
s=http.server.HTTPServer(("0.0.0.0",8080),H)
threading.Thread(target=s.serve_forever,daemon=True).start()
time.sleep(1)
import urllib.request
r=urllib.request.urlopen("http://10.0.2.15:8080/")
print("http_ok="+r.read().decode())
s.shutdown()
PYTEST
    cat > "$STAGING/usr/share/rux-tests/socketpair.py" << 'PYTEST'
import os,ctypes
libc=ctypes.CDLL(None)
sv=(ctypes.c_int*2)()
ret=libc.socketpair(1,1,0,sv)
if ret==0:
    a,b=sv[0],sv[1]
    os.write(a,b'hello_sp')
    data=os.read(b,32)
    os.write(b,b'reply_sp')
    data2=os.read(a,32)
    os.close(a);os.close(b)
    print('sp_'+data.decode()+'_'+data2.decode())
else: print('sp_err')
PYTEST
    cat > "$STAGING/usr/share/rux-tests/pipestress.py" << 'PYTEST'
import os
ok=0
for i in range(20):
    r,w=os.pipe()
    pid=os.fork()
    if pid==0:
        os.close(r);os.write(w,str(i).encode()+b'\n');os._exit(0)
    os.close(w);d=os.read(r,32).decode().strip();os.close(r)
    os.waitpid(pid,0)
    if d==str(i):ok+=1
print('pipestress_'+str(ok))
PYTEST
    cat > "$STAGING/usr/share/rux-tests/forkbomb.py" << 'PYTEST'
import os
pids=[]
for i in range(30):
    pid=os.fork()
    if pid==0:os._exit(0)
    pids.append(pid)
for p in pids:
    try:os.waitpid(p,0)
    except ChildProcessError:pass
print('forkbomb_ok')
PYTEST

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
