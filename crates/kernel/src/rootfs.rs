/// Busybox-compatible rootfs layout.
///
/// Populates the ramfs with the full directory tree, symlinks, and config
/// files at boot. All commands are symlinks to `/bin/rux-box`.

use rux_vfs::{FileSystem, FileName};

// ── Directories (parent-before-child order) ─────────────────────────

const DIRS: &[&[u8]] = &[
    b"bin", b"sbin",
    b"usr", b"usr/bin", b"usr/sbin", b"usr/lib",
    b"etc", b"etc/init.d",
    b"dev", b"proc", b"sys",
    b"tmp", b"var", b"var/log", b"var/run", b"var/tmp",
    b"root", b"home", b"lib", b"mnt", b"opt", b"run",
];

// ── Symlinks: (parent_dir, name, target) ────────────────────────────
// All target "rux-box" (relative symlink in same directory)

const BIN_CMDS: &[&[u8]] = &[
    b"sh", b"ash", b"cat", b"cp", b"date", b"dd", b"df", b"dmesg", b"hostname",
    b"echo", b"ed", b"egrep", b"false", b"fgrep", b"grep",
    b"gunzip", b"gzip", b"kill", b"ln", b"ls", b"mkdir", b"mknod",
    b"mktemp", b"more", b"mount", b"mv", b"nice", b"nohup",
    b"pidof", b"ping", b"printenv", b"printf", b"ps", b"pwd",
    b"rm", b"rmdir", b"sed", b"sleep", b"sort", b"stat", b"stty",
    b"sync", b"tail", b"tar", b"tee", b"test", b"[", b"touch",
    b"tr", b"true", b"umount", b"uname", b"uniq", b"vi",
    b"wc", b"which", b"xargs", b"yes", b"zcat",
];

const SBIN_CMDS: &[&[u8]] = &[
    b"halt", b"ifconfig", b"init", b"insmod", b"lsmod",
    b"modprobe", b"poweroff", b"reboot", b"rmmod", b"route",
    b"swapon", b"swapoff", b"sysctl",
];

const USR_BIN_CMDS: &[&[u8]] = &[
    b"awk", b"basename", b"clear", b"cut", b"dirname", b"du",
    b"env", b"expr", b"find", b"fold", b"free", b"head", b"id",
    b"install", b"killall", b"less", b"logger", b"md5sum",
    b"mkfifo", b"nohup", b"od", b"paste", b"patch", b"pgrep",
    b"readlink", b"realpath", b"seq", b"sha1sum", b"sha256sum",
    b"sha512sum", b"shuf", b"split", b"strings", b"tac",
    b"time", b"top", b"tty", b"uptime", b"wget", b"whoami",
];

const USR_SBIN_CMDS: &[&[u8]] = &[
    b"addgroup", b"adduser", b"chroot", b"crond", b"delgroup", b"deluser",
];

// ── Config files: (path components, contents, mode) ─────────────────

struct ConfigFile {
    dir: &'static [u8],   // parent directory path component under root
    name: &'static [u8],
    contents: &'static [u8],
    mode: u32,
}

const CONFIG_FILES: &[ConfigFile] = &[
    ConfigFile { dir: b"etc", name: b"passwd",
        contents: b"root:x:0:0:root:/root:/bin/sh\n", mode: 0o644 },
    ConfigFile { dir: b"etc", name: b"group",
        contents: b"root:x:0:\n", mode: 0o644 },
    ConfigFile { dir: b"etc", name: b"hostname",
        contents: b"rux\n", mode: 0o644 },
    ConfigFile { dir: b"etc", name: b"hosts",
        contents: b"127.0.0.1\tlocalhost\n::1\tlocalhost\n", mode: 0o644 },
    ConfigFile { dir: b"etc", name: b"profile",
        contents: b"export PATH=/bin:/sbin:/usr/bin:/usr/sbin\nexport HOME=/root\n", mode: 0o644 },
    ConfigFile { dir: b"etc", name: b"inittab",
        contents: b"::sysinit:/etc/init.d/rcS\n::respawn:/bin/sh\n", mode: 0o644 },
    ConfigFile { dir: b"etc", name: b"fstab",
        contents: b"# /etc/fstab\n", mode: 0o644 },
    ConfigFile { dir: b"etc", name: b"os-release",
        contents: b"NAME=\"rux\"\nVERSION=\"0.1.0\"\nID=rux\n", mode: 0o644 },
    ConfigFile { dir: b"etc", name: b"shells",
        contents: b"/bin/sh\n/bin/ash\n", mode: 0o644 },
    ConfigFile { dir: b"etc/init.d", name: b"rcS",
        contents: b"#!/bin/sh\necho \"rux init\"\n", mode: 0o755 },
    ConfigFile { dir: b"etc", name: b"motd",
        contents: b"Welcome to rux!\nType 'ls' for commands, 'q' to quit.\n", mode: 0o644 },
];

// ── Orchestrator ────────────────────────────────────────────────────

/// Populate the ramfs with the full busybox-compatible rootfs layout.
///
/// `fs` must be a freshly initialized RamFs (root inode = 0).
/// `elf_data` is the rux-box ELF binary for this architecture.
pub fn populate(
    fs: &mut rux_vfs::ramfs::RamFs,
    elf_data: &[u8],
) {
    let root = fs.root_inode();

    // Phase 1: Create all directories
    // DIRS entries are in parent-before-child order.
    // We need to resolve parent directories for nested ones.
    for &dir_path in DIRS {
        // Split path into parent + basename
        if let Some(slash) = dir_path.iter().rposition(|&b| b == b'/') {
            // Nested: e.g. "usr/bin" → parent="usr", name="bin"
            let parent_path = &dir_path[..slash];
            let name = &dir_path[slash + 1..];
            // Resolve parent by looking it up from root
            let parent = resolve_dir(fs, root, parent_path);
            fs.mkdir(parent, FileName::new(name).unwrap(), 0o755).unwrap();
        } else {
            // Top-level: e.g. "bin" → parent=root
            fs.mkdir(root, FileName::new(dir_path).unwrap(), 0o755).unwrap();
        }
    }

    // Phase 2: Write /bin/busybox (the main binary)
    let bin = fs.lookup(root, FileName::new(b"bin").unwrap()).unwrap();
    let box_ino = fs.create(bin, FileName::new(b"busybox").unwrap(), 0o755).unwrap();
    // Write the binary in chunks (may be >1MB)
    let mut offset = 0u64;
    while (offset as usize) < elf_data.len() {
        let chunk = &elf_data[offset as usize..];
        let n = fs.write(box_ino, offset, chunk).unwrap_or(0);
        if n == 0 { break; }
        offset += n as u64;
    }

    // Phase 3: Create symlinks
    // /bin/* → rux-box (relative, same directory)
    let bin_ino = bin;
    for &name in BIN_CMDS {
        fs.symlink(bin_ino, FileName::new(name).unwrap(), b"busybox").unwrap();
    }

    // /sbin/*, /usr/bin/*, /usr/sbin/* → /bin/rux-box (absolute, different dir)
    let sbin = fs.lookup(root, FileName::new(b"sbin").unwrap()).unwrap();
    for &name in SBIN_CMDS {
        fs.symlink(sbin, FileName::new(name).unwrap(), b"/bin/busybox").unwrap();
    }

    let usr = fs.lookup(root, FileName::new(b"usr").unwrap()).unwrap();
    let usr_bin = fs.lookup(usr, FileName::new(b"bin").unwrap()).unwrap();
    for &name in USR_BIN_CMDS {
        fs.symlink(usr_bin, FileName::new(name).unwrap(), b"/bin/busybox").unwrap();
    }

    let usr_sbin = fs.lookup(usr, FileName::new(b"sbin").unwrap()).unwrap();
    for &name in USR_SBIN_CMDS {
        fs.symlink(usr_sbin, FileName::new(name).unwrap(), b"/bin/busybox").unwrap();
    }

    // Phase 4: Create config files
    for cf in CONFIG_FILES {
        let dir_ino = resolve_dir(fs, root, cf.dir);
        let ino = fs.create(dir_ino, FileName::new(cf.name).unwrap(), cf.mode).unwrap();
        fs.write(ino, 0, cf.contents).unwrap();
    }

    super::serial::write_str("rux: filesystem ready (");
    let count = DIRS.len() + 1 + BIN_CMDS.len() + SBIN_CMDS.len()
        + USR_BIN_CMDS.len() + USR_SBIN_CMDS.len() + CONFIG_FILES.len();
    let mut buf = [0u8; 10];
    super::serial::write_str(super::write_u32(&mut buf, count as u32));
    super::serial::write_str(" entries)\n");
}

/// Resolve a directory path like "usr/bin" from a root inode.
fn resolve_dir(
    fs: &rux_vfs::ramfs::RamFs,
    root: rux_vfs::InodeId,
    path: &[u8],
) -> rux_vfs::InodeId {
    let mut current = root;
    for component in path.split(|&b| b == b'/') {
        if component.is_empty() { continue; }
        current = fs.lookup(current, FileName::new(component).unwrap()).unwrap();
    }
    current
}
