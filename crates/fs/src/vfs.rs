/// VFS mount/dispatch layer.
///
/// Routes filesystem operations to the correct mounted filesystem based
/// on tagged inode IDs. The upper 8 bits of every InodeId encode the
/// mount index; the lower 56 bits are the real inode from that filesystem.
///
/// Mount index 0 = root filesystem (ramfs). Existing inode IDs are
/// unchanged since their upper bits are zero.

use crate::{FileSystem, FileName, InodeId, InodeStat, DirEntry, VfsError};

const MOUNT_SHIFT: u32 = 56;
const INODE_MASK: u64 = (1u64 << 56) - 1;

#[inline(always)]
fn encode(mount_idx: u8, ino: InodeId) -> InodeId {
    ((mount_idx as u64) << MOUNT_SHIFT) | (ino & INODE_MASK)
}

#[inline(always)]
fn decode(tagged: InodeId) -> (u8, InodeId) {
    ((tagged >> MOUNT_SHIFT) as u8, tagged & INODE_MASK)
}

/// Maximum mount points.
pub const MAX_MOUNTS: usize = 16;

/// A mounted filesystem — enum to avoid trait objects in no_std.
pub enum MountedFs {
    Ram(*mut crate::ramfs::RamFs),
    Ext2(*mut crate::ext2::Ext2Fs),
    Proc(*mut crate::procfs::ProcFs),
    Dev(*mut crate::devfs::DevFs),
    None,
}

/// A mount table entry.
pub struct MountEntry {
    /// Mount index of the parent directory.
    pub parent_mount: u8,
    /// Inode of the directory this FS is mounted over (in parent FS).
    pub parent_ino: InodeId,
    /// Name of the mount point directory component.
    pub name: [u8; 64],
    pub name_len: u8,
    /// The mounted filesystem.
    pub fs: MountedFs,
    pub active: bool,
}

/// Virtual filesystem with mount table.
pub struct Vfs {
    mounts: [MountEntry; MAX_MOUNTS],
}

const EMPTY_MOUNT: MountEntry = MountEntry {
    parent_mount: 0,
    parent_ino: 0,
    name: [0; 64],
    name_len: 0,
    fs: MountedFs::None,
    active: false,
};

impl Vfs {
    /// Initialize a Vfs in-place at a given pointer.
    ///
    /// # Safety
    /// `this` must point to valid, zeroed memory of size >= size_of::<Vfs>().
    /// `root_fs` must be a valid, initialized RamFs.
    pub unsafe fn init_at(this: *mut Self, root_fs: *mut crate::ramfs::RamFs) {
        let vfs = &mut *this;
        vfs.mounts = [EMPTY_MOUNT; MAX_MOUNTS];
        // Mount 0 = root filesystem
        vfs.mounts[0].fs = MountedFs::Ram(root_fs);
        vfs.mounts[0].active = true;
    }

    /// Replace the root filesystem (mount slot 0).
    /// Used to switch from initial ramfs to a real root (e.g., ext2).
    pub fn set_root(&mut self, fs: MountedFs) {
        self.mounts[0].fs = fs;
        self.mounts[0].active = true;
    }

    /// Mount a filesystem at a directory. The directory must exist in
    /// the parent filesystem and be identified by its tagged inode.
    pub fn mount(&mut self, parent_dir_tagged: InodeId, name: &[u8], fs: MountedFs) -> Result<u8, VfsError> {
        let (parent_mount, parent_ino) = decode(parent_dir_tagged);

        // Find free slot
        let idx = self.mounts.iter().position(|m| !m.active)
            .ok_or(VfsError::NoSpace)? as u8;

        let entry = &mut self.mounts[idx as usize];
        entry.parent_mount = parent_mount;
        entry.parent_ino = parent_ino;
        let len = name.len().min(63);
        entry.name[..len].copy_from_slice(&name[..len]);
        entry.name_len = len as u8;
        entry.fs = fs;
        entry.active = true;

        Ok(idx)
    }

    /// Check if a lookup result crosses into a mount point.
    /// If `(mount_idx, dir_ino, name)` matches a mount entry, return
    /// the root inode of the mounted FS (tagged with the mount's index).
    fn check_mount(&self, mount_idx: u8, dir_ino: InodeId, name: FileName<'_>) -> Option<InodeId> {
        let name_bytes = name.as_bytes();
        for (i, m) in self.mounts.iter().enumerate() {
            if !m.active || i == 0 { continue; } // skip root and inactive
            if m.parent_mount == mount_idx
                && m.parent_ino == dir_ino
                && m.name_len as usize == name_bytes.len()
                && &m.name[..m.name_len as usize] == name_bytes
            {
                // Crossing into mount i
                let root = self.get_fs(i as u8).map(|fs| fs.root_inode()).unwrap_or(0);
                return Some(encode(i as u8, root));
            }
        }
        None
    }

    fn get_fs(&self, idx: u8) -> Result<&dyn FileSystem, VfsError> {
        let entry = &self.mounts[idx as usize];
        if !entry.active { return Err(VfsError::NoDevice); }
        match &entry.fs {
            MountedFs::Ram(ptr) => Ok(unsafe { &**ptr }),
            MountedFs::Ext2(ptr) => Ok(unsafe { &**ptr }),
            MountedFs::Proc(ptr) => Ok(unsafe { &**ptr }),
            MountedFs::Dev(ptr) => Ok(unsafe { &**ptr }),
            MountedFs::None => Err(VfsError::NoDevice),
        }
    }

    fn get_fs_mut(&mut self, idx: u8) -> Result<&mut dyn FileSystem, VfsError> {
        let entry = &mut self.mounts[idx as usize];
        if !entry.active { return Err(VfsError::NoDevice); }
        match &mut entry.fs {
            MountedFs::Ram(ptr) => Ok(unsafe { &mut **ptr }),
            MountedFs::Ext2(ptr) => Ok(unsafe { &mut **ptr }),
            MountedFs::Proc(ptr) => Ok(unsafe { &mut **ptr }),
            MountedFs::Dev(ptr) => Ok(unsafe { &mut **ptr }),
            MountedFs::None => Err(VfsError::NoDevice),
        }
    }
}

// ── Permission checks (Linux VFS-conformant) ─────────────────────────

use crate::check_perm;

impl Vfs {
    /// Stat a tagged inode (internal helper for permission checks).
    fn inode_stat(&self, ino: InodeId) -> Result<InodeStat, VfsError> {
        let mut buf = unsafe { core::mem::zeroed::<InodeStat>() };
        self.stat(ino, &mut buf)?;
        Ok(buf)
    }

    /// Check W+X on parent directory — required before create/mkdir/unlink/
    /// rmdir/link/symlink/rename. Matches Linux `may_create()`/`may_delete()`.
    /// If `target` is Some (delete/rename), also checks sticky bit (S_ISVTX):
    /// in a sticky directory, only the file owner, dir owner, or root can delete.
    fn may_modify_dir(&self, dir: InodeId, target: Option<InodeId>, cred: &crate::Credentials) -> Result<(), VfsError> {
        let dir_st = self.inode_stat(dir)?;
        check_perm(&dir_st, cred, crate::W_OK | crate::X_OK)?;
        // Sticky bit check (Linux may_delete)
        if let Some(target_ino) = target {
            if dir_st.mode & crate::S_ISVTX != 0 && cred.euid != 0 {
                let target_st = self.inode_stat(target_ino)?;
                if cred.euid != dir_st.uid && cred.euid != target_st.uid {
                    return Err(VfsError::PermissionDenied);
                }
            }
        }
        Ok(())
    }

    // ── Checked operations (permission-enforcing wrappers) ──────────

    /// Create a regular file, checking W+X on parent directory.
    pub fn checked_create(&mut self, dir: InodeId, name: FileName<'_>, mode: u32, cred: &crate::Credentials) -> Result<InodeId, VfsError> {
        self.may_modify_dir(dir, None, cred)?;
        self.create(dir, name, mode)
    }

    /// Create a directory, checking W+X on parent directory.
    pub fn checked_mkdir(&mut self, dir: InodeId, name: FileName<'_>, mode: u32, cred: &crate::Credentials) -> Result<InodeId, VfsError> {
        self.may_modify_dir(dir, None, cred)?;
        self.mkdir(dir, name, mode)
    }

    /// Remove a file, checking W+X on parent + sticky bit.
    pub fn checked_unlink(&mut self, dir: InodeId, name: FileName<'_>, cred: &crate::Credentials) -> Result<(), VfsError> {
        // Look up target for sticky bit check
        let target = self.lookup(dir, name).ok();
        self.may_modify_dir(dir, target, cred)?;
        self.unlink(dir, name)
    }

    /// Remove a directory, checking W+X on parent + sticky bit.
    pub fn checked_rmdir(&mut self, dir: InodeId, name: FileName<'_>, cred: &crate::Credentials) -> Result<(), VfsError> {
        let target = self.lookup(dir, name).ok();
        self.may_modify_dir(dir, target, cred)?;
        self.rmdir(dir, name)
    }

    /// Create a hard link, checking W+X on parent directory.
    pub fn checked_link(&mut self, dir: InodeId, name: FileName<'_>, target: InodeId, cred: &crate::Credentials) -> Result<(), VfsError> {
        self.may_modify_dir(dir, None, cred)?;
        self.link(dir, name, target)
    }

    /// Create a symlink, checking W+X on parent directory.
    pub fn checked_symlink(&mut self, dir: InodeId, name: FileName<'_>, target: &[u8], cred: &crate::Credentials) -> Result<InodeId, VfsError> {
        self.may_modify_dir(dir, None, cred)?;
        self.symlink(dir, name, target)
    }

    /// Rename, checking W+X on both parent directories + sticky bit on source.
    pub fn checked_rename(&mut self, old_dir: InodeId, old_name: FileName<'_>, new_dir: InodeId, new_name: FileName<'_>, cred: &crate::Credentials) -> Result<(), VfsError> {
        let old_target = self.lookup(old_dir, old_name).ok();
        self.may_modify_dir(old_dir, old_target, cred)?;
        if old_dir != new_dir { self.may_modify_dir(new_dir, None, cred)?; }
        self.rename(old_dir, old_name, new_dir, new_name)
    }

    /// Truncate, checking W on the file.
    pub fn checked_truncate(&mut self, ino: InodeId, size: u64, cred: &crate::Credentials) -> Result<(), VfsError> {
        let st = self.inode_stat(ino)?;
        check_perm(&st, cred, crate::W_OK)?;
        self.truncate(ino, size)
    }

    /// Check access permissions on a file (for open/access syscalls).
    pub fn check_access(&self, ino: InodeId, requested: u32, cred: &crate::Credentials) -> Result<(), VfsError> {
        let st = self.inode_stat(ino)?;
        check_perm(&st, cred, requested)
    }

    /// chmod: only owner or root.
    pub fn checked_chmod(&mut self, ino: InodeId, mode: u32, cred: &crate::Credentials) -> Result<(), VfsError> {
        if cred.euid != 0 {
            let st = self.inode_stat(ino)?;
            if cred.euid != st.uid { return Err(VfsError::PermissionDenied); }
        }
        self.chmod(ino, mode)
    }

    /// chown: only root.
    pub fn checked_chown(&mut self, ino: InodeId, uid: u32, gid: u32, cred: &crate::Credentials) -> Result<(), VfsError> {
        if cred.euid != 0 { return Err(VfsError::PermissionDenied); }
        self.chown(ino, uid, gid)
    }

    /// utimes: owner or root.
    pub fn checked_utimes(&mut self, ino: InodeId, atime: u64, mtime: u64, cred: &crate::Credentials) -> Result<(), VfsError> {
        if cred.euid != 0 {
            let st = self.inode_stat(ino)?;
            if cred.euid != st.uid { return Err(VfsError::PermissionDenied); }
        }
        self.utimes(ino, atime, mtime)
    }
}

impl FileSystem for Vfs {
    fn root_inode(&self) -> InodeId {
        let root_ino = self.get_fs(0).map(|fs| fs.root_inode()).unwrap_or(0);
        encode(0, root_ino)
    }

    fn stat(&self, ino: InodeId, buf: &mut InodeStat) -> Result<(), VfsError> {
        let (idx, real_ino) = decode(ino);
        self.get_fs(idx)?.stat(real_ino, buf)
    }

    fn read(&self, ino: InodeId, offset: u64, buf: &mut [u8]) -> Result<usize, VfsError> {
        let (idx, real_ino) = decode(ino);
        self.get_fs(idx)?.read(real_ino, offset, buf)
    }

    fn write(&mut self, ino: InodeId, offset: u64, buf: &[u8]) -> Result<usize, VfsError> {
        let (idx, real_ino) = decode(ino);
        self.get_fs_mut(idx)?.write(real_ino, offset, buf)
    }

    fn truncate(&mut self, ino: InodeId, size: u64) -> Result<(), VfsError> {
        let (idx, real_ino) = decode(ino);
        self.get_fs_mut(idx)?.truncate(real_ino, size)
    }

    fn lookup(&self, dir: InodeId, name: FileName<'_>) -> Result<InodeId, VfsError> {
        // Check if this name is a mount point
        let (idx, real_dir) = decode(dir);
        if let Some(mounted_root) = self.check_mount(idx, real_dir, name) {
            return Ok(mounted_root);
        }
        // Normal lookup in the underlying FS
        let real_ino = self.get_fs(idx)?.lookup(real_dir, name)?;
        Ok(encode(idx, real_ino))
    }

    fn create(&mut self, dir: InodeId, name: FileName<'_>, mode: u32) -> Result<InodeId, VfsError> {
        let (idx, real_dir) = decode(dir);
        let real_ino = self.get_fs_mut(idx)?.create(real_dir, name, mode)?;
        Ok(encode(idx, real_ino))
    }

    fn mkdir(&mut self, dir: InodeId, name: FileName<'_>, mode: u32) -> Result<InodeId, VfsError> {
        let (idx, real_dir) = decode(dir);
        let real_ino = self.get_fs_mut(idx)?.mkdir(real_dir, name, mode)?;
        Ok(encode(idx, real_ino))
    }

    fn unlink(&mut self, dir: InodeId, name: FileName<'_>) -> Result<(), VfsError> {
        let (idx, real_dir) = decode(dir);
        self.get_fs_mut(idx)?.unlink(real_dir, name)
    }

    fn rmdir(&mut self, dir: InodeId, name: FileName<'_>) -> Result<(), VfsError> {
        let (idx, real_dir) = decode(dir);
        self.get_fs_mut(idx)?.rmdir(real_dir, name)
    }

    fn link(&mut self, dir: InodeId, name: FileName<'_>, target: InodeId) -> Result<(), VfsError> {
        let (dir_idx, real_dir) = decode(dir);
        let (target_idx, real_target) = decode(target);
        if dir_idx != target_idx { return Err(VfsError::CrossDevice); }
        self.get_fs_mut(dir_idx)?.link(real_dir, name, real_target)
    }

    fn symlink(&mut self, dir: InodeId, name: FileName<'_>, target: &[u8]) -> Result<InodeId, VfsError> {
        let (idx, real_dir) = decode(dir);
        let real_ino = self.get_fs_mut(idx)?.symlink(real_dir, name, target)?;
        Ok(encode(idx, real_ino))
    }

    fn readlink(&self, ino: InodeId, buf: &mut [u8]) -> Result<usize, VfsError> {
        let (idx, real_ino) = decode(ino);
        self.get_fs(idx)?.readlink(real_ino, buf)
    }

    fn readdir(&self, dir: InodeId, offset: usize, buf: &mut DirEntry) -> Result<bool, VfsError> {
        let (idx, real_dir) = decode(dir);
        self.get_fs(idx)?.readdir(real_dir, offset, buf)
    }

    fn rename(&mut self, old_dir: InodeId, old_name: FileName<'_>, new_dir: InodeId, new_name: FileName<'_>) -> Result<(), VfsError> {
        let (idx1, real_old) = decode(old_dir);
        let (idx2, real_new) = decode(new_dir);
        if idx1 != idx2 { return Err(VfsError::CrossDevice); }
        self.get_fs_mut(idx1)?.rename(real_old, old_name, real_new, new_name)
    }

    fn chmod(&mut self, ino: InodeId, mode: u32) -> Result<(), VfsError> {
        let (idx, real_ino) = decode(ino);
        self.get_fs_mut(idx)?.chmod(real_ino, mode)
    }

    fn chown(&mut self, ino: InodeId, uid: u32, gid: u32) -> Result<(), VfsError> {
        let (idx, real_ino) = decode(ino);
        self.get_fs_mut(idx)?.chown(real_ino, uid, gid)
    }

    fn utimes(&mut self, ino: InodeId, atime: u64, mtime: u64) -> Result<(), VfsError> {
        let (idx, real_ino) = decode(ino);
        self.get_fs_mut(idx)?.utimes(real_ino, atime, mtime)
    }
}
