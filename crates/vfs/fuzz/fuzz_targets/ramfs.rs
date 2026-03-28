#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use rux_vfs::ramfs::{RamFs, PAGE_SIZE};
use rux_vfs::{DirEntry, FileName, FileSystem, InodeStat, InodeType};

use rux_klib::PhysAddr;
use rux_mm::{FrameAllocator, MemoryError, PageSize};

/// Simple mock allocator for fuzzing. Hands out heap-backed pages.
struct MockAllocator {
    pages: Vec<*mut [u8; PAGE_SIZE]>,
}

impl MockAllocator {
    fn new() -> Self {
        Self { pages: Vec::new() }
    }
}

impl FrameAllocator for MockAllocator {
    fn alloc(&mut self, _size: PageSize) -> Result<PhysAddr, MemoryError> {
        let page = Box::new([0u8; PAGE_SIZE]);
        let ptr = Box::into_raw(page);
        self.pages.push(ptr);
        Ok(PhysAddr::new(ptr as usize))
    }

    fn dealloc(&mut self, addr: PhysAddr, _size: PageSize) {
        let ptr = addr.as_usize() as *mut [u8; PAGE_SIZE];
        if let Some(pos) = self.pages.iter().position(|&p| p == ptr) {
            self.pages.swap_remove(pos);
        }
        unsafe { drop(Box::from_raw(ptr)); }
    }

    fn available_frames(&self, _size: PageSize) -> usize {
        usize::MAX
    }
}

impl Drop for MockAllocator {
    fn drop(&mut self) {
        for &ptr in &self.pages {
            unsafe { drop(Box::from_raw(ptr)); }
        }
    }
}

/// Fuzz operations that exercise the RamFs FileSystem trait.
#[derive(Debug, Arbitrary)]
enum FsOp {
    Create { dir: u8, name_seed: u8, mode: u16 },
    Mkdir { dir: u8, name_seed: u8, mode: u16 },
    Lookup { dir: u8, name_seed: u8 },
    Unlink { dir: u8, name_seed: u8 },
    Rmdir { dir: u8, name_seed: u8 },
    Read { ino: u8, offset: u16 },
    Write { ino: u8, offset: u16, data_len: u8 },
    Truncate { ino: u8, size: u16 },
    Link { dir: u8, name_seed: u8, target: u8 },
    Symlink { dir: u8, name_seed: u8, target_len: u8 },
    Readlink { ino: u8 },
    Readdir { dir: u8, offset: u8 },
    Rename { old_dir: u8, old_seed: u8, new_dir: u8, new_seed: u8 },
    Chmod { ino: u8, mode: u16 },
    Chown { ino: u8, uid: u16, gid: u16 },
    Stat { ino: u8 },
}

fn make_name(seed: u8) -> [u8; 4] {
    let mut buf = [b'a', b'a', b'a', 0];
    buf[0] = b'a' + (seed % 26);
    buf[1] = b'a' + ((seed / 26) % 26);
    buf[2] = b'0' + (seed % 10);
    buf
}

fuzz_target!(|ops: Vec<FsOp>| {
    let mut alloc = Box::new(MockAllocator::new());
    let alloc_ptr: *mut dyn FrameAllocator = &mut *alloc as &mut dyn FrameAllocator;
    let mut fs = unsafe { Box::new(RamFs::new(alloc_ptr)) };
    let mut stat_buf = InodeStat {
        ino: 0, mode: 0, nlink: 0, uid: 0, gid: 0,
        size: 0, blocks: 0, blksize: 0, _pad0: 0,
        atime: 0, mtime: 0, ctime: 0, dev: 0, rdev: 0,
    };
    let mut dir_buf = DirEntry {
        ino: 0, kind: InodeType::File, name_len: 0,
        _pad: [0; 6], name: [0; 256],
    };
    let mut read_buf = [0u8; 4096];

    for op in ops.iter().take(256) {
        match op {
            FsOp::Create { dir, name_seed, mode } => {
                let nb = make_name(*name_seed);
                if let Ok(name) = FileName::new(&nb[..3]) {
                    let _ = fs.create(*dir as u64, name, *mode as u32);
                }
            }
            FsOp::Mkdir { dir, name_seed, mode } => {
                let nb = make_name(*name_seed);
                if let Ok(name) = FileName::new(&nb[..3]) {
                    let _ = fs.mkdir(*dir as u64, name, *mode as u32);
                }
            }
            FsOp::Lookup { dir, name_seed } => {
                let nb = make_name(*name_seed);
                if let Ok(name) = FileName::new(&nb[..3]) {
                    let _ = fs.lookup(*dir as u64, name);
                }
            }
            FsOp::Unlink { dir, name_seed } => {
                let nb = make_name(*name_seed);
                if let Ok(name) = FileName::new(&nb[..3]) {
                    let _ = fs.unlink(*dir as u64, name);
                }
            }
            FsOp::Rmdir { dir, name_seed } => {
                let nb = make_name(*name_seed);
                if let Ok(name) = FileName::new(&nb[..3]) {
                    let _ = fs.rmdir(*dir as u64, name);
                }
            }
            FsOp::Read { ino, offset } => {
                let _ = fs.read(*ino as u64, *offset as u64, &mut read_buf);
            }
            FsOp::Write { ino, offset, data_len } => {
                let len = (*data_len as usize).min(256);
                let data = &read_buf[..len]; // reuse as source
                let _ = fs.write(*ino as u64, *offset as u64, data);
            }
            FsOp::Truncate { ino, size } => {
                let _ = fs.truncate(*ino as u64, *size as u64);
            }
            FsOp::Link { dir, name_seed, target } => {
                let nb = make_name(*name_seed);
                if let Ok(name) = FileName::new(&nb[..3]) {
                    let _ = fs.link(*dir as u64, name, *target as u64);
                }
            }
            FsOp::Symlink { dir, name_seed, target_len } => {
                let nb = make_name(*name_seed);
                let tlen = (*target_len as usize).min(64);
                if let Ok(name) = FileName::new(&nb[..3]) {
                    let _ = fs.symlink(*dir as u64, name, &read_buf[..tlen]);
                }
            }
            FsOp::Readlink { ino } => {
                let _ = fs.readlink(*ino as u64, &mut read_buf);
            }
            FsOp::Readdir { dir, offset } => {
                let _ = fs.readdir(*dir as u64, *offset as usize, &mut dir_buf);
            }
            FsOp::Rename { old_dir, old_seed, new_dir, new_seed } => {
                let ob = make_name(*old_seed);
                let nb = make_name(*new_seed);
                if let (Ok(old_name), Ok(new_name)) =
                    (FileName::new(&ob[..3]), FileName::new(&nb[..3]))
                {
                    let _ = fs.rename(*old_dir as u64, old_name, *new_dir as u64, new_name);
                }
            }
            FsOp::Chmod { ino, mode } => {
                let _ = fs.chmod(*ino as u64, *mode as u32);
            }
            FsOp::Chown { ino, uid, gid } => {
                let _ = fs.chown(*ino as u64, *uid as u32, *gid as u32);
            }
            FsOp::Stat { ino } => {
                let _ = fs.stat(*ino as u64, &mut stat_buf);
            }
        }

        // Invariant: root inode is always valid and a directory.
        assert!(fs.stat(0, &mut stat_buf).is_ok());
    }

    // Drop fs before alloc so the allocator is still valid during fs drop (if needed).
    drop(fs);
    drop(alloc);
});
