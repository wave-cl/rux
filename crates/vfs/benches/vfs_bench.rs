#![feature(test)]
extern crate test;

use test::Bencher;

use rux_vfs::ramfs::{RamFs, PAGE_SIZE};
use rux_vfs::path::resolve_path;
use rux_vfs::{DirEntry, FileName, FileSystem, InodeStat, InodeType};

fn new_fs() -> Box<RamFs> {
    Box::new(RamFs::new())
}

fn zeroed_stat() -> InodeStat {
    InodeStat {
        ino: 0, mode: 0, nlink: 0, uid: 0, gid: 0, size: 0,
        blocks: 0, blksize: 0, _pad0: 0, atime: 0, mtime: 0,
        ctime: 0, dev: 0, rdev: 0,
    }
}

fn zeroed_dirent() -> DirEntry {
    DirEntry {
        ino: 0, kind: InodeType::File, name_len: 0,
        _pad: [0; 6], name: [0; 256],
    }
}

#[bench]
fn bench_lookup(b: &mut Bencher) {
    let mut fs = new_fs();
    // Create 32 files so lookup has to scan
    for i in 0..32u8 {
        let name_bytes = [b'f', b'0' + i / 10, b'0' + i % 10];
        let name = FileName::new(&name_bytes[..3]).unwrap();
        fs.create(0, name, 0o644).unwrap();
    }
    // Lookup the last one (worst case linear scan)
    let target = FileName::new(b"f31").unwrap();
    b.iter(|| {
        test::black_box(fs.lookup(0, target).unwrap());
    });
}

#[bench]
fn bench_create(b: &mut Bencher) {
    let mut fs = new_fs();
    let mut idx = 0u32;
    b.iter(|| {
        let mut buf = [0u8; 16];
        let n = fmt_u32(idx, &mut buf);
        if let Ok(name) = FileName::new(&buf[..n]) {
            let _ = fs.create(0, name, 0o644);
        }
        idx = idx.wrapping_add(1);
    });
}

#[bench]
fn bench_read_4k(b: &mut Bencher) {
    let mut fs = new_fs();
    let name = FileName::new(b"bigfile").unwrap();
    let ino = fs.create(0, name, 0o644).unwrap();
    let data = [0xABu8; PAGE_SIZE];
    fs.write(ino, 0, &data).unwrap();
    let mut buf = [0u8; PAGE_SIZE];
    b.iter(|| {
        fs.read(ino, 0, &mut buf).unwrap();
        // Black-box the buffer contents to prevent dead store elimination
        test::black_box(&buf);
    });
}

#[bench]
fn bench_write_4k(b: &mut Bencher) {
    let mut fs = new_fs();
    let name = FileName::new(b"wrfile").unwrap();
    let ino = fs.create(0, name, 0o644).unwrap();
    let data = [0xCDu8; PAGE_SIZE];
    b.iter(|| {
        fs.write(ino, 0, &data).unwrap();
        test::black_box(());
    });
}

#[bench]
fn bench_readdir(b: &mut Bencher) {
    let mut fs = new_fs();
    for i in 0..32u8 {
        let name_bytes = [b'f', b'0' + i / 10, b'0' + i % 10];
        let name = FileName::new(&name_bytes[..3]).unwrap();
        fs.create(0, name, 0o644).unwrap();
    }
    let mut de = zeroed_dirent();
    b.iter(|| {
        let mut off = 0;
        while fs.readdir(0, off, &mut de).unwrap() {
            test::black_box(&de);
            off += 1;
        }
        test::black_box(off);
    });
}

#[bench]
fn bench_stat(b: &mut Bencher) {
    let mut fs = new_fs();
    let name = FileName::new(b"statme").unwrap();
    let ino = fs.create(0, name, 0o644).unwrap();
    let mut st = zeroed_stat();
    b.iter(|| {
        fs.stat(ino, &mut st).unwrap();
        // Black-box the stat buffer to prevent elimination
        test::black_box(&st);
    });
}

#[bench]
fn bench_path_resolve(b: &mut Bencher) {
    let mut fs = new_fs();
    let foo = fs.mkdir(0, FileName::new(b"foo").unwrap(), 0o755).unwrap();
    let bar = fs.mkdir(foo, FileName::new(b"bar").unwrap(), 0o755).unwrap();
    fs.create(bar, FileName::new(b"baz").unwrap(), 0o644).unwrap();
    b.iter(|| {
        test::black_box(resolve_path(&*fs, b"/foo/bar/baz").unwrap());
    });
}

fn fmt_u32(mut v: u32, buf: &mut [u8; 16]) -> usize {
    if v == 0 { buf[0] = b'0'; return 1; }
    let mut i = 16;
    while v > 0 { i -= 1; buf[i] = b'0' + (v % 10) as u8; v /= 10; }
    let len = 16 - i;
    buf.copy_within(i..16, 0);
    len
}
