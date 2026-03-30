#![feature(test)]
extern crate test;

use rux_klib::PhysAddr;
use rux_arch::pte::{PageTableEntry, PageTableEntryOps};
use rux_arch::cpu::CpuFeatures;
use test::Bencher;

// Benchmarks use aarch64 PTE on this host (aarch64-apple-darwin).
// x86_64 PTE is only available under cfg(test), not bench.
use rux_arch::aarch64::pte::{Aarch64Pte, VALID, TABLE, AF, SH_INNER, ATTR_NORMAL, AP_EL0_RW};

#[bench]
fn bench_pte_encode_4096(b: &mut Bencher) {
    let flags = VALID | TABLE | AF | SH_INNER | ATTR_NORMAL | AP_EL0_RW;
    b.iter(|| {
        for i in 0..4096u64 {
            let pte = Aarch64Pte::encode(PhysAddr::new((i * 4096) as usize), flags);
            test::black_box(pte);
        }
    });
}

#[bench]
fn bench_pte_decode_4096(b: &mut Bencher) {
    let flags = VALID | TABLE | AF | SH_INNER | ATTR_NORMAL | AP_EL0_RW;
    let ptes: Vec<PageTableEntry> = (0..4096u64)
        .map(|i| Aarch64Pte::encode(PhysAddr::new((i * 4096) as usize), flags))
        .collect();
    b.iter(|| {
        for pte in &ptes {
            test::black_box(Aarch64Pte::phys_addr(*pte));
            test::black_box(Aarch64Pte::is_present(*pte));
            test::black_box(Aarch64Pte::is_writable(*pte));
        }
    });
}

#[bench]
fn bench_pte_single_encode_decode(b: &mut Bencher) {
    let flags = VALID | AF;
    b.iter(|| {
        let pte = Aarch64Pte::encode(PhysAddr::new(0x1000), flags);
        let addr = Aarch64Pte::phys_addr(pte);
        test::black_box(addr);
    });
}

#[bench]
fn bench_cpu_features_has(b: &mut Bencher) {
    let features = CpuFeatures(0xFFFF_FFFF_FFFF_FFFF);
    b.iter(|| {
        test::black_box(features.has(1 << 7));
    });
}
