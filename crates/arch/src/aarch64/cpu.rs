use crate::cpu::CpuFeatures;

pub const FP: u64       = 1 << 0;
pub const ASIMD: u64    = 1 << 1;
pub const ATOMICS: u64  = 1 << 2;  // LSE atomics
pub const CRC32: u64    = 1 << 3;
pub const SHA2: u64     = 1 << 4;
pub const AES: u64      = 1 << 5;
pub const RNG: u64      = 1 << 6;  // RNDR/RNDRRS
pub const BTI: u64      = 1 << 7;
pub const MTE: u64      = 1 << 8;  // Memory Tagging Extension
pub const SVE: u64      = 1 << 9;
pub const PAN: u64      = 1 << 10;

/// Parse ID_AA64ISAR0_EL1 into CpuFeatures.
#[inline]
pub const fn parse_isar0(val: u64) -> CpuFeatures {
    let mut f: u64 = 0;
    if (val >> 4) & 0xF != 0 { f |= AES; }
    if (val >> 12) & 0xF != 0 { f |= SHA2; }
    if (val >> 16) & 0xF != 0 { f |= CRC32; }
    if (val >> 20) & 0xF != 0 { f |= ATOMICS; }
    if (val >> 60) & 0xF != 0 { f |= RNG; }
    CpuFeatures(f)
}

/// Parse ID_AA64PFR0_EL1 into CpuFeatures.
#[inline]
pub const fn parse_pfr0(val: u64) -> CpuFeatures {
    let mut f: u64 = 0;
    if (val >> 16) & 0xF != 0xF { f |= FP; }
    if (val >> 20) & 0xF != 0xF { f |= ASIMD; }
    if (val >> 32) & 0xF != 0 { f |= SVE; }
    CpuFeatures(f)
}

/// Parse ID_AA64MMFR1_EL1 into CpuFeatures.
#[inline]
pub const fn parse_mmfr1(val: u64) -> CpuFeatures {
    let mut f: u64 = 0;
    if (val >> 20) & 0xF >= 1 { f |= PAN; }
    CpuFeatures(f)
}
