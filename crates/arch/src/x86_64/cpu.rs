use crate::cpu::CpuFeatures;

pub const TSC: u64           = 1 << 0;
pub const APIC: u64          = 1 << 1;
pub const NX: u64            = 1 << 2;
pub const GBPAGES: u64       = 1 << 3;
pub const PCID: u64          = 1 << 4;
pub const POPCNT: u64        = 1 << 5;
pub const BMI1: u64          = 1 << 6;
pub const BMI2: u64          = 1 << 7;
pub const INVARIANT_TSC: u64 = 1 << 8;
pub const FSGSBASE: u64      = 1 << 9;
pub const SMEP: u64          = 1 << 10;
pub const SMAP: u64          = 1 << 11;
pub const X2APIC: u64        = 1 << 12;
pub const SSE2: u64          = 1 << 13;
pub const XSAVE: u64         = 1 << 14;
pub const UMIP: u64          = 1 << 15;

/// Parse CPUID leaf 1 ECX/EDX into CpuFeatures.
#[inline]
pub const fn parse_cpuid_01(ecx: u32, edx: u32) -> CpuFeatures {
    let mut f: u64 = 0;
    if edx & (1 << 4) != 0 { f |= TSC; }
    if edx & (1 << 9) != 0 { f |= APIC; }
    if edx & (1 << 26) != 0 { f |= SSE2; }
    if ecx & (1 << 23) != 0 { f |= POPCNT; }
    if ecx & (1 << 21) != 0 { f |= X2APIC; }
    if ecx & (1 << 17) != 0 { f |= PCID; }
    if ecx & (1 << 26) != 0 { f |= XSAVE; }
    CpuFeatures(f)
}

/// Parse CPUID leaf 7 subleaf 0 EBX+ECX into CpuFeatures.
#[inline]
pub const fn parse_cpuid_07(ebx: u32, ecx: u32) -> CpuFeatures {
    let mut f: u64 = 0;
    if ebx & (1 << 0) != 0 { f |= FSGSBASE; }
    if ebx & (1 << 3) != 0 { f |= BMI1; }
    if ebx & (1 << 7) != 0 { f |= SMEP; }
    if ebx & (1 << 8) != 0 { f |= BMI2; }
    if ebx & (1 << 20) != 0 { f |= SMAP; }
    if ecx & (1 << 2) != 0 { f |= UMIP; }
    CpuFeatures(f)
}

/// Parse CPUID extended leaf 0x80000001 EDX into CpuFeatures.
#[inline]
pub const fn parse_cpuid_ext_01(edx: u32) -> CpuFeatures {
    let mut f: u64 = 0;
    if edx & (1 << 20) != 0 { f |= NX; }
    if edx & (1 << 26) != 0 { f |= GBPAGES; }
    CpuFeatures(f)
}

/// Parse CPUID extended leaf 0x80000007 EDX for invariant TSC.
#[inline]
pub const fn parse_cpuid_ext_07(edx: u32) -> CpuFeatures {
    let mut f: u64 = 0;
    if edx & (1 << 8) != 0 { f |= INVARIANT_TSC; }
    CpuFeatures(f)
}
