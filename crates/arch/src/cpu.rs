/// CPU feature bitmask. Each bit represents a specific hardware feature.
/// Architecture-specific feature constants are in the per-arch submodules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct CpuFeatures(pub u64);

const _: () = assert!(core::mem::size_of::<CpuFeatures>() == 8);

impl CpuFeatures {
    pub const EMPTY: Self = Self(0);

    #[inline(always)]
    pub const fn has(self, feature: u64) -> bool {
        self.0 & feature != 0
    }

    #[inline(always)]
    pub const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[inline(always)]
    pub const fn and(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}

/// Detect CPU features at runtime.
pub trait CpuDetect {
    fn detect() -> CpuFeatures;
}

// ── x86_64 feature flags ────────────────────────────────────────────────

#[cfg(any(target_arch = "x86_64", test))]
pub mod x86_64 {
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

    use super::CpuFeatures;

    /// Parse CPUID leaf 1 ECX/EDX into CpuFeatures.
    #[inline]
    pub const fn parse_cpuid_01(ecx: u32, edx: u32) -> CpuFeatures {
        let mut f: u64 = 0;
        if edx & (1 << 4) != 0 { f |= TSC; }
        if edx & (1 << 9) != 0 { f |= APIC; }
        if edx & (1 << 26) != 0 { f |= SSE2; }
        if ecx & (1 << 23) != 0 { f |= POPCNT; }
        if ecx & (1 << 21) != 0 { f |= X2APIC; }
        if ecx & (1 << 26) != 0 { f |= XSAVE; }
        CpuFeatures(f)
    }

    /// Parse CPUID leaf 7 subleaf 0 EBX into CpuFeatures.
    #[inline]
    pub const fn parse_cpuid_07(ebx: u32) -> CpuFeatures {
        let mut f: u64 = 0;
        if ebx & (1 << 0) != 0 { f |= FSGSBASE; }
        if ebx & (1 << 3) != 0 { f |= BMI1; }
        if ebx & (1 << 7) != 0 { f |= SMEP; }
        if ebx & (1 << 8) != 0 { f |= BMI2; }
        if ebx & (1 << 20) != 0 { f |= SMAP; }
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
}

// ── aarch64 feature flags ───────────────────────────────────────────────

#[cfg(any(target_arch = "aarch64", test))]
pub mod aarch64 {
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

    use super::CpuFeatures;

    /// Parse ID_AA64ISAR0_EL1 into CpuFeatures.
    #[inline]
    pub const fn parse_isar0(val: u64) -> CpuFeatures {
        let mut f: u64 = 0;
        // AES: bits 7:4
        if (val >> 4) & 0xF != 0 { f |= AES; }
        // SHA2: bits 15:12
        if (val >> 12) & 0xF != 0 { f |= SHA2; }
        // CRC32: bits 19:16
        if (val >> 16) & 0xF != 0 { f |= CRC32; }
        // Atomics (LSE): bits 23:20
        if (val >> 20) & 0xF != 0 { f |= ATOMICS; }
        // RNG: bits 63:60
        if (val >> 60) & 0xF != 0 { f |= RNG; }
        CpuFeatures(f)
    }

    /// Parse ID_AA64PFR0_EL1 into CpuFeatures.
    #[inline]
    pub const fn parse_pfr0(val: u64) -> CpuFeatures {
        let mut f: u64 = 0;
        // FP: bits 19:16 (0 = implemented, 0xF = not)
        if (val >> 16) & 0xF != 0xF { f |= FP; }
        // ASIMD: bits 23:20
        if (val >> 20) & 0xF != 0xF { f |= ASIMD; }
        // SVE: bits 35:32
        if (val >> 32) & 0xF != 0 { f |= SVE; }
        CpuFeatures(f)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_features_has() {
        let f = CpuFeatures(0b1010);
        assert!(f.has(0b0010));
        assert!(f.has(0b1000));
        assert!(!f.has(0b0100));
        assert!(!f.has(0b0001));
    }

    #[test]
    fn cpu_features_or_and() {
        let a = CpuFeatures(0b1100);
        let b = CpuFeatures(0b1010);
        assert_eq!(a.or(b), CpuFeatures(0b1110));
        assert_eq!(a.and(b), CpuFeatures(0b1000));
    }

    #[test]
    fn cpu_features_empty() {
        let f = CpuFeatures::EMPTY;
        assert_eq!(f.0, 0);
        assert!(!f.has(1));
    }

    // ── x86_64 CPUID parsing ────────────────────────────────────────────

    mod x86_64_tests {
        use super::*;
        use crate::cpu::x86_64::*;

        #[test]
        fn parse_cpuid_01_tsc_apic() {
            // EDX bit 4 = TSC, bit 9 = APIC
            let f = parse_cpuid_01(0, (1 << 4) | (1 << 9));
            assert!(f.has(TSC));
            assert!(f.has(APIC));
            assert!(!f.has(POPCNT));
        }

        #[test]
        fn parse_cpuid_01_popcnt_x2apic() {
            // ECX bit 23 = POPCNT, bit 21 = X2APIC
            let f = parse_cpuid_01((1 << 23) | (1 << 21), 0);
            assert!(f.has(POPCNT));
            assert!(f.has(X2APIC));
            assert!(!f.has(TSC));
        }

        #[test]
        fn parse_cpuid_07_bmi_smep_smap() {
            let f = parse_cpuid_07((1 << 3) | (1 << 7) | (1 << 8) | (1 << 20));
            assert!(f.has(BMI1));
            assert!(f.has(SMEP));
            assert!(f.has(BMI2));
            assert!(f.has(SMAP));
            assert!(!f.has(FSGSBASE));
        }

        #[test]
        fn parse_cpuid_ext_nx_gbpages() {
            let f = parse_cpuid_ext_01((1 << 20) | (1 << 26));
            assert!(f.has(NX));
            assert!(f.has(GBPAGES));
        }

        #[test]
        fn parse_cpuid_ext_invariant_tsc() {
            let f = parse_cpuid_ext_07(1 << 8);
            assert!(f.has(INVARIANT_TSC));
        }

        #[test]
        fn combine_all_cpuid_leaves() {
            let f1 = parse_cpuid_01((1 << 23), (1 << 4) | (1 << 9));
            let f7 = parse_cpuid_07(1 << 3);
            let fe = parse_cpuid_ext_01(1 << 20);
            let combined = f1.or(f7).or(fe);
            assert!(combined.has(TSC));
            assert!(combined.has(APIC));
            assert!(combined.has(POPCNT));
            assert!(combined.has(BMI1));
            assert!(combined.has(NX));
        }
    }

    // ── aarch64 ID register parsing ─────────────────────────────────────

    mod aarch64_tests {
        use super::*;
        use crate::cpu::aarch64::*;

        #[test]
        fn parse_isar0_atomics_aes() {
            // Atomics at bits 23:20 = 0x2 (LSE), AES at bits 7:4 = 0x2
            let val = (0x2u64 << 20) | (0x2u64 << 4);
            let f = parse_isar0(val);
            assert!(f.has(ATOMICS));
            assert!(f.has(AES));
            assert!(!f.has(CRC32));
        }

        #[test]
        fn parse_isar0_crc32_sha2() {
            let val = (0x1u64 << 16) | (0x1u64 << 12);
            let f = parse_isar0(val);
            assert!(f.has(CRC32));
            assert!(f.has(SHA2));
        }

        #[test]
        fn parse_pfr0_fp_asimd() {
            // FP at bits 19:16 = 0x0 (implemented), ASIMD at 23:20 = 0x0
            let val = 0u64; // all zeros = FP + ASIMD present
            let f = parse_pfr0(val);
            assert!(f.has(FP));
            assert!(f.has(ASIMD));
        }

        #[test]
        fn parse_pfr0_no_fp() {
            // FP at bits 19:16 = 0xF (not implemented)
            let val = 0xFu64 << 16;
            let f = parse_pfr0(val);
            assert!(!f.has(FP));
        }

        #[test]
        fn parse_pfr0_sve() {
            // SVE at bits 35:32 = 0x1
            let val = 0x1u64 << 32;
            let f = parse_pfr0(val);
            assert!(f.has(SVE));
        }
    }
}
