/// CPU feature bitmask. Each bit represents a specific hardware feature.
/// Architecture-specific feature constants are in the per-arch submodules
/// (x86_64/cpu.rs, aarch64/cpu.rs).
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

/// Global detected CPU features. Set once at boot by `set_cpu_features()`.
static mut CPU_FEATURES: CpuFeatures = CpuFeatures::EMPTY;

/// Store detected features (called once at boot).
///
/// # Safety
/// Must be called before any concurrent access (single-CPU boot context).
pub unsafe fn set_cpu_features(f: CpuFeatures) {
    CPU_FEATURES = f;
}

/// Read the detected features. Safe after boot init completes.
#[inline(always)]
pub fn cpu_features() -> CpuFeatures {
    unsafe { CPU_FEATURES }
}

/// Detect CPU features at runtime.
pub trait CpuDetect {
    fn detect() -> CpuFeatures;
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
        use crate::x86_64::cpu::*;

        #[test]
        fn parse_cpuid_01_tsc_apic() {
            let f = parse_cpuid_01(0, (1 << 4) | (1 << 9));
            assert!(f.has(TSC));
            assert!(f.has(APIC));
            assert!(!f.has(POPCNT));
        }

        #[test]
        fn parse_cpuid_01_popcnt_x2apic() {
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
        use crate::aarch64::cpu::*;

        #[test]
        fn parse_isar0_atomics_aes() {
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
            let val = 0u64;
            let f = parse_pfr0(val);
            assert!(f.has(FP));
            assert!(f.has(ASIMD));
        }

        #[test]
        fn parse_pfr0_no_fp() {
            let val = 0xFu64 << 16;
            let f = parse_pfr0(val);
            assert!(!f.has(FP));
        }

        #[test]
        fn parse_pfr0_sve() {
            let val = 0x1u64 << 32;
            let f = parse_pfr0(val);
            assert!(f.has(SVE));
        }
    }
}
