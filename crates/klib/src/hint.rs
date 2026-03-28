/// Branch prediction hints for hot paths.
///
/// Uses the `#[cold]` + `#[inline(never)]` trick to tell LLVM which
/// branch is expected. When LLVM sees a call to a `#[cold]` function
/// in one arm of a branch, it marks that arm as unlikely and lays out
/// the hot path as fall-through.
///
/// These are not `const fn` — LLVM branch weights are a codegen concept.
/// For `const fn` methods (which are `#[inline(always)]`), the functions
/// are small enough that the CPU branch predictor handles them; LLVM
/// layout hints add no value on 2-instruction bodies.

/// Hint that `b` is expected to be `true`.
///
/// ```ignore
/// if likely(n < len) { fast_path() } else { slow_path() }
/// ```
#[inline(always)]
pub fn likely(b: bool) -> bool {
    if !b {
        _cold();
    }
    b
}

/// Hint that `b` is expected to be `false`.
///
/// ```ignore
/// if unlikely(ptr.is_null()) { handle_null() } else { deref(ptr) }
/// ```
#[inline(always)]
pub fn unlikely(b: bool) -> bool {
    if b {
        _cold();
    }
    b
}

#[cold]
#[inline(never)]
fn _cold() {}
