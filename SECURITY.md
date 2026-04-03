# rux Kernel Security Model

rux is written in Rust, which provides compile-time memory safety guarantees
that eliminate entire classes of vulnerabilities. This changes the security
posture compared to C kernels (Linux, XNU): many traditional mitigations are
unnecessary because Rust prevents the underlying bugs.

## Implemented: Hardware & Policy Mitigations

These features protect against hardware-level attacks or enforce policy
that no programming language can provide.

### CPU Memory Protection
| Feature | x86_64 | aarch64 | Purpose |
|---------|--------|---------|---------|
| SMEP | CR4.20 | N/A | Prevent kernel executing user code |
| SMAP | CR4.21 + stac/clac | PAN (MSR PAN) | Prevent kernel accessing user memory |
| UMIP | CR4.11 | N/A | Block SGDT/SIDT info leaks from userspace |
| NX/XN | PTE bit 63 | UXN/PXN | No-execute enforcement per page |
| CR0.WP | CR0.16 | SCTLR | Enforce read-only pages in kernel mode |

### Spectre Mitigations
| Feature | Purpose |
|---------|---------|
| IBRS | Indirect Branch Restricted Speculation |
| STIBP | Single Thread Indirect Branch Predictor isolation |
| IBPB | Indirect Branch Prediction Barrier on context switch |

### Memory Hardening
| Feature | Detail |
|---------|--------|
| W^X enforcement | .text = RX, .rodata = R, .data = RW (enforced by CR0.WP) |
| Null pointer guard | Page 0 unmapped in kernel page table |
| Stack guard pages | 4KB unmapped page at bottom of each 32KB kernel stack |
| FPU state isolation | FXSAVE64/FXRSTOR64 (x86) or STP/LDP Q regs (aarch64) on every context switch |
| PCID/ASID | TLB tagged per-process to prevent cross-process leaks |
| User ASLR | mmap_base (0-16MB entropy), stack (0-28KB entropy), interpreter base (0-1MB entropy) per exec |
| Retpoline | Compiler-level Spectre v2 mitigation via `+retpoline` target feature (x86_64 only) |

### Process Isolation
| Feature | Detail |
|---------|--------|
| Per-process page tables | Each process has isolated user address space |
| COW fork | Copy-on-write with frame refcounting |
| Syscall filtering | Per-process syscall bitmask (infrastructure ready) |

## Not Implemented: Rust Provides Equivalent Protection

These features exist in C kernels (Linux, XNU) to catch memory corruption
bugs that Rust prevents at compile time. They add runtime overhead with
no security benefit in a Rust kernel.

| Feature | Why not needed in Rust |
|---------|----------------------|
| Stack canaries (`-fstack-protector`) | Rust prevents buffer overflows at compile time. No `strcpy`/`sprintf` to overflow. |
| KASAN (Kernel Address Sanitizer) | Rust prevents use-after-free, double-free, and out-of-bounds access. |
| ASAN (Address Sanitizer) | Same as KASAN — Rust's ownership model prevents these at compile time. |
| CFI/CFG (Control Flow Integrity) | Rust function pointers are type-safe. Indirect calls go through vtables with known types. |
| MTE (Memory Tagging Extension) | Rust prevents the use-after-free and buffer overflow bugs that MTE detects. |
| CET / Shadow Stacks | Rust prevents return address corruption (no buffer overflows to overwrite the stack). |
| Format string protection | Rust has no printf/varargs. `format!()` is type-checked at compile time. |
| Return-oriented programming (ROP) defenses | Without memory corruption bugs, attackers can't redirect control flow to gadgets. |

## Not Implemented: Deferred (High Effort, Lower Priority)

These features provide defense-in-depth but require significant implementation
effort. They are less critical for a Rust kernel because the attack surface
they protect against (memory corruption) is largely eliminated by the language.

| Feature | Reason Deferred |
|---------|----------------|
| SMAP/PAN CR4 enforcement on QEMU TCG | SMAP (x86_64) and PAN (aarch64) guards (stac/clac, MSR PAN) are implemented and all kernel→user memory access paths are wrapped. However, CR4.SMAP is only enabled on KVM/real hardware — QEMU TCG's stac/clac interaction with SMAP is unreliable from syscall paths. SMAP_ACTIVE volatile guard + full audit in place; enforcement deferred until KVM testing. |
| KPTI (Kernel Page Table Isolation) | Mitigates Meltdown (speculative kernel memory reads from userspace). High implementation effort: requires separate user/kernel page tables and CR3 swap on every syscall. Design approach: trampoline page mapped in both kernel and user page tables to handle the CR3 switch during syscall entry/exit. The Rust kernel's minimal `unsafe` surface makes exploitation significantly harder even without KPTI. |
| Read-only page tables | Prevents page table corruption from kernel bugs. Rust's type system prevents most wild writes; the remaining `unsafe` page table code is small and auditable. |

## The `unsafe` Surface

The kernel's `unsafe` code is concentrated in:
- **Architecture-specific assembly** (syscall entry/exit, context switch, interrupt handlers)
- **Page table manipulation** (raw pointer walks through identity-mapped physical memory)
- **Per-CPU data access** (GS-base / TPIDR_EL1 register reads)
- **MMIO device access** (UART, APIC, GIC registers)

All `unsafe` blocks are in `crates/kernel/src/arch/` or `crates/mm/src/`. Generic kernel
code (syscall dispatch, VFS, pipe, signal handling) is safe Rust.
