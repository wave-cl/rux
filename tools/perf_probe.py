#!/usr/bin/env python3
# Userspace performance probe for the rux test harness.
#
# Measures a handful of high-signal latency metrics and prints them
# as "perf: name=VALUE unit" lines so test.sh can extract them with
# awk and feed them into tests/perf_history.csv.
#
# Metrics chosen for stability (not exhaustiveness):
#   - getpid_ns: per-call syscall overhead (hot path)
#   - openclose_ns: open+close on /etc/hostname (disk + fd allocation)
#   - forkexit_us: fork+exit+waitpid latency (context switch + MM reap)
#   - mmap4k_ns: mmap+unmap of one 4K anonymous page
#
# Each metric is measured via 5 samples, median reported — single-shot
# measurements on a noisy VM produce 30%+ variance and drown out real
# regressions. Median-of-5 cuts that roughly in half. Total probe
# runtime is still under ~1 second.
import os, time, mmap

def measure(n_iters, body):
    """Run `body()` n_iters times, return ns-per-call."""
    t0 = time.monotonic_ns()
    for _ in range(n_iters):
        body()
    t1 = time.monotonic_ns()
    return (t1 - t0) // n_iters

def median5(n_iters, body):
    samples = sorted(measure(n_iters, body) for _ in range(5))
    return samples[2]

# ── getpid: 100k × 5 samples ─────────────────────────────────────
print(f"perf: getpid_ns={median5(100_000, os.getpid)}")

# ── open+close /etc/hostname: 1k × 5 samples ─────────────────────
def _oc():
    fd = os.open("/etc/hostname", os.O_RDONLY)
    os.close(fd)
print(f"perf: openclose_ns={median5(1000, _oc)}")

# ── fork+exit+waitpid: 50 × 5 samples (expensive) ────────────────
def _fork():
    pid = os.fork()
    if pid == 0:
        os._exit(0)
    os.waitpid(pid, 0)
# forkexit is reported in microseconds because it's ~1000x slower
forkexit_ns = median5(50, _fork)
print(f"perf: forkexit_us={forkexit_ns // 1000}")

# ── mmap+munmap 4k anon: 1k × 5 samples ──────────────────────────
def _mmap():
    m = mmap.mmap(-1, 4096)
    m.close()
print(f"perf: mmap4k_ns={median5(1000, _mmap)}")

print("perf: done")
