#!/bin/sh
# Mutation testing wrapper for rux-kernel.
#
# cargo-mutants needs specific flag plumbing to build the kernel in its
# scratch dir: without --cargo-arg overrides it inherits the default
# target (x86_64-unknown-none) from .cargo/config.toml and fails to
# find the `test` crate, so every mutant shows up as "unviable".
#
# We override the target to the host (aarch64-apple-darwin) and flip
# the `native` feature so rux-kernel compiles as std, using the
# FlatPageTable stub + std-backed primitives.
#
# Usage:
#   tools/mutants.sh                     # run on all supported modules
#   tools/mutants.sh deadline_queue      # run on one module
#
# Output: mutation score per module, appended to tests/mutation_baseline.txt.
# Expect ~15-30 min per module — this is opt-in and NOT run from test.sh.
set -eu

cd "$(dirname "$0")/.."

HOST_TARGET="${HOST_TARGET:-aarch64-apple-darwin}"
TIMEOUT="${MUTANTS_TIMEOUT:-60}"

# Modules with enough native test coverage to produce meaningful signal.
# Each entry is: <short_name>:<source_file>
MODULES="
deadline_queue:crates/kernel/src/deadline_queue.rs
posix_timer:crates/kernel/src/posix_timer.rs
fs_ops:crates/kernel/src/syscall/fs_ops.rs
"

run_one() {
    name="$1"
    file="$2"
    # Note: "$3" (test filter) was a trap — cargo-mutants v27 drops
    # the `--` separator when trailing args are passed, which sent
    # `--test-threads=1` to `cargo test` instead of the test binary
    # and made `cargo test` exit 1 on arg parse. Every mutation was
    # then reported as "caught" (100% false positive). Use double
    # `-- --` to force cargo-mutants to preserve the separator, and
    # drop the filter (runs the whole 34-test native suite).
    printf '\n\033[1m── cargo-mutants: %s ──\033[0m\n' "$name"

    cargo mutants \
        -p rux-kernel \
        -f "$file" \
        --baseline skip \
        --timeout "$TIMEOUT" \
        --cargo-arg=--features=native \
        --cargo-arg=--target="$HOST_TARGET" \
        -- -- --test-threads=1
}

if [ $# -gt 0 ]; then
    want="$1"
    found=""
    for line in $MODULES; do
        case "$line" in
            "$want":*)
                found="$line"
                break
                ;;
        esac
    done
    if [ -z "$found" ]; then
        printf 'unknown module: %s\n' "$want" >&2
        printf 'available:\n' >&2
        for line in $MODULES; do
            printf '  %s\n' "${line%%:*}" >&2
        done
        exit 2
    fi
    run_one "${found%%:*}" "${found#*:}"
else
    for line in $MODULES; do
        run_one "${line%%:*}" "${line#*:}"
    done
fi
