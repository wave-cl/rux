#!/bin/sh
# Regenerate tests/golden/syscall_conf_linux.txt by running the
# conformance script on a real Linux kernel via Docker. Commit the
# result. Run this any time tools/syscall_conf.py changes.
#
# Requires: Docker (started). If Docker isn't running, start it with
#   open -g -a Docker
# and wait ~10s before re-running.
set -e
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"
mkdir -p tests/golden
docker run --rm -v "$REPO_ROOT/tools:/t" python:3.12-slim python3 /t/syscall_conf.py \
    > tests/golden/syscall_conf_linux.txt
echo "Captured golden:"
tail -1 tests/golden/syscall_conf_linux.txt
echo "Lines: $(wc -l < tests/golden/syscall_conf_linux.txt)"
