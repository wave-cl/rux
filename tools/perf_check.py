#!/usr/bin/env python3
# Append a new row to tests/perf_history.csv from perf: lines captured
# by test.sh, then compare against the previous row and exit non-zero
# if any metric regressed by more than REGRESSION_PCT.
#
# Usage:
#   tools/perf_check.py <arch> <perf-dump-file>
#
# The perf-dump-file contains `perf: name=value` lines (possibly
# interleaved with other output). Unknown lines are ignored. If no
# metrics are found, the run is skipped without error.
#
# CSV columns are auto-detected from the first row; new metrics are
# appended to the right as they're introduced. Missing metrics in
# older rows show as empty cells.
import sys, os, csv, subprocess, datetime, re

REGRESSION_PCT = 50  # alert threshold (noisy VMs need generous slack — catches ~2x regressions)
HISTORY_PATH = "tests/perf_history.csv"

def parse_perf_dump(path):
    """Extract {metric_name: int_value} from a file of 'perf: key=value' lines."""
    out = {}
    pat = re.compile(r"^perf:\s+([a-z_0-9]+)=(\d+)\s*$")
    try:
        with open(path) as f:
            for line in f:
                m = pat.match(line.strip())
                if m:
                    out[m.group(1)] = int(m.group(2))
    except FileNotFoundError:
        pass
    return out

def git_commit_short():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], text=True
        ).strip()
    except Exception:
        return "unknown"

def read_csv(path):
    if not os.path.exists(path):
        return [], []
    with open(path) as f:
        rdr = csv.reader(f)
        rows = list(rdr)
    if not rows:
        return [], []
    return rows[0], rows[1:]

def write_csv(path, header, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)

def main():
    if len(sys.argv) != 3:
        print("usage: perf_check.py <arch> <perf-dump-file>", file=sys.stderr)
        sys.exit(2)
    arch = sys.argv[1]
    metrics = parse_perf_dump(sys.argv[2])
    if not metrics:
        print(f"perf_check ({arch}): no metrics captured, skipping")
        return
    commit = git_commit_short()
    date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    header, rows = read_csv(HISTORY_PATH)
    fixed_cols = ["commit", "date", "arch"]
    metric_cols = sorted(set(header[len(fixed_cols):]) | set(metrics.keys())) \
        if header else sorted(metrics.keys())
    new_header = fixed_cols + metric_cols

    # If columns changed, rewrite old rows to match the new header layout.
    if header != new_header and rows:
        old_metric_cols = header[len(fixed_cols):] if header else []
        rewritten = []
        for row in rows:
            row_dict = dict(zip(old_metric_cols, row[len(fixed_cols):]))
            new_row = row[:len(fixed_cols)] + [
                row_dict.get(c, "") for c in metric_cols
            ]
            rewritten.append(new_row)
        rows = rewritten

    # Find the most recent row for this arch (to compare against).
    prev = None
    for row in reversed(rows):
        if len(row) > 2 and row[2] == arch:
            prev = dict(zip(metric_cols, row[len(fixed_cols):]))
            break

    # Append our new row.
    new_row = [commit, date, arch] + [str(metrics.get(c, "")) for c in metric_cols]
    rows.append(new_row)
    write_csv(HISTORY_PATH, new_header, rows)

    # Print current values and compare against previous.
    print(f"perf ({arch}):", ", ".join(f"{k}={v}" for k, v in sorted(metrics.items())))
    if prev is None:
        print(f"  (no prior {arch} baseline — committing this as the starting point)")
        return
    regressions = []
    for k, v in sorted(metrics.items()):
        prev_s = prev.get(k, "")
        if not prev_s:
            continue
        try:
            pv = int(prev_s)
        except ValueError:
            continue
        if pv <= 0:
            continue
        delta_pct = 100.0 * (v - pv) / pv
        if delta_pct > REGRESSION_PCT:
            regressions.append((k, pv, v, delta_pct))
        elif delta_pct < -10:  # improvement worth noting
            print(f"  [improved] {k}: {pv} -> {v} ({delta_pct:+.1f}%)")
    if regressions:
        print(f"  REGRESSION (>{REGRESSION_PCT}% slower vs prior {arch}):")
        for k, pv, v, d in regressions:
            print(f"    {k}: {pv} -> {v} ({d:+.1f}%)")
        sys.exit(1)

if __name__ == "__main__":
    main()
