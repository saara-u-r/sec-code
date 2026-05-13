#!/usr/bin/env python3
"""
refilter_by_diff.py — drop samples where the sink line is unchanged
between code_before and code_after.

Motivation: Stage-1 audit (BENCHMARK_AUDIT_REPORT_2026-05-13.md) found
that ~50% of CVE-fix-derived positives are commit-level noise — the
labeled file was touched in the fix commit, but the *actual* sink line
(`pickle.loads(...)`, `os.system(...)`, etc.) is identical in
code_before and code_after. Those files are co-changed noise, not the
real vulnerability site.

This filter operationalizes the "alphabet closes at a sink" framework:
if the sink wasn't changed by the fix, it isn't the vulnerable line.

What this script does:
  * Iterates every sample with cwe != "safe" and source != "canonical"
    (hard negatives don't have a fix; canonical samples are hand-curated
    positives without a paired safe version).
  * Loads code_before from the .py file and code_after from meta.json.
  * Calls file_utils.sink_was_modified(code_before, code_after, cwe).
  * If modified=False (sink unchanged), move to data/raw_rejected/.
  * If modified=None (no code_after available), keeps the sample by
    default — unless --strict is passed.

Outputs a manifest at data/raw_rejected/manifest_diff_filter_*.json with
per-sample audit evidence (which sink line was removed/changed).

Usage:
  python scripts/refilter_by_diff.py                # dry run, print stats
  python scripts/refilter_by_diff.py --apply        # move rejects
  python scripts/refilter_by_diff.py --apply --strict   # also drop no-code_after
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.file_utils import sink_was_modified  # noqa: E402
from src.utils.logger import get_logger  # noqa: E402

logger = get_logger("refilter_by_diff")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-dir", default="data/raw")
    parser.add_argument("--rejected-dir", default="data/raw_rejected")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--strict", action="store_true",
                        help="Also drop samples where code_after is missing "
                             "(modified=None). Default keeps them.")
    args = parser.parse_args()

    raw = Path(args.raw_dir)
    rejected = Path(args.rejected_dir)

    keep, drop_unchanged, no_data, total = Counter(), Counter(), Counter(), Counter()
    drop_entries: list[dict] = []
    no_data_entries: list[dict] = []

    for meta_path in sorted(raw.glob("*.meta.json")):
        try:
            m = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        cwe = m.get("cwe")
        source = m.get("source") or ""
        if not cwe or cwe == "safe":
            continue
        # Skip canonical samples — they have no fix-commit pair by design
        if source == "canonical":
            continue
        # Skip hard-negatives (cwe != safe but is_hard_negative=True)
        if m.get("is_hard_negative"):
            continue

        py_path = meta_path.with_suffix("").with_suffix(".py")
        if py_path.exists():
            code_before = py_path.read_text(encoding="utf-8", errors="ignore")
        else:
            code_before = m.get("code_before") or ""
        code_after = m.get("code_after") or ""

        total[cwe] += 1
        modified, evidence = sink_was_modified(code_before, code_after, cwe)

        if modified is True:
            keep[cwe] += 1
        elif modified is False:
            drop_unchanged[cwe] += 1
            drop_entries.append({
                "id": m.get("id"),
                "cwe": cwe,
                "source": m.get("source"),
                "repo": m.get("repo"),
                "file_path": m.get("file_path"),
                "meta_path": str(meta_path),
                "py_path": str(py_path),
                "reason": "sink_line_unchanged_between_before_and_after",
            })
        else:
            no_data[cwe] += 1
            no_data_entries.append({
                "id": m.get("id"),
                "cwe": cwe,
                "source": m.get("source"),
                "meta_path": str(meta_path),
                "py_path": str(py_path),
                "reason": "no_code_after_available",
            })

    # Print summary
    print("\n=== Diff filter report — DRY RUN ===" if not args.apply else
          "\n=== Diff filter report — APPLIED ===")
    print(f"{'CWE':<10} {'total':>6} {'keep':>6} {'drop':>6} {'no_diff':>8} {'kept_%':>8}")
    print("-" * 56)
    grand_total = grand_keep = grand_drop = grand_no = 0
    for cwe in sorted(total):
        t, k, d, nd = total[cwe], keep[cwe], drop_unchanged[cwe], no_data[cwe]
        # If --strict, no-data are dropped too
        effective_keep = k if args.strict else k + nd
        pct = (effective_keep / t * 100) if t else 0
        print(f"{cwe:<10} {t:>6} {k:>6} {d:>6} {nd:>8} {pct:>7.1f}%")
        grand_total += t
        grand_keep += k
        grand_drop += d
        grand_no += nd

    print("-" * 56)
    print(f"{'TOTAL':<10} {grand_total:>6} {grand_keep:>6} {grand_drop:>6} {grand_no:>8}")
    print(f"\nWould drop: {grand_drop} sample pairs"
          + (f" + {grand_no} no-code_after (strict)" if args.strict else ""))

    if not args.apply:
        print("\nDRY RUN — nothing moved. Re-run with --apply.")
        return 0

    rejected.mkdir(parents=True, exist_ok=True)
    moved = 0
    final_drop = list(drop_entries)
    if args.strict:
        final_drop.extend(no_data_entries)
    for entry in final_drop:
        for src_str in (entry["meta_path"], entry["py_path"]):
            src = Path(src_str)
            if src.exists():
                shutil.move(str(src), str(rejected / src.name))
                moved += 1

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    manifest_path = rejected / f"manifest_diff_filter_{ts}.json"
    manifest_path.write_text(json.dumps({
        "schema": "phase2b_diff_filter_manifest_v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "strict_mode": args.strict,
        "reason": (
            "Diff-based filter: a sample passes only if at least one sink "
            "line in code_before is absent from code_after (i.e., the fix "
            "actually modified the sink). Samples with unchanged sink lines "
            "are co-changed file noise — the CVE fixed something else."
        ),
        "moved_pairs": len(final_drop),
        "rejected_entries": final_drop,
    }, indent=2))

    print(f"\nMoved {moved} files ({len(final_drop)} pairs) to {rejected}/")
    print(f"Manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
