#!/usr/bin/env python3
"""
export_dataset.py — emit the benchmark as a CWE-foldered before/after/json tree.

Layout produced::

    dataset/
      CWE-22/
        cve-2020-15239_1_before.py
        cve-2020-15239_1_after.py
        cve-2020-15239_1.json
        ...
      CWE-78/
        ...

Only positives that carry BOTH a ``code_before`` and a ``code_after`` are
exported, because the before/after/json triple requires a fix pair. The
vudenc and hand-curated canonical positives have no paired ``code_after``
and are therefore not part of this export (they remain in ``data/raw``).

Per-sample JSON fields (exactly the requested set):
  cve_id, cwe, cvss_severity, code_before, sink_lines, changed_lines,
  vulnerable_snippet, code_after.

Usage:
  python scripts/export_dataset.py            # write dataset/
  python scripts/export_dataset.py --out DIR  # custom output dir
"""

from __future__ import annotations

import argparse
import difflib
import glob
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.file_utils import (  # noqa: E402
    SINK_PATTERNS,
    _strip_comments_for_match,
    sink_was_modified,
)


def _slug(meta: dict) -> str:
    """Stable, filesystem-safe stem for a sample, preferring the CVE id."""
    cve = meta.get("cve_id")
    if cve:
        return cve.lower()
    ghsa = meta.get("ghsa_id")
    if ghsa:
        return ghsa.lower()
    return "nocve-" + (meta.get("content_hash") or meta.get("id", "unknown"))[:16]


def _sink_lines(code: str, cwe: str) -> list[dict]:
    """Return [{line, text}] for every line that matches a CWE sink pattern."""
    patterns = SINK_PATTERNS.get(cwe) or []
    if not patterns:
        return []
    stripped = _strip_comments_for_match(code)
    out: list[dict] = []
    for i, ln in enumerate(stripped.splitlines(), start=1):
        if not ln.strip():
            continue
        if any(p.search(ln) for p in patterns):
            out.append({"line": i, "text": ln.strip()})
    return out


def _changed_lines(before: str, after: str) -> list[dict]:
    """Line-level diff: lines removed from `before` / added in `after`."""
    b = before.splitlines()
    a = after.splitlines()
    out: list[dict] = []
    for d in difflib.unified_diff(b, a, lineterm="", n=0):
        if d.startswith(("---", "+++", "@@")):
            continue
        if d.startswith("-"):
            out.append({"op": "removed", "text": d[1:].strip()})
        elif d.startswith("+"):
            out.append({"op": "added", "text": d[1:].strip()})
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw-dir", default="data/raw")
    ap.add_argument("--out", default="dataset")
    ap.add_argument("--eval-only", action="store_true",
                    help="Restrict to the sample_ids the eval actually scored "
                         "(the clean-variant rows in reports/eval/*_predictions.jsonl).")
    args = ap.parse_args()

    eval_ids: set[str] | None = None
    if args.eval_only:
        eval_ids = set()
        for pf in glob.glob("reports/eval/*_predictions.jsonl"):
            for line in Path(pf).read_text(encoding="utf-8").splitlines():
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                if r.get("variant") == "clean":
                    eval_ids.add(r["sample_id"])
        print(f"--eval-only: restricting to {len(eval_ids)} scored sample_ids")

    out_root = Path(args.out)
    out_root.mkdir(parents=True, exist_ok=True)

    # group by (cwe, slug) so multiple files under one CVE get _1, _2 ...
    grouped: dict[tuple[str, str], list[tuple[dict, str, str]]] = defaultdict(list)
    skipped_no_after = skipped_no_before = 0

    for meta_path in sorted(glob.glob(f"{args.raw_dir}/*.meta.json")):
        m = json.loads(Path(meta_path).read_text(encoding="utf-8"))
        if eval_ids is not None and m.get("id") not in eval_ids:
            continue
        cwe = m.get("cwe")
        if not cwe or cwe == "safe":
            continue
        code_after = (m.get("code_after") or "").strip()
        if not code_after:
            skipped_no_after += 1
            continue
        py = Path(meta_path[: -len(".meta.json")] + ".py")
        code_before = (
            py.read_text(encoding="utf-8", errors="ignore")
            if py.exists()
            else (m.get("code_before") or "")
        )
        if not code_before.strip():
            skipped_no_before += 1
            continue
        grouped[(cwe, _slug(m))].append((m, code_before, m.get("code_after")))

    written = 0
    per_cwe: dict[str, int] = defaultdict(int)
    for (cwe, slug), items in sorted(grouped.items()):
        cwe_dir = out_root / cwe
        cwe_dir.mkdir(parents=True, exist_ok=True)
        for idx, (m, code_before, code_after) in enumerate(items, start=1):
            stem = f"{slug}_{idx}"
            (cwe_dir / f"{stem}_before.py").write_text(code_before, encoding="utf-8")
            (cwe_dir / f"{stem}_after.py").write_text(code_after, encoding="utf-8")
            modified, evidence = sink_was_modified(code_before, code_after, cwe)
            before_sinks = {s["text"] for s in _sink_lines(code_before, cwe)}
            after_sinks = {s["text"] for s in _sink_lines(code_after, cwe)}
            vulnerable_snippet = sorted(before_sinks - after_sinks)
            record = {
                "cve_id": m.get("cve_id"),
                "cwe": cwe,
                "cvss_severity": m.get("cvss_severity"),
                "code_before": code_before,
                "sink_lines": _sink_lines(code_before, cwe),
                "changed_lines": _changed_lines(code_before, code_after),
                "vulnerable_snippet": vulnerable_snippet,
                "code_after": code_after,
            }
            (cwe_dir / f"{stem}.json").write_text(
                json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            written += 1
            per_cwe[cwe] += 1

    print(f"Exported {written} samples to {out_root}/")
    for cwe in sorted(per_cwe):
        print(f"  {cwe:<10} {per_cwe[cwe]}")
    print(f"Skipped: {skipped_no_after} no-code_after, {skipped_no_before} no-code_before")
    return 0


if __name__ == "__main__":
    sys.exit(main())
