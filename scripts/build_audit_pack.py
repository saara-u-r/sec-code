#!/usr/bin/env python3
"""
build_audit_pack.py — generate a Stage-1 sample-quality audit pack.

For each active CWE, samples N random meta.json files (or audits ALL
when the class is rare), pulls the code region around the sink match,
and emits a structured markdown document with a verdict slot per sample.

The intent is to surface label noise — samples tagged with one CWE that
are actually a different CWE, or that fail the smell-test as
representatives of the labeled vulnerability — without forcing a
full-file read for every sample. The sink-match excerpt is usually
enough to make the call.

Output schema (per sample):
  ### #N — {id} ({source}, {cve_id or '-'})
  - **Repo:** ...
  - **File:** ...
  - **Sink matched:** {regex pattern from meta}
  - **Match position:** line {n}
  **Code excerpt around match:**
      ... (~10 lines of code around the matched line)
  **Verdict:** [PASS/FAIL]
  **Reason if FAIL:**

Usage:
  python scripts/build_audit_pack.py                          # default settings
  python scripts/build_audit_pack.py --per-cwe 20             # 20 per CWE
  python scripts/build_audit_pack.py --output AUDIT.md        # custom output
  python scripts/build_audit_pack.py --seed 7                 # different sample
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.cwe_taxonomy import (  # noqa: E402
    CWE_NAMES, SINK_PATTERNS, TARGET_CWES,
)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def load_active_samples(raw_dir: Path) -> dict[str, list[dict]]:
    """Group sample meta.json + source code by CWE. Skip samples whose CWE is
    no longer active (the audit only matters for in-scope classes)."""
    by_cwe: dict[str, list[dict]] = defaultdict(list)
    for meta_path in sorted(raw_dir.glob("*.meta.json")):
        try:
            m = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        cwe = m.get("cwe")
        if cwe not in TARGET_CWES and cwe != "safe":
            continue
        py_path = meta_path.with_suffix("").with_suffix(".py")
        code = ""
        if py_path.exists():
            try:
                code = py_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                pass
        by_cwe[cwe].append({"meta": m, "code": code, "py_path": str(py_path)})
    return by_cwe


# ---------------------------------------------------------------------------
# Sink-match localization
# ---------------------------------------------------------------------------

def locate_sink(code: str, cwe: str, recorded_pattern: str | None) -> tuple[int, str] | None:
    """Return (line_no_1indexed, pattern_str) for the first sink match, or None.

    Tries the recorded pattern first (the one that originally matched at
    scrape time) for highest fidelity, then falls back to scanning all
    SINK_PATTERNS for the CWE. The "safe" hard-negatives don't have sink
    patterns and return None — for those we excerpt the file start instead.
    """
    candidates: list[re.Pattern] = []
    if recorded_pattern:
        try:
            candidates.append(re.compile(recorded_pattern, re.IGNORECASE | re.DOTALL))
        except re.error:
            pass
    candidates.extend(SINK_PATTERNS.get(cwe, []))

    for pat in candidates:
        m = pat.search(code)
        if m:
            line_no = code.count("\n", 0, m.start()) + 1
            return line_no, pat.pattern
    return None


def excerpt(code: str, line_no: int, window: int = 8) -> str:
    lines = code.splitlines()
    start = max(0, line_no - window - 1)
    end = min(len(lines), line_no + window)
    out = []
    for i, ln in enumerate(lines[start:end], start=start + 1):
        marker = "→" if i == line_no else " "
        out.append(f"{i:5d} {marker} {ln}")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Sampling
# ---------------------------------------------------------------------------

def sample_for_audit(
    by_cwe: dict[str, list[dict]],
    per_cwe: int,
    audit_all_below: int,
    seed: int,
    skip_canonical: bool,
    skip_safe: bool,
) -> dict[str, list[dict]]:
    rng = random.Random(seed)
    sampled: dict[str, list[dict]] = {}
    for cwe, samples in by_cwe.items():
        if cwe == "safe" and skip_safe:
            continue
        pool = samples
        if skip_canonical:
            pool = [s for s in pool if s["meta"].get("source") != "canonical"]
        if not pool:
            continue
        n = len(pool) if len(pool) <= audit_all_below else per_cwe
        sampled[cwe] = rng.sample(pool, min(n, len(pool)))
    return sampled


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render_sample_block(idx: int, entry: dict) -> str:
    m = entry["meta"]
    code = entry["code"]
    cwe = m.get("cwe", "?")
    recorded_sink = m.get("sink_pattern")
    loc = locate_sink(code, cwe, recorded_sink) if code else None

    if loc:
        line_no, pat = loc
        snippet = excerpt(code, line_no, window=8)
        sink_repr = pat
        match_pos = f"line {line_no}"
    else:
        snippet = "\n".join(f"{i+1:5d}   {ln}" for i, ln in enumerate(code.splitlines()[:20]))
        sink_repr = recorded_sink or "(none)"
        match_pos = "(no sink re-matched at audit time — pattern may have evolved)"

    parts = [
        f"### #{idx} — `{m.get('id')}` ({m.get('source','?')}, {m.get('cve_id') or '—'})",
        "",
        f"- **Repo:** {m.get('repo') or '—'}",
        f"- **File path:** `{m.get('file_path') or '—'}`",
        f"- **Framework:** {m.get('framework') or '—'}",
        f"- **Sink pattern recorded:** `{sink_repr}`",
        f"- **Sink match position:** {match_pos}",
        f"- **label_source / confidence:** {m.get('label_source') or '—'} / "
        f"{m.get('label_confidence') or '—'}",
        "",
        "**Code excerpt:**",
        "",
        "```python",
        snippet,
        "```",
        "",
        "**Verdict:** [ PASS / FAIL ]",
        "",
        "**If FAIL, the actual CWE (or reason):**",
        "",
        "---",
        "",
    ]
    return "\n".join(parts)


def render_pack(sampled: dict[str, list[dict]], by_cwe: dict[str, list[dict]], args) -> str:
    out: list[str] = [
        f"# Stage-1 Sample Audit Pack — {args.timestamp}",
        "",
        "Per-CWE spot-check of label correctness. For each sample below, read",
        "the code excerpt and decide:",
        "",
        "- **PASS** — the labeled CWE matches what the code actually does",
        "- **FAIL** — the code does not exhibit the labeled CWE (note the actual CWE",
        "  or the reason: e.g. \"sink call but no taint flow\", \"test fixture\",",
        "  \"unrelated co-changed file\", etc.)",
        "",
        f"Sampled with seed={args.seed}. Per-CWE sampling: {args.per_cwe} for",
        f"populous classes, ALL for classes with ≤{args.audit_all_below} samples.",
        "",
        "Canonical samples are excluded from the audit (they are hand-curated",
        "textbook positives by construction).",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| CWE | Active | Sampled | Audit FP rate (filled after audit) |",
        "|---|---:|---:|---|",
    ]

    for cwe in sorted(by_cwe):
        n_active = sum(1 for s in by_cwe[cwe] if s["meta"].get("source") != "canonical") \
            if args.skip_canonical else len(by_cwe[cwe])
        n_sampled = len(sampled.get(cwe, []))
        out.append(f"| {cwe} ({CWE_NAMES.get(cwe, cwe)}) | {n_active} | {n_sampled} | __/__ |")

    out.append("")
    out.append("---")
    out.append("")

    # Per-CWE sections
    for cwe in sorted(sampled.keys()):
        out.append(f"## {cwe} — {CWE_NAMES.get(cwe, cwe)}")
        out.append("")
        out.append(f"Sampled: **{len(sampled[cwe])}** / {len(by_cwe[cwe])} on disk.")
        out.append("")
        for i, entry in enumerate(sampled[cwe], start=1):
            out.append(render_sample_block(i, entry))

    return "\n".join(out)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    from datetime import datetime, timezone
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-dir", default="data/raw")
    parser.add_argument("--output", default="BENCHMARK_AUDIT_SAMPLES_2026-05-13.md")
    parser.add_argument("--per-cwe", type=int, default=10,
                        help="Samples per CWE for populous classes (default: 10)")
    parser.add_argument("--audit-all-below", type=int, default=30,
                        help="Audit every sample for classes with ≤ this many on disk (default: 30)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--include-canonical", action="store_true",
                        help="Include hand-curated canonical samples in the audit "
                             "(default: skip them — they are positives by construction)")
    parser.add_argument("--include-safe", action="store_true",
                        help="Audit the 'safe' hard-negative class too (default: skip)")
    args = parser.parse_args()
    args.skip_canonical = not args.include_canonical
    args.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    raw = Path(args.raw_dir)
    by_cwe = load_active_samples(raw)
    sampled = sample_for_audit(
        by_cwe,
        per_cwe=args.per_cwe,
        audit_all_below=args.audit_all_below,
        seed=args.seed,
        skip_canonical=args.skip_canonical,
        skip_safe=not args.include_safe,
    )

    print(f"{'CWE':<10} {'on-disk':>8} {'sampled':>8}")
    for cwe in sorted(by_cwe):
        print(f"{cwe:<10} {len(by_cwe[cwe]):>8} {len(sampled.get(cwe, [])):>8}")
    total = sum(len(v) for v in sampled.values())
    print(f"\nTotal samples in audit pack: {total}")

    text = render_pack(sampled, by_cwe, args)
    Path(args.output).write_text(text, encoding="utf-8")
    print(f"Wrote {args.output} ({len(text)} chars)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
