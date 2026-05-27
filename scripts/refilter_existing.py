#!/usr/bin/env python3
"""
refilter_existing.py — Apply Phase 2B sink-presence filter to existing data/raw/.

Pre-Phase-2B samples were ingested without the sink filter, so data/raw/
contains co-changed-file noise (see docs/progress/PHASE_2B_DAY1_REPORT.md). This script
walks every meta.json, re-runs has_cwe_sink() against the code, and moves
rejects to data/raw_rejected/ with a manifest documenting the reason.

Safety:
  • Default mode is --dry-run. Nothing on disk moves until --apply is passed.
  • Hard-negative samples (is_hard_negative=True) and "safe" cwe samples are
    NOT filtered — the sink check only applies to original-CWE positives.
  • Source/CWE pairs in BLOCKED_SOURCE_CWE are unconditionally rejected
    regardless of sink presence (e.g. vudenc CWE-94 per the audit).
  • The manifest preserves enough info to undo the move if needed:
    each entry includes original .py and .meta.json paths.

Usage:
  python scripts/refilter_existing.py                # dry run, print stats
  python scripts/refilter_existing.py --apply        # actually move rejects
  python scripts/refilter_existing.py --raw-dir data/raw --rejected-dir data/raw_rejected
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# Allow running as `python scripts/refilter_existing.py` from repo root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.utils.cwe_taxonomy import BLOCKED_SOURCE_CWE
from src.utils.file_utils import has_cwe_sink
from src.utils.logger import get_logger

logger = get_logger(__name__)


def classify(meta: dict, code: str) -> tuple[bool, str | None]:
    """
    Return (keep, reason_if_rejected). Rules:
      1. Hard negatives are always kept (their label is "safe", not the original CWE).
      2. cwe="safe" samples are always kept (no sink applicable).
      3. (source, cwe) in BLOCKED_SOURCE_CWE → reject with reason="blocked_source".
      4. has_cwe_sink returns False → reject with reason="sink_absent".
      5. Otherwise keep.
    """
    if meta.get("is_hard_negative"):
        return True, None

    cwe = meta.get("cwe")
    if cwe == "safe" or not cwe:
        return True, None

    source = meta.get("source", "unknown")
    if (source, cwe) in BLOCKED_SOURCE_CWE:
        return False, "blocked_source"

    sink_ok, _ = has_cwe_sink(code, cwe, file_path=meta.get("file_path"))
    if not sink_ok:
        return False, "sink_absent"

    return True, None


def main() -> int:
    parser = argparse.ArgumentParser(description="Refilter existing data/raw/ with the Phase 2B sink filter")
    parser.add_argument("--raw-dir",      default="data/raw")
    parser.add_argument("--rejected-dir", default="data/raw_rejected")
    parser.add_argument("--apply",        action="store_true", help="Actually move files (default: dry run)")
    parser.add_argument("--manifest",     default=None,        help="Output manifest path (default: <rejected_dir>/manifest_<timestamp>.json)")
    args = parser.parse_args()

    raw = Path(args.raw_dir)
    rejected = Path(args.rejected_dir)

    if not raw.exists():
        logger.error(f"raw-dir does not exist: {raw}")
        return 1

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    manifest_path = Path(args.manifest) if args.manifest else rejected / f"manifest_{timestamp}.json"

    # ---------- pass 1: classify -----------------------------------------
    meta_files = sorted(raw.glob("*.meta.json"))
    logger.info(f"Found {len(meta_files)} meta files in {raw}")

    kept_by_cwe:     dict[str, int] = defaultdict(int)
    kept_by_source:  dict[str, int] = defaultdict(int)
    rej_by_cwe:      dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))  # cwe → reason → count
    rej_by_source:   dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))  # source → reason → count
    rejected_entries: list[dict] = []

    for meta_path in meta_files:
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning(f"  unparseable meta: {meta_path.name} ({e}) — skipping")
            continue

        py_path = meta_path.with_suffix("").with_suffix(".py")
        if not py_path.exists():
            code = meta.get("code_before", "") or ""
        else:
            try:
                code = py_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                code = meta.get("code_before", "") or ""

        cwe    = meta.get("cwe") or "unknown"
        source = meta.get("source") or "unknown"
        keep, reason = classify(meta, code)

        if keep:
            kept_by_cwe[cwe] += 1
            kept_by_source[source] += 1
        else:
            rej_by_cwe[cwe][reason] += 1
            rej_by_source[source][reason] += 1
            rejected_entries.append({
                "id":         meta.get("id"),
                "cwe":        cwe,
                "source":     source,
                "cve_id":     meta.get("cve_id"),
                "file_path":  meta.get("file_path"),
                "meta_path":  str(meta_path),
                "py_path":    str(py_path),
                "reason":     reason,
            })

    # ---------- report ----------------------------------------------------
    total       = sum(kept_by_cwe.values()) + sum(c for d in rej_by_cwe.values() for c in d.values())
    total_kept  = sum(kept_by_cwe.values())
    total_rej   = sum(c for d in rej_by_cwe.values() for c in d.values())
    pct_rej     = (100 * total_rej / total) if total else 0.0

    print()
    print(f"=== Phase 2B refilter — {'APPLY' if args.apply else 'DRY RUN'} ===")
    print(f"raw-dir: {raw}")
    print(f"Total meta files: {total}")
    print(f"Kept:     {total_kept:5}  ({100 - pct_rej:.1f}%)")
    print(f"Rejected: {total_rej:5}  ({pct_rej:.1f}%)")
    print()
    print(f"{'CWE':<10} {'kept':>6} {'sink_absent':>13} {'blocked_source':>15} {'total':>7} {'reject%':>9}")
    print("-" * 65)
    all_cwes = sorted(set(kept_by_cwe.keys()) | set(rej_by_cwe.keys()))
    for cwe in all_cwes:
        k = kept_by_cwe.get(cwe, 0)
        r_sink    = rej_by_cwe.get(cwe, {}).get("sink_absent",    0)
        r_blocked = rej_by_cwe.get(cwe, {}).get("blocked_source", 0)
        tot = k + r_sink + r_blocked
        pct = (100 * (r_sink + r_blocked) / tot) if tot else 0.0
        print(f"{cwe:<10} {k:>6} {r_sink:>13} {r_blocked:>15} {tot:>7} {pct:>8.0f}%")

    print()
    print(f"{'Source':<16} {'kept':>6} {'sink_absent':>13} {'blocked_source':>15} {'total':>7} {'reject%':>9}")
    print("-" * 75)
    all_sources = sorted(set(kept_by_source.keys()) | set(rej_by_source.keys()))
    for source in all_sources:
        k = kept_by_source.get(source, 0)
        r_sink    = rej_by_source.get(source, {}).get("sink_absent",    0)
        r_blocked = rej_by_source.get(source, {}).get("blocked_source", 0)
        tot = k + r_sink + r_blocked
        pct = (100 * (r_sink + r_blocked) / tot) if tot else 0.0
        print(f"{source:<16} {k:>6} {r_sink:>13} {r_blocked:>15} {tot:>7} {pct:>8.0f}%")

    # ---------- pass 2: move files (if --apply) --------------------------
    if not args.apply:
        print()
        print(f"DRY RUN — nothing moved. To apply, re-run with --apply.")
        print(f"Would write manifest to: {manifest_path}")
        return 0

    rejected.mkdir(parents=True, exist_ok=True)
    moved_meta = 0
    moved_py   = 0
    move_errors = 0

    for entry in rejected_entries:
        for kind, src_str in [("meta", entry["meta_path"]), ("py", entry["py_path"])]:
            src = Path(src_str)
            if not src.exists():
                continue
            dst = rejected / src.name
            try:
                shutil.move(str(src), str(dst))
                if kind == "meta":
                    moved_meta += 1
                else:
                    moved_py += 1
            except Exception as e:
                logger.warning(f"  move failed: {src} → {dst} ({e})")
                move_errors += 1

    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps({
        "schema": "phase2b_refilter_manifest_v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "raw_dir": str(raw),
        "rejected_dir": str(rejected),
        "counts": {
            "total":  total,
            "kept":   total_kept,
            "rejected": total_rej,
        },
        "rejected_by_cwe":    {cwe: dict(reasons) for cwe, reasons in rej_by_cwe.items()},
        "rejected_by_source": {src: dict(reasons) for src, reasons in rej_by_source.items()},
        "rejected_entries":   rejected_entries,
    }, indent=2))

    print()
    print(f"Applied. Moved {moved_meta} .meta.json + {moved_py} .py files → {rejected}")
    if move_errors:
        print(f"WARN: {move_errors} move errors (see logs above)")
    print(f"Manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
