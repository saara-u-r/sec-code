#!/usr/bin/env python3
"""
rollback_weak_random.py — one-shot rollback of the 2026-05-11 weak_random_miner output.

Moves every data/raw/weak_random_*.{py,meta.json} to data/raw_rejected/ and
writes a manifest documenting the rollback. Triggered by the CWE-330 audit
in PHASE_2B_OPEN_QUESTIONS.md: the original miner run used a file-wide
security-context check which produced ~60-80% false positives. After the
2026-05-12 fix (line-proximity + tightened keyword regex), the miner needs
to be rerun from a clean slate.

Usage:
  python scripts/rollback_weak_random.py            # dry run
  python scripts/rollback_weak_random.py --apply    # actually move
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROLLBACK_REASON = (
    "CWE-330 file-wide security-context check produced ~60-80% FPs "
    "(see PHASE_2B_OPEN_QUESTIONS.md, 2026-05-11). Rolled back 2026-05-12 "
    "ahead of weak_random_miner rerun with line-proximity filter."
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-dir", default="data/raw")
    parser.add_argument("--rejected-dir", default="data/raw_rejected")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    raw = Path(args.raw_dir)
    rejected = Path(args.rejected_dir)

    metas = sorted(raw.glob("weak_random_*.meta.json"))
    pys = sorted(raw.glob("weak_random_*.py"))
    print(f"Found {len(metas)} meta + {len(pys)} py files matching weak_random_* in {raw}")

    if not metas:
        print("Nothing to do.")
        return 0

    entries = []
    for meta_path in metas:
        try:
            m = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            m = {}
        py_path = meta_path.with_suffix("").with_suffix(".py")
        entries.append({
            "id": m.get("id"),
            "cwe": m.get("cwe"),
            "source": m.get("source"),
            "repo": m.get("repo"),
            "file_path": m.get("file_path"),
            "meta_path": str(meta_path),
            "py_path": str(py_path),
            "reason": "cwe330_filewide_context_fp",
        })

    if not args.apply:
        print("DRY RUN — no files moved. Re-run with --apply to commit.")
        print(f"Would move {len(metas) + len(pys)} files into {rejected}/")
        return 0

    rejected.mkdir(parents=True, exist_ok=True)
    moved_meta = moved_py = errors = 0
    for entry in entries:
        for src_str in (entry["meta_path"], entry["py_path"]):
            src = Path(src_str)
            if not src.exists():
                continue
            try:
                shutil.move(str(src), str(rejected / src.name))
                if src_str.endswith(".meta.json"):
                    moved_meta += 1
                else:
                    moved_py += 1
            except Exception as e:
                print(f"  move failed: {src} ({e})")
                errors += 1

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    manifest_path = rejected / f"manifest_rollback_weak_random_{timestamp}.json"
    manifest_path.write_text(json.dumps({
        "schema": "phase2b_rollback_manifest_v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "raw_dir": str(raw),
        "rejected_dir": str(rejected),
        "reason": ROLLBACK_REASON,
        "rejected_entries": entries,
    }, indent=2))

    print(f"\nMoved {moved_meta} .meta.json + {moved_py} .py files → {rejected}/")
    if errors:
        print(f"WARN: {errors} errors during move")
    print(f"Manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
