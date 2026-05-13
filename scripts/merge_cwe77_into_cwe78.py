#!/usr/bin/env python3
"""
merge_cwe77_into_cwe78.py — relabel all CWE-77 samples as CWE-78.

In MITRE's hierarchy, CWE-78 (OS Command Injection) is a child of CWE-77
(Improper Neutralization of Special Elements in a Command). For Python
specifically, both fire on the same sink set (`os.system`, `subprocess
shell=True`, `Popen`); the distinction is bureaucratic. Keeping them as
separate labels created artificial scarcity (CWE-77: 4 samples;
CWE-78: 16 samples). Merging them gives a single ~20+ sample
"command injection" class — usable for the benchmark.

What this script does:
  1. Find every meta.json on disk with cwe="CWE-77".
  2. Rewrite cwe → "CWE-78", vuln_type → "command_injection",
     cwe_name → "OS Command Injection".
  3. Re-upsert each rewritten meta to MongoDB so the collection stays
     in sync with disk.
  4. Print a per-sample audit log so the relabel is fully traceable
     (the original CWE-77 source is in the {source, repo, cve_id} fields
     which are not touched).

Filenames are NOT renamed (an `id` like `cvefixes_command_injection_generic_xxx`
remains; we don't rename to avoid breaking external references). Future
samples will use the merged taxonomy automatically because CWE-77 is
removed from `CWE_VULN_MAP`.

Usage:
  python scripts/merge_cwe77_into_cwe78.py            # dry-run summary
  python scripts/merge_cwe77_into_cwe78.py --apply    # actually relabel
"""

from __future__ import annotations

import argparse
import glob
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.logger import get_logger  # noqa: E402
from src.utils.mongo_writer import get_collection, upsert_sample  # noqa: E402

logger = get_logger("merge77")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-dir", default="data/raw")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    affected: list[dict] = []
    for f in glob.glob(f"{args.raw_dir}/*.meta.json"):
        try:
            with open(f, encoding="utf-8") as fh:
                m = json.load(fh)
        except Exception:
            continue
        if m.get("cwe") != "CWE-77":
            continue
        affected.append({"path": f, "meta": m})

    print(f"Found {len(affected)} CWE-77 samples on disk.")
    if not affected:
        return 0
    for entry in affected[:8]:
        m = entry["meta"]
        print(f"  {m.get('id')} | {m.get('source')} | {m.get('cve_id') or '-'} | {m.get('repo')}")
    if len(affected) > 8:
        print(f"  ... and {len(affected) - 8} more")

    if not args.apply:
        print("\nDRY RUN — no changes made. Re-run with --apply to merge.")
        return 0

    col = get_collection()
    rewrote = 0
    for entry in affected:
        path = Path(entry["path"])
        m = entry["meta"]
        # Disk rewrite
        m["cwe"] = "CWE-78"
        m["cwe_name"] = "OS Command Injection"
        m["vuln_type"] = "command_injection"
        # Record the merge in a side-channel field so the audit trail is preserved
        m.setdefault("provenance_notes", []).append(
            "Relabeled CWE-77 → CWE-78 on 2026-05-13 (Phase 2B merge — see "
            "scripts/merge_cwe77_into_cwe78.py and cwe_taxonomy.DEPRECATED_CWES)."
        )
        path.write_text(json.dumps(m, indent=2), encoding="utf-8")
        rewrote += 1
        # MongoDB upsert by content_hash (the script's pre-condition is that
        # sync_mongo_to_disk has run, so the Mongo doc with this content_hash
        # exists and represents the original CWE-77 state — upsert overwrites.)
        upsert_sample(m)
        logger.info(f"  rewrote {m.get('id')}")

    print(f"\nRelabeled {rewrote} disk files + Mongo docs (CWE-77 → CWE-78).")
    print("Next: re-run scripts/run_phase2.py and scripts/run_phase2b_configs.py.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
