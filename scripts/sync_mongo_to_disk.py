#!/usr/bin/env python3
"""
sync_mongo_to_disk.py — make the MongoDB collection match data/raw/.

Phase 2B rejections (refilter, weak_random rollback, rescope) were applied
at the file-system level: rejected samples moved to data/raw_rejected/ with
manifests, but the corresponding MongoDB documents were left in place.

This means MongoDB has documents for samples no longer on disk. When
scripts/run_phase2.py reads samples it prefers MongoDB, so a stale Mongo
collection silently re-includes rejected samples in the train/val/test
split. We need Mongo to mirror disk exactly.

What this script does:
  1. Read every {id} from data/raw/*.meta.json.
  2. Read every {id} from MongoDB.
  3. Delete Mongo documents whose id is NOT on disk
     (these are samples that were rejected/rescoped post-write).
  4. (Optional with --upsert-missing) Re-upsert any disk samples that
     are missing from Mongo so the next read pass sees them.

Note: "safe" hard-negative samples (cwe=safe) live on disk only — they
were never written to Mongo. That asymmetry is intentional and preserved.

Usage:
  python scripts/sync_mongo_to_disk.py            # dry run
  python scripts/sync_mongo_to_disk.py --apply    # delete stale docs
  python scripts/sync_mongo_to_disk.py --apply --upsert-missing
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

logger = get_logger("sync_mongo_to_disk")


def _disk_ids(raw_dir: str) -> set[str]:
    ids: set[str] = set()
    for meta_path in glob.glob(f"{raw_dir}/*.meta.json"):
        try:
            with open(meta_path, encoding="utf-8") as fh:
                m = json.load(fh)
        except Exception:
            continue
        if m.get("id"):
            ids.add(m["id"])
    return ids


def _mongo_ids(col) -> set[str]:
    return {d["id"] for d in col.find({"id": {"$exists": True}}, {"id": 1, "_id": 0})}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-dir", default="data/raw")
    parser.add_argument("--apply", action="store_true",
                        help="Actually delete stale documents. Default is dry run.")
    parser.add_argument("--upsert-missing", action="store_true",
                        help="After deleting stale, also re-upsert any disk docs missing from Mongo.")
    args = parser.parse_args()

    col = get_collection()
    if col is None:
        logger.error("MongoDB unavailable — set MONGODB_URI in .env")
        return 1

    disk_ids = _disk_ids(args.raw_dir)
    mongo_ids = _mongo_ids(col)

    stale = mongo_ids - disk_ids
    missing = disk_ids - mongo_ids

    print(f"Disk ids:   {len(disk_ids)}")
    print(f"Mongo ids:  {len(mongo_ids)}")
    print(f"Stale (in Mongo, not on disk): {len(stale)}")
    print(f"Missing (on disk, not in Mongo): {len(missing)}")

    # Breakdown of stale by CWE
    if stale:
        from collections import Counter
        stale_cwes = Counter()
        for d in col.find({"id": {"$in": list(stale)}}, {"cwe": 1, "_id": 0}):
            stale_cwes[d.get("cwe") or "?"] += 1
        print("\nStale-document breakdown by CWE:")
        for c, n in sorted(stale_cwes.items()):
            print(f"  {c:<12} {n:>6}")

    if not args.apply:
        print("\nDRY RUN — no changes made. Re-run with --apply to delete stale documents.")
        return 0

    if stale:
        result = col.delete_many({"id": {"$in": list(stale)}})
        logger.info(f"Deleted {result.deleted_count} stale documents from Mongo.")

    if args.upsert_missing and missing:
        upserted = 0
        for meta_path in glob.glob(f"{args.raw_dir}/*.meta.json"):
            try:
                with open(meta_path, encoding="utf-8") as fh:
                    m = json.load(fh)
            except Exception:
                continue
            if m.get("id") in missing:
                upsert_sample(m)
                upserted += 1
        logger.info(f"Upserted {upserted} missing documents to Mongo.")

    # Verify
    new_mongo = _mongo_ids(col)
    print(f"\nPost-sync Mongo ids: {len(new_mongo)}")
    print(f"  on-disk and in Mongo: {len(new_mongo & disk_ids)}")
    print(f"  in Mongo not on disk: {len(new_mongo - disk_ids)}  (should be 0)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
