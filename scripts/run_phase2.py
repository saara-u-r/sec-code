#!/usr/bin/env python3
"""
run_phase2.py — Phase 2: Stratified Train/Val/Test Split

Loads all samples (vulnerable + hard-negatives) from MongoDB or disk,
performs a stratified group split with anti-leakage, writes the
``split`` field back to each document on disk and (best-effort) to
MongoDB, and emits ``data/phase2_split_report.json``.

The split satisfies two correctness constraints:

  1. **No repo leakage** — same `repo` lands in same split
  2. **CWE stratification** — class proportions preserved across splits

See ``PHASE2_DESIGN.md`` §6–§7 for the design.

Usage:
    python scripts/run_phase2.py                  # default seed=42
    python scripts/run_phase2.py --seed 123       # different seed
    python scripts/run_phase2.py --dry-run        # preview, don't write
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.labeler.stratified_splitter import (  # noqa: E402
    SplitReport,
    stratified_group_split,
)
from src.utils.logger import get_logger  # noqa: E402

logger = get_logger("phase2")


# ---------------------------------------------------------------------------
# Sample loading — MongoDB primary, disk fallback
# ---------------------------------------------------------------------------

def _load_samples_from_mongo() -> list[dict] | None:
    """Try to load samples from MongoDB. Returns None on failure."""
    try:
        from src.utils.mongo_writer import get_collection
        col = get_collection()
        if col is None:
            return None
        projection = {
            "id":               1,
            "cwe":              1,
            "repo":             1,
            "framework":        1,
            "source":           1,
            "is_hard_negative": 1,
            "parent_sample_id": 1,
            "_id":              0,
        }
        return list(col.find({"id": {"$exists": True}}, projection))
    except Exception as e:
        logger.warning(f"MongoDB read failed: {e}")
        return None


def _load_samples_from_disk(raw_dir: str) -> list[dict]:
    """Walk data/raw/*.meta.json and return a list of sample dicts."""
    raw = Path(raw_dir)
    if not raw.exists():
        return []
    samples: list[dict] = []
    for meta_path in sorted(raw.glob("*.meta.json")):
        try:
            m = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not m.get("id"):
            continue
        samples.append({
            "id":               m["id"],
            "cwe":              m.get("cwe"),
            "repo":             m.get("repo"),
            "framework":        m.get("framework"),
            "source":           m.get("source"),
            "is_hard_negative": m.get("is_hard_negative", False),
            "parent_sample_id": m.get("parent_sample_id"),
        })
    return samples


def load_samples(raw_dir: str = "data/raw") -> tuple[list[dict], str]:
    """Return (samples, source_label) — source_label is "mongo" or "disk"."""
    samples = _load_samples_from_mongo()
    if samples:
        return samples, "mongo"
    logger.warning("MongoDB unavailable — falling back to disk")
    return _load_samples_from_disk(raw_dir), "disk"


# ---------------------------------------------------------------------------
# Split write-back — disk primary, MongoDB best-effort
# ---------------------------------------------------------------------------

def _write_split_to_disk(raw_dir: str, assignments: list) -> int:
    """Update meta.json files on disk with the new ``split`` field. Returns
    the number of files updated."""
    raw = Path(raw_dir)
    if not raw.exists():
        return 0
    by_id = {a.sample_id: a.split for a in assignments}
    n_updated = 0
    for meta_path in raw.glob("*.meta.json"):
        try:
            m = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        sid = m.get("id")
        if sid not in by_id:
            continue
        if m.get("split") == by_id[sid]:
            continue  # already correct
        m["split"] = by_id[sid]
        meta_path.write_text(json.dumps(m, indent=2), encoding="utf-8")
        n_updated += 1
    return n_updated


def _write_split_to_mongo(assignments: list) -> int:
    """Best-effort MongoDB bulk update. Returns count or 0 on failure."""
    try:
        from pymongo import UpdateOne
        from src.utils.mongo_writer import get_collection
        col = get_collection()
        if col is None:
            return 0
        ops = [
            UpdateOne({"id": a.sample_id}, {"$set": {"split": a.split}})
            for a in assignments
        ]
        if not ops:
            return 0
        result = col.bulk_write(ops, ordered=False)
        return result.modified_count
    except Exception as e:
        logger.warning(f"MongoDB write failed: {e}")
        return 0


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _print_report(report: SplitReport, source_label: str) -> None:
    total = sum(report.totals.values())
    logger.info("=" * 70)
    logger.info(f"Source: {source_label.upper()}  |  Total samples: {total}")
    logger.info("=" * 70)
    logger.info(
        f"  train: {report.totals['train']:>5}  "
        f"({report.totals['train']/total:.0%})"
    )
    logger.info(
        f"  val:   {report.totals['val']:>5}  "
        f"({report.totals['val']/total:.0%})"
    )
    logger.info(
        f"  test:  {report.totals['test']:>5}  "
        f"({report.totals['test']/total:.0%})"
    )

    logger.info("")
    logger.info("Per-CWE distribution:")
    for cwe in sorted(report.per_cwe.keys()):
        d = report.per_cwe[cwe]
        n = d["train"] + d["val"] + d["test"]
        logger.info(
            f"  {cwe:8s}  total={n:>5}  "
            f"train={d['train']:>4}  val={d['val']:>4}  test={d['test']:>4}"
        )

    logger.info("")
    logger.info(f"Groups: {report.n_groups}  (singletons: {report.n_singleton_groups})")
    logger.info("Repo-leakage check:")
    for k, v in report.leakage_check.items():
        ok = "✓" if v == 0 else "✗"
        logger.info(f"  {ok} {k}: {v}")


def _write_report_json(report: SplitReport, path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2)
    logger.info(f"Report written to {path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Phase 2 — stratified train/val/test split")
    p.add_argument("--seed", type=int, default=42, help="RNG seed (default 42)")
    p.add_argument("--raw-dir", default="data/raw", help="Disk source/target directory")
    p.add_argument(
        "--report",
        default="data/phase2_split_report.json",
        help="Where to write the JSON report",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Compute the split and print the report; do NOT write back",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    logger.info("=== Phase 2 — Stratified Group Split ===")
    logger.info(f"Seed: {args.seed}  |  Mode: {'DRY-RUN' if args.dry_run else 'EXECUTE'}")
    logger.info("")

    samples, source_label = load_samples(args.raw_dir)
    if not samples:
        logger.error(
            "No samples found. Run scripts/run_generator.py first or check "
            "MongoDB/data/raw."
        )
        sys.exit(1)

    # Filter to samples with a CWE label (we don't split unlabeled data)
    samples = [s for s in samples if s.get("cwe")]
    logger.info(f"Loaded {len(samples)} labeled samples from {source_label}")

    cwe_counts = Counter(s["cwe"] for s in samples)
    logger.info("Input class distribution:")
    for cwe, n in sorted(cwe_counts.items()):
        logger.info(f"  {cwe}: {n}")
    logger.info("")

    report = stratified_group_split(samples, seed=args.seed)
    _print_report(report, source_label)

    if args.dry_run:
        logger.info("")
        logger.info("DRY-RUN — no writes performed. Re-run without --dry-run.")
        # Still write the report — useful for previewing
        _write_report_json(report, args.report)
        return

    logger.info("")
    logger.info("Writing split assignments…")
    n_disk = _write_split_to_disk(args.raw_dir, report.assignments)
    logger.info(f"  Disk: {n_disk} meta files updated")
    n_mongo = _write_split_to_mongo(report.assignments)
    logger.info(f"  MongoDB: {n_mongo} documents updated (best-effort)")

    _write_report_json(report, args.report)
    logger.info("")
    logger.info("=== Phase 2 complete ===")


if __name__ == "__main__":
    main()
