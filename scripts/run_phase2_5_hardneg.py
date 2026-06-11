#!/usr/bin/env python3
"""
run_phase2_5_hardneg.py — Phase 2.5 hard-negative miner.

Reads vulnerable samples from MongoDB, applies CWE-specific sanitization
rules, and writes the resulting hard negatives as new samples back to
MongoDB and to ``data/raw/`` on disk. The new documents carry:

  * ``is_hard_negative = True``
  * ``parent_sample_id`` pointing to the vulnerable original
  * ``sanitization_transform`` naming which canonical fix was applied
  * ``cwe = "safe"`` (distinguishes "explicitly sanitized" from
    "no target vulnerability")
  * ``code_before = <sanitized source>`` (the safe twin)
  * ``code_after  = ""`` (no further fix needed)

Usage
-----
    python scripts/run_phase2_5_hardneg.py --dry-run          # preview
    python scripts/run_phase2_5_hardneg.py --execute          # write
    python scripts/run_phase2_5_hardneg.py --cwe CWE-89 --limit 50
    python scripts/run_phase2_5_hardneg.py --execute --seed 42

Outputs a report at ``data/phase2_5_hardneg_report.json``.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root is on the path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.red_team.sanitization import sanitize  # noqa: E402
from src.utils.file_utils import build_meta, hash_code, save_code_sample  # noqa: E402
from src.utils.logger import get_logger  # noqa: E402
from src.utils.mongo_writer import get_collection  # noqa: E402

logger = get_logger("phase2_5_hardneg")

# Target CWEs — must match the sanitization rules registered in src/red_team/sanitization
TARGET_CWES = ["CWE-89", "CWE-79", "CWE-22", "CWE-78", "CWE-918", "CWE-94", "CWE-502"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed_for_sample(sample_doc: dict, base_seed: int) -> int:
    """Derive a per-sample deterministic seed from the content hash."""
    content_hash = sample_doc.get("content_hash", "") or sample_doc.get("id", "")
    return base_seed + (abs(hash(content_hash)) % (2 ** 31))


def _already_has_hardneg(col, parent_id: str) -> bool:
    """Return True if a hard negative already exists for `parent_id`."""
    if col is None:
        return False
    try:
        return col.count_documents({"parent_sample_id": parent_id}, limit=1) > 0
    except Exception:
        return False


def _iter_samples_from_disk(raw_dir: str, cwe: str) -> Iterator[dict]:
    """
    Fallback when MongoDB is unavailable: walk data/raw/*.meta.json,
    filter by CWE, and yield meta dicts loaded from disk.

    The .py file's contents are loaded into ``code_before`` if the
    meta's code_before field is empty (some legacy meta files omit it).
    """
    from collections.abc import Iterator  # noqa: F401 — for type hint only
    raw_path = Path(raw_dir)
    if not raw_path.exists():
        return

    for meta_path in sorted(raw_path.glob("*.meta.json")):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if meta.get("cwe") != cwe:
            continue
        if meta.get("is_hard_negative", False):
            continue
        if not meta.get("code_before"):
            py_path = meta_path.with_suffix("").with_suffix(".py")
            if py_path.exists():
                try:
                    meta["code_before"] = py_path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
            if not meta.get("code_before"):
                continue
        yield meta


def _existing_hardneg_parent_ids_on_disk(raw_dir: str) -> set[str]:
    """Walk data/raw/*.meta.json once and collect all parent_sample_id values
    of existing hard negatives. Used as the dedup set when MongoDB is offline."""
    raw_path = Path(raw_dir)
    if not raw_path.exists():
        return set()
    out: set[str] = set()
    for meta_path in raw_path.glob("hardneg_*.meta.json"):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        pid = meta.get("parent_sample_id")
        if pid:
            out.add(pid)
    return out


def _build_hardneg_meta(
    parent: dict,
    sanitized_code: str,
    transform: str,
) -> dict:
    """
    Construct the metadata document for a hard-negative sample.

    Inherits framework / repo / file_path / cve_id from parent for
    traceability, but assigns its own ID, content_hash, and pipeline state.
    """
    parent_id = parent.get("id", "unknown")
    parent_source = parent.get("source", "unknown")
    new_hash = hash_code(sanitized_code)

    return build_meta(
        {
            "id":                   f"hardneg_{transform}_{new_hash}",
            "source":               f"hardneg_{parent_source}",
            # Hard negatives are SAFE — they should not classify as any
            # target vulnerability. We use a distinct "safe" label rather
            # than "CWE-other" so the model can learn the difference
            # between "wasn't a target CWE" and "was sanitized away".
            "cwe":                  "safe",
            "label_source":         "hardneg_sanitization",
            "label_confidence":     "high",
            # Inherit traceability anchors from the parent
            "cve_id":               parent.get("cve_id"),
            "ghsa_id":              parent.get("ghsa_id"),
            "repo":                 parent.get("repo"),
            "file_path":            parent.get("file_path"),
            "framework":            parent.get("framework", "unknown"),
            "fix_commit":           parent.get("fix_commit"),
            "vulnerable_commit":    parent.get("vulnerable_commit"),
            "commit_message":       parent.get("commit_message", ""),
            "pair_id":              f"{parent_id}_hardneg",
            # Phase 2.5 markers
            "is_hard_negative":         True,
            "parent_sample_id":         parent_id,
            "sanitization_transform":   transform,
        },
        sanitized_code,
        "",  # no separate "fixed" version — the sanitized code IS the fix
    )


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

def run_miner(
    target_cwes: list[str],
    limit_per_cwe: int | None,
    base_seed: int,
    dry_run: bool,
    output_dir: str,
) -> dict:
    """
    Mine hard negatives. Returns a stats dict suitable for JSON dumping.

    Stats shape::

        {
          "<CWE>": {
            "scanned":       int,
            "generated":     int,
            "skipped":       {reason: count, ...},
            "by_transform":  {transform_name: count, ...},
          },
          ...,
          "totals": {...},
          "started_at":  iso8601,
          "finished_at": iso8601,
          "dry_run":     bool,
          "seed":        int,
        }
    """
    started_at = datetime.now(timezone.utc).isoformat()

    # Try MongoDB first; fall back to disk if unreachable
    try:
        col = get_collection()
    except Exception as e:
        logger.warning(f"MongoDB unreachable — falling back to disk: {e}")
        col = None

    using_disk_fallback = col is None
    if using_disk_fallback:
        logger.warning(
            "Reading samples from data/raw/ (MongoDB offline). "
            "Hard negatives will be written to disk; MongoDB upsert is best-effort."
        )
        existing_hardneg_parents = _existing_hardneg_parent_ids_on_disk(output_dir)
    else:
        existing_hardneg_parents = set()

    stats_per_cwe: dict[str, dict] = {}

    for cwe in target_cwes:
        cwe_stats = {
            "scanned":      0,
            "generated":    0,
            "skipped":      Counter(),
            "by_transform": Counter(),
        }
        stats_per_cwe[cwe] = cwe_stats

        if using_disk_fallback:
            iterator = _iter_samples_from_disk(output_dir, cwe)
            if limit_per_cwe is not None:
                iterator = (s for i, s in enumerate(iterator) if i < limit_per_cwe)
            cursor = iterator
        else:
            query = {
                "cwe": cwe,
                "is_hard_negative": {"$ne": True},
            }
            cursor = col.find(query)
            if limit_per_cwe is not None:
                cursor = cursor.limit(limit_per_cwe)

        logger.info(f"=== {cwe} ===")
        for parent in cursor:
            cwe_stats["scanned"] += 1

            parent_id = parent.get("id", "")
            if not parent_id:
                cwe_stats["skipped"]["missing_parent_id"] += 1
                continue

            # Skip if a hard-neg already exists for this parent
            if using_disk_fallback:
                if parent_id in existing_hardneg_parents:
                    cwe_stats["skipped"]["already_has_hardneg"] += 1
                    continue
            else:
                if _already_has_hardneg(col, parent_id):
                    cwe_stats["skipped"]["already_has_hardneg"] += 1
                    continue

            code_before = parent.get("code_before", "") or ""
            if not code_before.strip():
                cwe_stats["skipped"]["empty_code"] += 1
                continue

            seed = _seed_for_sample(parent, base_seed)
            sanitized, result = sanitize(code_before, cwe, random.Random(seed))

            if not result.success:
                reason = result.reason or "unknown"
                # Truncate verbose AST error messages
                short = reason.split(":")[0] if len(reason) > 80 else reason
                cwe_stats["skipped"][short] += 1
                continue

            # Build the new MongoDB document
            try:
                meta = _build_hardneg_meta(parent, sanitized, result.transform)
            except Exception as e:
                cwe_stats["skipped"][f"meta_build_failed: {type(e).__name__}"] += 1
                continue

            cwe_stats["by_transform"][result.transform] += 1

            if dry_run:
                cwe_stats["generated"] += 1
                continue

            # Write to disk + MongoDB (save_code_sample handles both)
            try:
                save_code_sample(sanitized, meta, output_dir)
                cwe_stats["generated"] += 1
            except Exception as e:
                cwe_stats["skipped"][f"save_failed: {type(e).__name__}"] += 1
                logger.warning(f"Failed to save hardneg for {parent_id}: {e}")

        # Convert Counters to plain dicts for JSON serialization
        cwe_stats["skipped"] = dict(cwe_stats["skipped"])
        cwe_stats["by_transform"] = dict(cwe_stats["by_transform"])

        logger.info(
            f"  {cwe}: scanned={cwe_stats['scanned']:>5}  "
            f"generated={cwe_stats['generated']:>5}  "
            f"skipped={sum(cwe_stats['skipped'].values()):>5}"
        )
        if cwe_stats["skipped"]:
            top_reasons = sorted(
                cwe_stats["skipped"].items(), key=lambda kv: -kv[1]
            )[:3]
            for reason, count in top_reasons:
                logger.info(f"    skip reason: {reason} → {count}")
        if cwe_stats["by_transform"]:
            for t, count in cwe_stats["by_transform"].items():
                logger.info(f"    transform: {t} → {count}")

    # Aggregate totals
    totals = {
        "scanned":   sum(s["scanned"] for s in stats_per_cwe.values()),
        "generated": sum(s["generated"] for s in stats_per_cwe.values()),
        "skipped":   sum(sum(s["skipped"].values()) for s in stats_per_cwe.values()),
    }

    return {
        "started_at":  started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "dry_run":     dry_run,
        "seed":        base_seed,
        "target_cwes": target_cwes,
        "totals":      totals,
        "per_cwe":     stats_per_cwe,
    }


def write_report(report: dict, path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info(f"Report written to {path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Phase 2.5 hard-negative miner")
    p.add_argument(
        "--cwe", action="append",
        help="Limit to specific CWE(s). Repeat for multiple. Default: all 7 targets.",
    )
    p.add_argument(
        "--limit", type=int, default=None,
        help="Max samples per CWE (default: unlimited)",
    )
    p.add_argument(
        "--seed", type=int, default=42,
        help="Base RNG seed for deterministic sanitization (default: 42)",
    )

    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run", dest="execute", action="store_false", default=False,
        help="Preview without writing (default)",
    )
    mode.add_argument(
        "--execute", dest="execute", action="store_true",
        help="Actually write generated hard negatives to MongoDB and disk",
    )
    p.add_argument(
        "--output-dir", default="data/raw",
        help="Disk output directory (default: data/raw)",
    )
    p.add_argument(
        "--report", default="data/phase2_5_hardneg_report.json",
        help="Where to write the JSON report",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    target_cwes = args.cwe or TARGET_CWES

    logger.info("=" * 60)
    logger.info("Phase 2.5 — Hard Negative Miner")
    logger.info("=" * 60)
    logger.info(f"Target CWEs:     {target_cwes}")
    logger.info(f"Limit per CWE:   {args.limit or 'unlimited'}")
    logger.info(f"Mode:            {'EXECUTE' if args.execute else 'DRY-RUN'}")
    logger.info(f"Seed:            {args.seed}")
    logger.info("")

    report = run_miner(
        target_cwes=target_cwes,
        limit_per_cwe=args.limit,
        base_seed=args.seed,
        dry_run=not args.execute,
        output_dir=args.output_dir,
    )

    logger.info("")
    logger.info("=" * 60)
    logger.info(
        f"Done. Scanned: {report['totals']['scanned']}  "
        f"Generated: {report['totals']['generated']}  "
        f"Skipped: {report['totals']['skipped']}"
    )
    if not args.execute:
        logger.info("DRY-RUN — no documents were written. Re-run with --execute.")

    write_report(report, args.report)


if __name__ == "__main__":
    main()
