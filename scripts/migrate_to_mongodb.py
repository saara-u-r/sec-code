"""
migrate_to_mongodb.py

One-time migration: push all existing data/raw/*.meta.json samples to MongoDB
Atlas, upgrading each document to the current v2.0 schema along the way.

Handles two generations of on-disk schema:
  v0 (cvefixes early runs) — minimal fields, no code_before in JSON
  v1 (osv/ghsa/pypa runs)  — more fields but old names (valid_syntax,
                              has_flask_import, is_vulnerable, timestamp)

Also rewrites each .meta.json on disk to the upgraded schema so everything
is consistent after the migration.

Usage:
    .venv/bin/python3 scripts/migrate_to_mongodb.py
    .venv/bin/python3 scripts/migrate_to_mongodb.py --dry-run   # no writes
    .venv/bin/python3 scripts/migrate_to_mongodb.py --no-rewrite # skip disk update
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.file_utils import build_meta, hash_code, CWE_NAMES
from src.utils.mongo_writer import upsert_sample, _init
from src.utils.logger import get_logger

logger = get_logger(__name__)

DATA_DIR = Path("data/raw")

# Map source name → label metadata for old samples that didn't store this
_LABEL_META = {
    "cvefixes": ("nvd",  "high"),
    "osv":      ("osv",  "high"),
    "ghsa":     ("ghsa", "high"),
    "pypa":     ("pypa", "medium"),
}


def _upgrade(old: dict, code_before: str) -> dict:
    """
    Upgrade an old-schema metadata dict to the current v2.0 schema.
    Uses build_meta() so all computed signals are recalculated from code.
    """
    source = old.get("source", "unknown")
    label_source, label_confidence = _LABEL_META.get(source, ("advisory", "medium"))

    # Coerce old 'timestamp' → 'scraped_at'
    scraped_at = old.get("scraped_at") or old.get("timestamp")

    # code_after may be stored in meta or absent entirely
    code_after = old.get("code_after", "")

    # Build pair_id from what's available
    cve_id    = old.get("cve_id")
    fix_commit = old.get("fix_commit", "")
    file_path  = old.get("file_path", "")
    if cve_id and file_path:
        pair_id = f"{cve_id}_{file_path}"
    elif fix_commit and file_path:
        pair_id = f"{fix_commit[:8]}_{file_path}"
    else:
        pair_id = None

    fields = {
        "id":               old["id"],
        "source":           source,
        "cve_id":           cve_id,
        "ghsa_id":          old.get("ghsa_id"),
        "osv_id":           old.get("osv_id"),
        "pysec_id":         old.get("pysec_id"),
        "cwe":              old.get("cwe", ""),
        "vuln_type":        old.get("vuln_type"),
        "label_source":     old.get("label_source", label_source),
        "label_confidence": old.get("label_confidence", label_confidence),
        # CVSS — carry over whatever was stored
        "cvss_score":               old.get("cvss_score"),
        "cvss_severity":            old.get("cvss_severity"),
        "cvss_version":             old.get("cvss_version"),
        "cvss_vector":              old.get("cvss_vector"),
        "cvss_attack_vector":       old.get("cvss_attack_vector"),
        "cvss_attack_complexity":   old.get("cvss_attack_complexity"),
        "cvss_privileges_required": old.get("cvss_privileges_required"),
        "cvss_user_interaction":    old.get("cvss_user_interaction"),
        "cvss_scope":               old.get("cvss_scope"),
        "cvss_confidentiality":     old.get("cvss_confidentiality"),
        "cvss_integrity":           old.get("cvss_integrity"),
        "cvss_availability":        old.get("cvss_availability"),
        "cvss_source":              old.get("cvss_source"),
        # Git provenance
        "repo":              old.get("repo"),
        "file_path":         file_path,
        "fix_commit":        fix_commit or None,
        "vulnerable_commit": old.get("vulnerable_commit"),
        "commit_message":    old.get("commit_message", ""),
        "commit_date":       old.get("commit_date"),
        # Framework
        "framework": old.get("framework", "unknown"),
        "pair_id":   pair_id,
    }

    meta = build_meta(fields, code_before, code_after)

    # Preserve original scraped_at rather than overwriting with now()
    if scraped_at:
        meta["scraped_at"] = scraped_at

    return meta


def migrate(dry_run: bool = False, rewrite_disk: bool = True) -> None:
    if not dry_run and not _init():
        logger.error("Cannot connect to MongoDB — aborting. Check MONGODB_URI in .env.")
        sys.exit(1)

    meta_files = sorted(DATA_DIR.glob("*.meta.json"))
    total = len(meta_files)
    logger.info(f"Found {total} samples in {DATA_DIR}")

    pushed = 0
    skipped = 0
    errors = 0

    for i, meta_path in enumerate(meta_files, 1):
        sample_id = meta_path.stem.replace(".meta", "")
        py_path = meta_path.with_suffix("").with_suffix(".py")

        # Load existing metadata
        try:
            old_meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning(f"[{i}/{total}] Cannot read {meta_path.name}: {e}")
            errors += 1
            continue

        # Skip the test sample we created earlier
        if old_meta.get("id") == "test_connection_sample_001":
            skipped += 1
            continue

        # Load code_before from .py file (source of truth)
        if not py_path.exists():
            logger.warning(f"[{i}/{total}] No .py file for {sample_id} — skipping")
            skipped += 1
            continue

        code_before = py_path.read_text(encoding="utf-8")

        # Already on new schema — still upsert but skip disk rewrite
        if old_meta.get("_schema_version") == "2.0":
            if not dry_run:
                upsert_sample(old_meta)
            pushed += 1
            if i % 50 == 0 or i == total:
                logger.info(f"  [{i}/{total}] {sample_id[:50]} (already v2.0)")
            continue

        # Upgrade old schema → v2.0
        try:
            new_meta = _upgrade(old_meta, code_before)
        except Exception as e:
            logger.warning(f"[{i}/{total}] Upgrade failed for {sample_id}: {e}")
            errors += 1
            continue

        if not dry_run:
            # Write to MongoDB
            upsert_sample(new_meta)

            # Rewrite .meta.json on disk with upgraded schema
            if rewrite_disk:
                meta_path.write_text(json.dumps(new_meta, indent=2), encoding="utf-8")

        pushed += 1
        if i % 50 == 0 or i == total:
            logger.info(
                f"  [{i}/{total}] {sample_id[:50]}"
                f" | {new_meta.get('cwe')} | {new_meta.get('framework')}"
                f" | loc={new_meta.get('loc_before')}"
            )

    logger.info("─" * 60)
    logger.info(f"Migration complete — pushed: {pushed}  skipped: {skipped}  errors: {errors}")
    if dry_run:
        logger.info("DRY RUN — no data was written")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate existing samples to MongoDB")
    parser.add_argument("--dry-run",    action="store_true", help="Preview only, no writes")
    parser.add_argument("--no-rewrite", action="store_true", help="Skip updating .meta.json files on disk")
    args = parser.parse_args()
    migrate(dry_run=args.dry_run, rewrite_disk=not args.no_rewrite)
