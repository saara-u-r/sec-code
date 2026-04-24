"""
cleaner.py — Phase 1, Step 5

Runs over everything in data/raw/ and:

  1. Deduplicates — removes files whose code hash already appeared, persisting
     seen hashes to data/raw/.seen_hashes so re-runs don't re-introduce dupes
  2. Validates — checks for parseable Python syntax; drops files that fail
  3. Filters — drops files with fewer than MIN_CODE_LINES non-blank lines
  4. Normalises — strips trailing whitespace, normalises line endings
  5. Flags — updates .meta.json with valid_syntax and has_flask_import fields

Why clean before analysis?
  Duplicate snippets skew class distributions and inflate evaluation metrics.
  Syntax errors crash the AST-based analyzer in Phase 2.
  Running the cleaner here keeps Phases 2–7 assumption-free.
"""

import ast
import json
import re
from pathlib import Path

from src.utils.file_utils import hash_code
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Minimum number of non-blank, non-comment lines for a snippet to be kept.
MIN_CODE_LINES = 5

SEEN_HASHES_FILE = "data/raw/.seen_hashes"


# ---------------------------------------------------------------------------
# Predicates & Extractors
# ---------------------------------------------------------------------------

def extract_cve(source: str) -> str | None:
    """Find the first CVE-YYYY-NNNNN pattern in the text."""
    match = re.search(r"CVE-\d{4}-\d{4,7}", source, re.IGNORECASE)
    return match.group(0).upper() if match else None


def is_valid_python(source: str) -> bool:
    try:
        ast.parse(source)
        return True
    except SyntaxError:
        return False


def has_flask_import(source: str) -> bool:
    return "from flask" in source.lower() or "import flask" in source.lower()


def has_enough_lines(source: str) -> bool:
    """Return True if the source has at least MIN_CODE_LINES non-blank, non-comment lines."""
    count = sum(
        1 for line in source.splitlines()
        if line.strip() and not line.strip().startswith("#")
    )
    return count >= MIN_CODE_LINES


def normalize(source: str) -> str:
    """Strip trailing whitespace per line and normalise to Unix line endings."""
    lines = [line.rstrip() for line in source.splitlines()]
    return "\n".join(lines).strip()


# ---------------------------------------------------------------------------
# Passes
# ---------------------------------------------------------------------------

def _load_seen_hashes(path: str) -> set[str]:
    p = Path(path)
    if not p.exists():
        return set()
    return set(p.read_text(encoding="utf-8").splitlines())


def _save_seen_hashes(hashes: set[str], path: str) -> None:
    Path(path).write_text("\n".join(sorted(hashes)), encoding="utf-8")


def deduplicate(raw_dir: str) -> dict[str, int]:
    """
    Remove duplicate .py files (by content hash).
    Builds the seen set fresh each run from the files actually on disk, then
    overwrites SEEN_HASHES_FILE so scrapers can use it for cross-run dedup.
    """
    seen: set[str] = set()
    kept = removed = 0

    for meta_path in Path(raw_dir).glob("*.meta.json"):
        py_path = meta_path.with_suffix("").with_suffix(".py")

        if not py_path.exists():
            meta_path.unlink(missing_ok=True)
            continue

        code = py_path.read_text(encoding="utf-8", errors="ignore")
        h = hash_code(code)

        if h in seen:
            py_path.unlink()
            meta_path.unlink()
            removed += 1
        else:
            seen.add(h)
            kept += 1

    _save_seen_hashes(seen, SEEN_HASHES_FILE)
    logger.info(f"Deduplication: kept={kept}, removed={removed} ({len(seen)} hashes on disk)")
    return {"kept": kept, "removed": removed}


def validate_and_clean(raw_dir: str) -> dict[str, int]:
    """
    For every remaining .py file:
      - Drop files with invalid Python syntax
      - Drop files with fewer than MIN_CODE_LINES non-blank lines
      - Normalise whitespace
      - Flag metadata with valid_syntax and has_flask_import
    """
    stats: dict[str, int] = {
        "valid": 0,
        "dropped_invalid_syntax": 0,
        "dropped_too_short": 0,
        "cves_found": 0,
    }

    for py_path in Path(raw_dir).glob("*.py"):
        meta_path = py_path.with_suffix(".meta.json")

        try:
            code = py_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            py_path.unlink(missing_ok=True)
            meta_path.unlink(missing_ok=True)
            stats["dropped_invalid_syntax"] += 1
            continue

        if not code.strip():
            py_path.unlink()
            meta_path.unlink(missing_ok=True)
            stats["dropped_invalid_syntax"] += 1
            continue

        # Drop files that aren't valid Python — no rescue attempts
        if not is_valid_python(code):
            py_path.unlink()
            meta_path.unlink(missing_ok=True)
            stats["dropped_invalid_syntax"] += 1
            continue

        # Drop snippets that are too short to be useful training samples
        if not has_enough_lines(code):
            py_path.unlink()
            meta_path.unlink(missing_ok=True)
            stats["dropped_too_short"] += 1
            continue

        cve = extract_cve(code)
        flask = has_flask_import(code)
        py_path.write_text(normalize(code), encoding="utf-8")
        stats["valid"] += 1

        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text())
                meta["valid_syntax"] = True
                meta["has_flask_import"] = flask
                if cve:
                    meta["cve_id"] = cve
                    stats["cves_found"] += 1
                meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
            except Exception:
                pass

    logger.info(f"Validation & Filtering: {stats}")
    return stats


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(raw_dir: str = "data/raw") -> dict:
    logger.info(f"=== Cleaner starting on {raw_dir} ===")
    dedup_stats = deduplicate(raw_dir)
    clean_stats = validate_and_clean(raw_dir)
    result = {**dedup_stats, **clean_stats}
    logger.info(f"=== Cleaner done: {result} ===")
    return result
