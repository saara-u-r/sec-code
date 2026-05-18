"""
purge_bad_samples.py — Dataset cleanup

Removes low-quality samples from data/raw/ based on the same criteria
used by the health checker. Run this after ingestion and before Phase 2
(CVE attribution) to start with a clean dataset.

What gets purged (configurable via flags):
  --invalid-syntax   Files that are not valid Python (default: ON)
  --no-exec-code     Files that are pure docstrings / narratives with no
                     executable code (default: ON)
  --attack-pocs      Files that are attacker PoC scripts, not server code
                     (default: ON)
  --false-labels     Files where the CWE label has zero pattern support
                     in the code (default: OFF — use with care)
  --no-flask         Files with no Flask import AND no request.* taint
                     (default: OFF — some snippets are legit without Flask)
  --source SOURCE    Only purge samples from a specific source
                     e.g. --source repo_clone to clean up pallets/flask noise

Dry run (default): prints what would be deleted without deleting anything.
Pass --execute to actually delete.

Usage:
  python scripts/purge_bad_samples.py --dry-run
  python scripts/purge_bad_samples.py --execute
  python scripts/purge_bad_samples.py --execute --source repo_clone
  python scripts/purge_bad_samples.py --execute --false-labels
"""

import argparse
import ast
import json
import re
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Detection helpers (mirrored from health_check.py)
# ---------------------------------------------------------------------------

TAINT_SOURCES = re.compile(
    r"request\s*\.\s*(args|form|data|json|values|files|cookies|headers)",
    re.IGNORECASE,
)

CWE_PATTERNS: dict[str, list[re.Pattern]] = {
    "CWE-89": [
        # Inline patterns — unsafe format directly inside execute()
        re.compile(r'execute\s*\(\s*f["\']', re.IGNORECASE),
        re.compile(r'execute\s*\(\s*["\'][^"\']*%\s*', re.IGNORECASE),
        re.compile(r'execute\s*\(\s*["\'][^"\']*\+', re.IGNORECASE),
        re.compile(r'execute\s*\(\s*.*\.format\s*\(', re.IGNORECASE),
        re.compile(r"execute\s*\(\s*(query|sql|stmt)\b", re.IGNORECASE),
        # Multi-line patterns — SQL built in a variable before execute()
        re.compile(r'(query|sql|stmt)\s*=\s*f["\']', re.IGNORECASE),
        re.compile(r'(query|sql|stmt)\s*=\s*["\'][^"\']*\+', re.IGNORECASE),
        re.compile(r'(query|sql|stmt)\s*=\s*.*\.format\s*\(', re.IGNORECASE),
        # ORM-level injection
        re.compile(r'filter\s*\(\s*f["\']', re.IGNORECASE),
        re.compile(r'\.raw\s*\(\s*f["\']', re.IGNORECASE),
        re.compile(r'text\s*\(\s*f["\']', re.IGNORECASE),
        re.compile(r'text\s*\(\s*["\'][^"\']*\+', re.IGNORECASE),
    ],
    "CWE-78": [
        re.compile(r"\bos\s*\.\s*(system|popen)\s*\("),
        re.compile(r"\bsubprocess\s*\.\s*(run|call|check_output|Popen)\s*\("),
        re.compile(r"\beval\s*\("),
        re.compile(r"\bexec\s*\("),
    ],
    "CWE-22": [
        re.compile(r"\bopen\s*\("),
        re.compile(r"\bsend_file\s*\("),
        re.compile(r"\bsend_from_directory\s*\("),
        re.compile(r"\bos\s*\.\s*path\s*\.\s*(join|abspath)\s*\("),
    ],
    "CWE-502": [
        re.compile(r"\bpickle\s*\.\s*loads?\s*\("),
        re.compile(r"\byaml\s*\.\s*load\s*\("),
        re.compile(r"\bmarshal\s*\.\s*loads?\s*\("),
    ],
    "CWE-79": [
        re.compile(r"\bmark_safe\s*\("),
        re.compile(r"\bMarkup\s*\("),
        re.compile(r"\brender_template_string\s*\("),
        re.compile(r"autoescape\s*=\s*False"),
        re.compile(r"\|safe\b"),
    ],
    "CWE-94": [
        re.compile(r"\beval\s*\("),
        re.compile(r"\bexec\s*\("),
        re.compile(r"\bcompile\s*\("),
        re.compile(r"\b__import__\s*\("),
    ],
    "CWE-918": [
        re.compile(r"\brequests\s*\.\s*(get|post|put|patch|delete|head|request)\s*\("),
        re.compile(r"\burllib\.request\.(urlopen|Request)\s*\("),
        re.compile(r"\bhttpx\s*\.\s*(get|post|put|patch|delete)\s*\("),
        re.compile(r"\baiohttp\s*\.\s*ClientSession\s*\("),
    ],
}


def is_valid_python(source: str) -> bool:
    try:
        ast.parse(source)
        return True
    except SyntaxError:
        return False


def has_executable_code(source: str) -> bool:
    stripped = re.sub(r'"""[\s\S]*?"""', "", source)
    stripped = re.sub(r"'''[\s\S]*?'''", "", stripped)
    stripped = re.sub(r"#.*", "", stripped)
    lines = [line for line in stripped.splitlines() if line.strip()]
    return len(lines) > 2


def is_attack_poc(source: str) -> bool:
    has_flask = bool(re.search(r"(from flask|import flask)", source, re.IGNORECASE))
    has_server_request = bool(TAINT_SOURCES.search(source))
    has_client = bool(re.search(r"\brequests\.(get|post|put)\s*\(", source))
    has_target = bool(re.search(r"(target_url|victim|http://|https://)", source, re.IGNORECASE))
    if has_flask or has_server_request:
        return False
    return has_client and has_target


def cwe_has_no_support(source: str, cwe: str) -> bool:
    patterns = CWE_PATTERNS.get(cwe, [])
    return bool(patterns) and not any(p.search(source) for p in patterns)


def has_flask_or_taint(source: str) -> bool:
    has_flask = bool(re.search(r"(from flask|import flask)", source, re.IGNORECASE))
    return has_flask or bool(TAINT_SOURCES.search(source))


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

def should_purge(
    source: str,
    meta: dict,
    *,
    purge_invalid_syntax: bool,
    purge_no_exec: bool,
    purge_attack_pocs: bool,
    purge_false_labels: bool,
    purge_no_flask: bool,
    source_filter: str | None,
) -> tuple[bool, str]:
    """
    Return (True, reason) if this sample should be purged, else (False, "").
    """
    if source_filter and meta.get("source", "") != source_filter:
        return False, ""

    if purge_invalid_syntax and not is_valid_python(source):
        return True, "invalid Python syntax"

    if purge_no_exec and not has_executable_code(source):
        return True, "no executable code (pure docstring/narrative)"

    if purge_attack_pocs and is_attack_poc(source):
        return True, "attacker PoC script — no server-side code"

    cwe = meta.get("cwe", "")
    is_vulnerable = meta.get("is_vulnerable", True)

    if purge_false_labels and is_vulnerable and cwe and cwe_has_no_support(source, cwe):
        return True, f"CWE label {cwe} has zero pattern support in code"

    if purge_no_flask and is_vulnerable and not has_flask_or_taint(source):
        return True, "no Flask import and no request.* taint source"

    return False, ""


def run_purge(raw_dir: str, execute: bool, **kwargs) -> None:
    raw = Path(raw_dir)
    meta_files = sorted(raw.glob("*.meta.json"))

    if not meta_files:
        print(f"[ERROR] No .meta.json files found in {raw_dir}", file=sys.stderr)
        sys.exit(1)

    to_purge: list[tuple[Path, Path, str]] = []  # (py_path, meta_path, reason)

    for meta_path in meta_files:
        py_path = meta_path.with_suffix("").with_suffix(".py")

        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            continue

        if not py_path.exists():
            to_purge.append((py_path, meta_path, "missing .py file"))
            continue

        try:
            source = py_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            to_purge.append((py_path, meta_path, "unreadable .py file"))
            continue

        purge, reason = should_purge(source, meta, **kwargs)
        if purge:
            to_purge.append((py_path, meta_path, reason))

    total = len(meta_files)
    print(f"\nDataset: {total} samples in {raw_dir}")
    print(f"Samples flagged for purge: {len(to_purge)}")
    print(f"Samples retained: {total - len(to_purge)}")

    if not to_purge:
        print("\nNothing to purge.")
        return

    # Group by reason for summary
    reason_counts: dict[str, int] = {}
    for _, _, reason in to_purge:
        reason_counts[reason] = reason_counts.get(reason, 0) + 1

    print("\nBreakdown by reason:")
    for reason, count in sorted(reason_counts.items(), key=lambda x: -x[1]):
        print(f"  {count:>5}x  {reason}")

    if not execute:
        print("\n[DRY RUN] No files deleted. Pass --execute to delete.")
        print("\nFirst 20 files that would be deleted:")
        for py_path, _, reason in to_purge[:20]:
            print(f"  {py_path.name}  ({reason})")
        return

    # Execute deletions
    deleted = 0
    for py_path, meta_path, reason in to_purge:
        py_path.unlink(missing_ok=True)
        meta_path.unlink(missing_ok=True)
        deleted += 1

    print(f"\n[DONE] Deleted {deleted} samples ({deleted * 2} files).")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Purge low-quality samples from data/raw/")
    p.add_argument("--raw-dir", default="data/raw", help="Path to raw samples directory")

    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", dest="execute", action="store_false",
                      default=False, help="Show what would be deleted (default)")
    mode.add_argument("--execute", dest="execute", action="store_true",
                      help="Actually delete the files")

    p.add_argument("--source", default=None,
                   help="Limit purge to a specific source (e.g. repo_clone, exploitdb)")

    # Purge criteria (all ON by default except false-labels and no-flask)
    p.add_argument("--no-invalid-syntax", dest="purge_invalid_syntax",
                   action="store_false", default=True,
                   help="Skip purging files with invalid Python syntax")
    p.add_argument("--no-exec-code", dest="purge_no_exec",
                   action="store_true", default=True,
                   help="Purge files with no executable code")
    p.add_argument("--no-attack-pocs", dest="purge_attack_pocs",
                   action="store_false", default=True,
                   help="Skip purging attacker PoC scripts")
    p.add_argument("--false-labels", dest="purge_false_labels",
                   action="store_true", default=False,
                   help="Also purge files where CWE label has zero code support")
    p.add_argument("--no-flask", dest="purge_no_flask",
                   action="store_true", default=False,
                   help="Also purge vulnerable samples with no Flask/request.* taint")

    return p.parse_args()


def main() -> None:
    args = parse_args()
    run_purge(
        raw_dir=args.raw_dir,
        execute=args.execute,
        purge_invalid_syntax=args.purge_invalid_syntax,
        purge_no_exec=args.purge_no_exec,
        purge_attack_pocs=args.purge_attack_pocs,
        purge_false_labels=args.purge_false_labels,
        purge_no_flask=args.purge_no_flask,
        source_filter=args.source,
    )


if __name__ == "__main__":
    main()
