"""
health_check.py — Dataset Quality Auditor

Runs a multi-pass health check over every sample in data/raw/ and
produces a report showing exactly which files are trustworthy, which
are suspect, and why.

Three layers of checks per sample:
  1. Structural   — valid Python syntax, has Flask import, has executable code
  2. CWE Pattern  — does the code actually contain the vulnerability the label claims?
  3. Taint Signal — does the vulnerability touch real Flask user input (request.*)?

Usage:
  python scripts/health_check.py
  python scripts/health_check.py --raw-dir data/raw --out reports/health_report.json
"""

import ast
import argparse
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# CWE-specific detectors
# Each detector returns True if the pattern is found in the source/AST.
# ---------------------------------------------------------------------------

# Taint sources: Flask request objects that carry user input
TAINT_SOURCES = re.compile(
    r"request\s*\.\s*(args|form|data|json|values|files|cookies|headers|get_json)",
    re.IGNORECASE,
)

# CWE-89: SQL injection
# Looks for string formatting / concatenation flowing into a .execute() call.
# Two categories:
#   INLINE  — unsafe formatting directly inside execute(...)
#   MULTILINE — SQL string built in a variable, then passed to execute()
#               e.g. query = "SELECT..." + user_input  →  cursor.execute(query)
_SQL_EXEC = re.compile(r"\.execute\s*\(", re.IGNORECASE)

_SQL_INLINE_PATTERNS = [
    re.compile(r'execute\s*\(\s*f["\']', re.IGNORECASE),           # execute(f"SELECT...")
    re.compile(r'execute\s*\(\s*["\'][^"\']*%\s*', re.IGNORECASE), # execute("..." % ...)
    re.compile(r'execute\s*\(\s*["\'][^"\']*\+', re.IGNORECASE),   # execute("..." + ...)
    re.compile(r'execute\s*\(\s*.*\.format\s*\(', re.IGNORECASE),  # execute("...".format(...))
    re.compile(r"execute\s*\(\s*(query|sql|stmt|cmd)\b", re.IGNORECASE), # execute(query)
]

# Multi-line SQLi: unsafe SQL string built in a variable before execute()
# Catches:  query = "SELECT..." + request.args.get(...)
#           sql = f"SELECT ... {user_input}"
_SQL_MULTILINE_PATTERNS = [
    re.compile(r'(query|sql|stmt)\s*=\s*f["\']', re.IGNORECASE),              # sql = f"SELECT..."
    re.compile(r'(query|sql|stmt)\s*=\s*["\'][^"\']*\+', re.IGNORECASE),     # sql = "SELECT..." +
    re.compile(r'(query|sql|stmt)\s*.*\+=\s*', re.IGNORECASE),               # sql += user_input
    re.compile(r'(query|sql|stmt)\s*=\s*.*\.format\s*\(', re.IGNORECASE),    # sql = "...".format(...)
    re.compile(r'(query|sql|stmt)\s*=\s*["\'][^"\']*%\s*', re.IGNORECASE),   # sql = "..." % ...
    re.compile(r'(query|sql|stmt)\s*=\s*"[^"]*"\s*\+\s*\w', re.IGNORECASE), # sql = "..." + var
]

# ORM-level SQLi: SQLAlchemy / Django filter() with string injection
_SQL_ORM_PATTERNS = [
    re.compile(r'filter\s*\(\s*["\'].*%', re.IGNORECASE),          # .filter("col = %s" % ...)
    re.compile(r'filter\s*\(\s*f["\']', re.IGNORECASE),            # .filter(f"col = {val}")
    re.compile(r'\.raw\s*\(\s*f["\']', re.IGNORECASE),             # .raw(f"SELECT...")
    re.compile(r'\.raw\s*\(\s*["\'][^"\']*%', re.IGNORECASE),      # .raw("SELECT..." % ...)
    re.compile(r'text\s*\(\s*f["\']', re.IGNORECASE),              # text(f"SELECT...")  SQLAlchemy
    re.compile(r'text\s*\(\s*["\'][^"\']*\+', re.IGNORECASE),      # text("SELECT..." + ...)
]

def check_cwe89(source: str) -> dict:
    has_exec       = bool(_SQL_EXEC.search(source))
    has_inline     = any(p.search(source) for p in _SQL_INLINE_PATTERNS)
    has_multiline  = any(p.search(source) for p in _SQL_MULTILINE_PATTERNS)
    has_orm        = any(p.search(source) for p in _SQL_ORM_PATTERNS)
    has_taint      = bool(TAINT_SOURCES.search(source))
    has_sql_kw     = bool(re.search(r'\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b', source, re.IGNORECASE))

    has_format = has_inline or has_multiline or has_orm

    # Confident: direct evidence of unsafe SQL construction (any method)
    confident = (
        (has_exec and has_inline) or          # inline format in execute()
        (has_exec and has_multiline) or        # variable built unsafely then executed
        has_orm or                             # ORM-level injection
        (has_sql_kw and has_taint and has_multiline)  # SQL keyword + taint + multiline build
    )
    plausible = has_exec or (has_sql_kw and has_taint)

    return {
        "has_sql_execute": has_exec,
        "has_inline_format": has_inline,
        "has_multiline_build": has_multiline,
        "has_orm_injection": has_orm,
        "has_unsafe_format": has_format,
        "has_taint_source": has_taint,
        "has_sql_keywords": has_sql_kw,
        "confident": confident,
        "plausible": plausible,
    }


# CWE-78: Command injection
_CMD_PATTERNS = [
    re.compile(r"\bos\s*\.\s*system\s*\("),
    re.compile(r"\bos\s*\.\s*popen\s*\("),
    re.compile(r"\bsubprocess\s*\.\s*(run|call|check_output|Popen)\s*\("),
    re.compile(r"\bcommands\s*\.\s*getoutput\s*\("),
    re.compile(r"\beval\s*\("),
    re.compile(r"\bexec\s*\("),
]
_SHELL_TRUE = re.compile(r"shell\s*=\s*True")

def check_cwe78(source: str) -> dict:
    has_cmd = any(p.search(source) for p in _CMD_PATTERNS)
    has_shell_true = bool(_SHELL_TRUE.search(source))
    has_taint = bool(TAINT_SOURCES.search(source))
    has_eval = bool(re.search(r'\beval\s*\(|\bexec\s*\(', source))
    confident = has_cmd and has_taint
    plausible = has_cmd or has_eval
    return {
        "has_cmd_call": has_cmd,
        "has_shell_true": has_shell_true,
        "has_taint_source": has_taint,
        "has_eval_exec": has_eval,
        "confident": confident,
        "plausible": plausible,
    }


# CWE-22: Path traversal
_PATH_PATTERNS = [
    re.compile(r"\bopen\s*\("),
    re.compile(r"\bsend_file\s*\("),
    re.compile(r"\bsend_from_directory\s*\("),
    re.compile(r"\bos\s*\.\s*path\s*\.\s*(join|abspath|realpath)\s*\("),
    re.compile(r"\bPathlib|Path\("),
]
_TRAVERSAL_HINT = re.compile(r"\.\./|%2e%2e|\\\\\.\\\\", re.IGNORECASE)

def check_cwe22(source: str) -> dict:
    has_file_op = any(p.search(source) for p in _PATH_PATTERNS)
    has_taint = bool(TAINT_SOURCES.search(source))
    has_traversal_hint = bool(_TRAVERSAL_HINT.search(source))
    confident = has_file_op and has_taint
    plausible = has_file_op or has_traversal_hint
    return {
        "has_file_operation": has_file_op,
        "has_taint_source": has_taint,
        "has_traversal_hint": has_traversal_hint,
        "confident": confident,
        "plausible": plausible,
    }


# CWE-502: Insecure deserialization
_DESER_PATTERNS = [
    re.compile(r"\bpickle\s*\.\s*loads?\s*\("),
    re.compile(r"\byaml\s*\.\s*load\s*\("),
    re.compile(r"\bjson\s*\.\s*loads?\s*\("),       # json is usually safe but flag for review
    re.compile(r"\bmarshal\s*\.\s*loads?\s*\("),
    re.compile(r"\bshelve\s*\."),
    re.compile(r"\bcPickle\s*\.\s*loads?\s*\("),
]
_SAFE_YAML = re.compile(r"yaml\.safe_load\s*\(")

def check_cwe502(source: str) -> dict:
    has_deser = any(p.search(source) for p in _DESER_PATTERNS)
    has_safe_yaml = bool(_SAFE_YAML.search(source))
    has_taint = bool(TAINT_SOURCES.search(source))
    # pickle + taint = definite; yaml.load (not safe_load) + taint = definite
    has_unsafe_yaml = bool(re.search(r"\byaml\s*\.\s*load\s*\(", source)) and not has_safe_yaml
    confident = (
        (bool(re.search(r"\bpickle\s*\.\s*loads?\s*\(", source)) and has_taint) or
        (has_unsafe_yaml and has_taint) or
        (bool(re.search(r"\bmarshal\s*\.\s*loads?\s*\(", source)) and has_taint)
    )
    plausible = has_deser
    return {
        "has_deserialization_call": has_deser,
        "has_unsafe_yaml": has_unsafe_yaml,
        "has_taint_source": has_taint,
        "has_safe_yaml": has_safe_yaml,
        "confident": confident,
        "plausible": plausible,
    }


CWE_CHECKERS = {
    "CWE-89":  check_cwe89,
    "CWE-78":  check_cwe78,
    "CWE-22":  check_cwe22,
    "CWE-502": check_cwe502,
}


# ---------------------------------------------------------------------------
# Structural checks
# ---------------------------------------------------------------------------

def structural_checks(source: str, meta: dict) -> dict:
    # 1. Valid Python syntax
    try:
        ast.parse(source)
        valid_syntax = True
    except SyntaxError as e:
        valid_syntax = False

    # 2. Flask import
    has_flask = bool(re.search(r"(from flask|import flask)", source, re.IGNORECASE))

    # 3. Not just a docstring / placeholder
    stripped = re.sub(r'"""[\s\S]*?"""', "", source)  # remove triple-quote strings
    stripped = re.sub(r"'''[\s\S]*?'''", "", stripped)
    stripped = re.sub(r"#.*", "", stripped)             # remove comments
    executable_lines = [l for l in stripped.splitlines() if l.strip()]
    has_executable_code = len(executable_lines) > 2

    # 4. Has Flask route handlers
    has_route = bool(re.search(r"@\w+\.(route|get|post|put|delete|patch)\s*\(", source))

    # 5. Has request.* (taint source)
    has_request = bool(TAINT_SOURCES.search(source))

    # 6. Appears to be an attack PoC (attacker script) vs. vulnerable server code
    attack_signals = [
        bool(re.search(r"\brequests\.(get|post|put)\s*\(", source)),  # uses requests lib (client)
        bool(re.search(r"\bsocket\.(connect|send)\s*\(", source)),
        bool(re.search(r"exploit|payload|target_url|victim", source, re.IGNORECASE)),
    ]
    is_likely_attack_poc = sum(attack_signals) >= 2

    return {
        "valid_syntax": valid_syntax,
        "has_flask_import": has_flask,
        "has_executable_code": has_executable_code,
        "has_route_handler": has_route,
        "has_request_taint": has_request,
        "is_likely_attack_poc": is_likely_attack_poc,
        "executable_line_count": len(executable_lines),
    }


# ---------------------------------------------------------------------------
# Overall verdict
# ---------------------------------------------------------------------------

STATUS_PASS    = "PASS"
STATUS_WARN    = "WARN"
STATUS_FAIL    = "FAIL"
STATUS_SKIPPED = "SKIPPED"   # secure samples (is_vulnerable=False) — CWE check skipped


def compute_verdict(meta: dict, structural: dict, cwe_check: Optional[dict]) -> tuple[str, list[str]]:
    issues: list[str] = []

    if not structural["valid_syntax"]:
        issues.append("invalid Python syntax")
    if not structural["has_executable_code"]:
        issues.append("no executable code (likely pure docstring/narrative)")
    if structural["is_likely_attack_poc"] and not structural["has_flask_import"]:
        issues.append("appears to be attacker PoC script, not vulnerable server code")

    is_vulnerable = meta.get("is_vulnerable", True)
    cwe = meta.get("cwe", "")

    if is_vulnerable and cwe and cwe_check:
        if not cwe_check["confident"] and not cwe_check["plausible"]:
            issues.append(f"CWE label {cwe} not supported by code patterns (false label?)")
        elif not cwe_check["confident"]:
            issues.append(f"CWE label {cwe} is plausible but not confirmed (weak signal)")
        if not cwe_check.get("has_taint_source", True):
            issues.append("no Flask request.* taint source found — may not be exploitable")
    elif is_vulnerable and not cwe:
        issues.append("is_vulnerable=True but no CWE assigned")

    if not issues:
        return STATUS_PASS, []
    # Distinguish warnings from hard failures
    hard_failures = [i for i in issues if "invalid" in i or "no executable" in i or "false label" in i]
    if hard_failures:
        return STATUS_FAIL, issues
    return STATUS_WARN, issues


# ---------------------------------------------------------------------------
# Main audit loop
# ---------------------------------------------------------------------------

@dataclass
class SampleResult:
    id: str
    source: str
    cwe: str
    vuln_type: str
    is_vulnerable: bool
    status: str
    issues: list[str] = field(default_factory=list)
    structural: dict = field(default_factory=dict)
    cwe_check: Optional[dict] = None


def audit_dataset(raw_dir: str) -> list[SampleResult]:
    results: list[SampleResult] = []
    raw = Path(raw_dir)

    meta_files = sorted(raw.glob("*.meta.json"))
    if not meta_files:
        print(f"[ERROR] No .meta.json files found in {raw_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"Auditing {len(meta_files)} samples in {raw_dir}…\n")

    for meta_path in meta_files:
        py_path = meta_path.with_suffix("").with_suffix(".py")

        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"  [SKIP] Cannot read {meta_path.name}: {e}", file=sys.stderr)
            continue

        if not py_path.exists():
            results.append(SampleResult(
                id=meta.get("id", meta_path.stem),
                source=meta.get("source", ""),
                cwe=meta.get("cwe", ""),
                vuln_type=meta.get("vuln_type", ""),
                is_vulnerable=meta.get("is_vulnerable", True),
                status=STATUS_FAIL,
                issues=["missing .py file"],
            ))
            continue

        try:
            source = py_path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            results.append(SampleResult(
                id=meta.get("id", meta_path.stem),
                source=meta.get("source", ""),
                cwe=meta.get("cwe", ""),
                vuln_type=meta.get("vuln_type", ""),
                is_vulnerable=meta.get("is_vulnerable", True),
                status=STATUS_FAIL,
                issues=[f"cannot read .py file: {e}"],
            ))
            continue

        struct = structural_checks(source, meta)

        is_vulnerable = meta.get("is_vulnerable", True)
        cwe = meta.get("cwe", "")
        checker = CWE_CHECKERS.get(cwe)

        if not is_vulnerable:
            # Secure/negative samples — CWE check is not expected
            cwe_result = None
            status = STATUS_SKIPPED
            issues: list[str] = []
            if not struct["valid_syntax"]:
                status = STATUS_FAIL
                issues.append("invalid Python syntax")
            elif not struct["has_executable_code"]:
                status = STATUS_WARN
                issues.append("no executable code")
        elif checker:
            cwe_result = checker(source)
            status, issues = compute_verdict(meta, struct, cwe_result)
        else:
            cwe_result = None
            status, issues = compute_verdict(meta, struct, None)

        results.append(SampleResult(
            id=meta.get("id", meta_path.stem),
            source=meta.get("source", ""),
            cwe=cwe,
            vuln_type=meta.get("vuln_type", ""),
            is_vulnerable=is_vulnerable,
            status=status,
            issues=issues,
            structural=struct,
            cwe_check=cwe_result,
        ))

    return results


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def print_summary(results: list[SampleResult]) -> None:
    total = len(results)
    by_status = {STATUS_PASS: 0, STATUS_WARN: 0, STATUS_FAIL: 0, STATUS_SKIPPED: 0}
    by_cwe: dict[str, dict] = {}
    by_source: dict[str, dict] = {}
    issue_freq: dict[str, int] = {}

    for r in results:
        by_status[r.status] = by_status.get(r.status, 0) + 1

        # Per-CWE breakdown
        cwe_key = r.cwe or "(no CWE)"
        if cwe_key not in by_cwe:
            by_cwe[cwe_key] = {STATUS_PASS: 0, STATUS_WARN: 0, STATUS_FAIL: 0, STATUS_SKIPPED: 0}
        by_cwe[cwe_key][r.status] = by_cwe[cwe_key].get(r.status, 0) + 1

        # Per-source breakdown
        src = r.source or "unknown"
        if src not in by_source:
            by_source[src] = {STATUS_PASS: 0, STATUS_WARN: 0, STATUS_FAIL: 0, STATUS_SKIPPED: 0}
        by_source[src][r.status] = by_source[src].get(r.status, 0) + 1

        for issue in r.issues:
            # Normalize issue text for frequency counting
            key = issue.split("(")[0].strip()
            issue_freq[key] = issue_freq.get(key, 0) + 1

    print("=" * 65)
    print("  DATASET HEALTH REPORT")
    print("=" * 65)
    print(f"\n  Total samples audited : {total}")
    print(f"  PASS    (clean)       : {by_status[STATUS_PASS]}")
    print(f"  WARN    (weak signal) : {by_status[STATUS_WARN]}")
    print(f"  FAIL    (bad sample)  : {by_status[STATUS_FAIL]}")
    print(f"  SKIPPED (secure/neg.) : {by_status[STATUS_SKIPPED]}")

    pass_rate = (by_status[STATUS_PASS] / total * 100) if total else 0
    print(f"\n  Pass rate (vulnerable samples only): {pass_rate:.1f}%")

    print("\n--- By CWE -------------------------------------------------------")
    print(f"  {'CWE':<12}  {'PASS':>6}  {'WARN':>6}  {'FAIL':>6}  {'SKIP':>6}")
    print(f"  {'-'*12}  {'-'*6}  {'-'*6}  {'-'*6}  {'-'*6}")
    for cwe in sorted(by_cwe):
        d = by_cwe[cwe]
        print(f"  {cwe:<12}  {d[STATUS_PASS]:>6}  {d[STATUS_WARN]:>6}  {d[STATUS_FAIL]:>6}  {d[STATUS_SKIPPED]:>6}")

    print("\n--- By Source ----------------------------------------------------")
    print(f"  {'Source':<18}  {'PASS':>6}  {'WARN':>6}  {'FAIL':>6}  {'SKIP':>6}")
    print(f"  {'-'*18}  {'-'*6}  {'-'*6}  {'-'*6}  {'-'*6}")
    for src in sorted(by_source):
        d = by_source[src]
        print(f"  {src:<18}  {d[STATUS_PASS]:>6}  {d[STATUS_WARN]:>6}  {d[STATUS_FAIL]:>6}  {d[STATUS_SKIPPED]:>6}")

    print("\n--- Top Issues ---------------------------------------------------")
    for issue, count in sorted(issue_freq.items(), key=lambda x: -x[1])[:10]:
        print(f"  {count:>5}x  {issue}")

    print()


def print_failures(results: list[SampleResult], show_warns: bool = False) -> None:
    fails = [r for r in results if r.status == STATUS_FAIL]
    warns = [r for r in results if r.status == STATUS_WARN] if show_warns else []

    if fails:
        print(f"\n--- FAILED samples ({len(fails)}) ---")
        for r in fails[:50]:   # cap at 50 to avoid flooding terminal
            print(f"  [{r.status}] {r.id}")
            for issue in r.issues:
                print(f"         - {issue}")

    if warns:
        print(f"\n--- WARNED samples ({len(warns)}) ---")
        for r in warns[:50]:
            print(f"  [{r.status}] {r.id}")
            for issue in r.issues:
                print(f"         - {issue}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Dataset health checker")
    p.add_argument("--raw-dir", default="data/raw", help="Path to raw samples directory")
    p.add_argument("--out", default=None, help="Save full JSON report to this path")
    p.add_argument("--show-warns", action="store_true", help="Print WARN samples too (default: FAIL only)")
    p.add_argument("--fail-fast", action="store_true", help="Exit with code 1 if any FAIL found")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    results = audit_dataset(args.raw_dir)

    print_summary(results)
    print_failures(results, show_warns=args.show_warns)

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        report = {
            "total": len(results),
            "summary": {
                "pass": sum(1 for r in results if r.status == STATUS_PASS),
                "warn": sum(1 for r in results if r.status == STATUS_WARN),
                "fail": sum(1 for r in results if r.status == STATUS_FAIL),
                "skipped": sum(1 for r in results if r.status == STATUS_SKIPPED),
            },
            "samples": [asdict(r) for r in results],
        }
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Full report saved to: {out_path}")

    if args.fail_fast and any(r.status == STATUS_FAIL for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
