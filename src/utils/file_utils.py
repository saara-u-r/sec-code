import ast
import json
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "2.0"

# Human-readable names for the CWEs we track
CWE_NAMES: dict[str, str] = {
    "CWE-89":  "SQL Injection",
    "CWE-78":  "OS Command Injection",
    "CWE-22":  "Path Traversal",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-327": "Use of Broken or Risky Cryptographic Algorithm",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-295": "Improper Certificate Validation",
    "CWE-798": "Use of Hard-coded Credentials",
}

# CVSS vector component expansion maps
_AV  = {"N": "NETWORK", "A": "ADJACENT", "L": "LOCAL", "P": "PHYSICAL"}
_AC  = {"L": "LOW", "H": "HIGH"}
_PR  = {"N": "NONE", "L": "LOW", "H": "HIGH"}
_UI  = {"N": "NONE", "R": "REQUIRED"}
_S   = {"U": "UNCHANGED", "C": "CHANGED"}
_CIA = {"N": "NONE", "L": "LOW", "H": "HIGH"}


# ---------------------------------------------------------------------------
# Framework detection (shared by all scrapers)
# ---------------------------------------------------------------------------

_FRAMEWORK_PATTERNS: dict[str, re.Pattern] = {
    "flask":     re.compile(r"(from flask\b|import flask\b)", re.IGNORECASE),
    "django":    re.compile(r"(from django\b|import django\b|django\.http|django\.views)", re.IGNORECASE),
    "fastapi":   re.compile(r"(from fastapi\b|import fastapi\b)", re.IGNORECASE),
    "starlette": re.compile(r"(from starlette\b|import starlette\b)", re.IGNORECASE),
    "aiohttp":   re.compile(r"(from aiohttp\b|import aiohttp\b)", re.IGNORECASE),
    "tornado":   re.compile(r"(from tornado\b|import tornado\b)", re.IGNORECASE),
    "bottle":    re.compile(r"(from bottle\b|import bottle\b)", re.IGNORECASE),
    "quart":     re.compile(r"(from quart\b|import quart\b)", re.IGNORECASE),
}

_REQUEST_TAINT = re.compile(
    r"(request\.(args|form|data|json|values|files|cookies|headers|GET|POST)"
    r"|HttpRequest|web\.Request|self\.request)",
    re.IGNORECASE,
)


def detect_framework(code: str) -> str:
    """Return the first recognized web framework found in the code, or 'unknown'."""
    for name, pat in _FRAMEWORK_PATTERNS.items():
        if pat.search(code):
            return name
    return "unknown"


def is_web_code(code: str) -> bool:
    """Return True if the file appears to be application-level web code."""
    for pat in _FRAMEWORK_PATTERNS.values():
        if pat.search(code):
            return True
    return bool(_REQUEST_TAINT.search(code))


# ---------------------------------------------------------------------------
# Flask AST helpers — kept for backward compatibility with health_check / cleaner
# ---------------------------------------------------------------------------

def is_flask_file(source: str) -> bool:
    return "from flask" in source.lower() or "import flask" in source.lower()


def extract_flask_routes(source: str) -> list[str]:
    """
    Return one snippet per @app.route / @bp.route decorated function.
    Returns an empty list if the source has no routes or won't parse.
    Unlike repo_cloner's original version, there is NO full-file fallback —
    callers that want the whole file can check for an empty return themselves.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    lines = source.splitlines()
    routes: list[str] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            try:
                decorator_str = ast.unparse(decorator)
            except Exception:
                continue
            if ".route(" in decorator_str or decorator_str.startswith("route("):
                deco_start = min(d.lineno for d in node.decorator_list) - 1
                snippet = "\n".join(lines[deco_start : node.end_lineno])
                routes.append(snippet)
                break

    return routes


# ---------------------------------------------------------------------------
# Vulnerability pattern detection (shared by all scrapers)
# ---------------------------------------------------------------------------

_VULN_PATTERNS: dict[str, list[re.Pattern]] = {
    "sql_injection": [
        re.compile(r'execute\s*\(\s*f["\']', re.IGNORECASE),
        re.compile(r'execute\s*\(.*?[+%].*?request', re.IGNORECASE | re.DOTALL),
        re.compile(r'execute\s*\(.*?\.format\s*\(', re.IGNORECASE | re.DOTALL),
        re.compile(r'(SELECT|INSERT|UPDATE|DELETE).*?[+%].*?request', re.IGNORECASE | re.DOTALL),
        re.compile(r'text\s*\(\s*f["\'].*?(SELECT|INSERT|UPDATE|DELETE)', re.IGNORECASE | re.DOTALL),
        re.compile(r'text\s*\(.*?(SELECT|INSERT|UPDATE|DELETE).*?[+%\{]', re.IGNORECASE | re.DOTALL),
    ],
    "command_injection": [
        re.compile(r'os\.(system|popen)\s*\(', re.IGNORECASE),
        re.compile(r'subprocess\.(run|call|check_call|check_output|Popen)\s*\(.*?shell\s*=\s*True', re.IGNORECASE | re.DOTALL),
        re.compile(r'eval\s*\(\s*request', re.IGNORECASE),
        re.compile(r'exec\s*\(\s*request', re.IGNORECASE),
    ],
    "path_traversal": [
        re.compile(r'open\s*\(.*?request', re.IGNORECASE | re.DOTALL),
        re.compile(r'send_file\s*\(.*?request', re.IGNORECASE | re.DOTALL),
        re.compile(r'os\.path\.join\s*\(.*?request', re.IGNORECASE | re.DOTALL),
        re.compile(r'send_from_directory\s*\(.*?request', re.IGNORECASE | re.DOTALL),
        re.compile(r'Path\s*\(.*?request', re.IGNORECASE | re.DOTALL),
    ],
    "insecure_deserialization": [
        re.compile(r'pickle\.loads?\s*\(', re.IGNORECASE),
        re.compile(r'yaml\.load\s*\(\s*(?!.*safe_load)', re.IGNORECASE),
        re.compile(r'marshal\.loads?\s*\(', re.IGNORECASE),
    ],
}

# Patterns that indicate a route is using the SAFE version of a pattern.
# Used to label secure samples from github_scraper.
_SECURE_PATTERNS: dict[str, list[re.Pattern]] = {
    "sql_injection": [
        re.compile(r'execute\s*\(\s*["\'].*?["\'],\s*\(', re.IGNORECASE),        # execute("SELECT ?", (val,))
        re.compile(r'execute\s*\(\s*["\'].*?%s["\'],', re.IGNORECASE),            # execute("SELECT %s", ...)
        re.compile(r'filter_by\s*\(', re.IGNORECASE),                             # ORM
        re.compile(r'filter\s*\(.*?==', re.IGNORECASE),                           # ORM filter
    ],
    "command_injection": [
        re.compile(r'shlex\.quote\s*\(', re.IGNORECASE),
        re.compile(r'subprocess\.(run|call|Popen)\s*\(\s*\[', re.IGNORECASE),    # list args, no shell=True
    ],
    "path_traversal": [
        re.compile(r'secure_filename\s*\(', re.IGNORECASE),
        re.compile(r'safe_join\s*\(', re.IGNORECASE),
    ],
    "insecure_deserialization": [
        re.compile(r'yaml\.safe_load\s*\(', re.IGNORECASE),
        re.compile(r'json\.loads?\s*\(.*?request', re.IGNORECASE | re.DOTALL),
    ],
}

_TAINT_SOURCE = re.compile(
    r"request\s*\.\s*(args|form|data|json|values|files|cookies|headers|GET|POST)",
    re.IGNORECASE,
)


def detect_vuln_type(snippet: str) -> str | None:
    """Return the first matching vulnerability type in a snippet, or None."""
    for vuln_type, patterns in _VULN_PATTERNS.items():
        if any(p.search(snippet) for p in patterns):
            return vuln_type
    return None


def has_taint_source(snippet: str) -> bool:
    """Return True if the snippet reads from user-supplied request data."""
    return bool(_TAINT_SOURCE.search(snippet))


def is_secure_sample(snippet: str, vuln_type: str) -> bool:
    """
    Return True if the snippet shows the SAFE pattern for vuln_type AND
    does NOT contain the corresponding vulnerable pattern.
    Requires a taint source so the snippet is actually handling user input.
    """
    if not has_taint_source(snippet):
        return False
    if detect_vuln_type(snippet) is not None:
        return False   # has a vulnerable pattern — not safe
    secure_pats = _SECURE_PATTERNS.get(vuln_type, [])
    return any(p.search(snippet) for p in secure_pats)


# ---------------------------------------------------------------------------
# CVSS vector parser
# ---------------------------------------------------------------------------

def parse_cvss_vector(vector: str | None) -> dict:
    """
    Parse a CVSS v3 vector string into individual component fields.
    Returns a dict of all cvss_* sub-metric fields (all None if vector is absent).
    Example input: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    """
    empty = {
        "cvss_version": None, "cvss_vector": vector,
        "cvss_attack_vector": None, "cvss_attack_complexity": None,
        "cvss_privileges_required": None, "cvss_user_interaction": None,
        "cvss_scope": None, "cvss_confidentiality": None,
        "cvss_integrity": None, "cvss_availability": None,
    }
    if not vector:
        return empty
    try:
        parts = vector.split("/")
        # First part is "CVSS:3.1" or "CVSS:3.0"
        version = parts[0].split(":")[1] if ":" in parts[0] else None
        lookup = {p.split(":")[0]: p.split(":")[1] for p in parts[1:] if ":" in p}
        return {
            "cvss_version":             version,
            "cvss_vector":              vector,
            "cvss_attack_vector":       _AV.get(lookup.get("AV", ""), None),
            "cvss_attack_complexity":   _AC.get(lookup.get("AC", ""), None),
            "cvss_privileges_required": _PR.get(lookup.get("PR", ""), None),
            "cvss_user_interaction":    _UI.get(lookup.get("UI", ""), None),
            "cvss_scope":               _S.get( lookup.get("S",  ""), None),
            "cvss_confidentiality":     _CIA.get(lookup.get("C", ""), None),
            "cvss_integrity":           _CIA.get(lookup.get("I", ""), None),
            "cvss_availability":        _CIA.get(lookup.get("A", ""), None),
        }
    except Exception:
        return empty


# ---------------------------------------------------------------------------
# Code quality signals
# ---------------------------------------------------------------------------

def compute_code_signals(code_before: str, code_after: str = "") -> dict:
    """Compute quality and structural signals from code_before/code_after."""
    def _loc(code: str) -> int:
        return len([l for l in code.splitlines() if l.strip()])

    try:
        ast.parse(code_before)
        syntax_valid = True
    except SyntaxError:
        syntax_valid = False

    return {
        "loc_before":       _loc(code_before),
        "loc_after":        _loc(code_after) if code_after else 0,
        "syntax_valid":     syntax_valid,
        "has_taint_source": has_taint_source(code_before),
        "is_web_code":      is_web_code(code_before),
    }


# ---------------------------------------------------------------------------
# Canonical metadata builder — single source of truth for the JSON schema
# ---------------------------------------------------------------------------

def build_meta(fields: dict, code_before: str, code_after: str = "") -> dict:
    """
    Build a complete, schema-versioned metadata dict from scraper-supplied fields.
    Computes quality signals, fills pipeline-state defaults, and ensures every
    sample from every scraper has exactly the same set of keys.

    Scrapers pass what they know in `fields`; everything else gets a typed default.
    """
    cwe = fields.get("cwe", "")
    signals = compute_code_signals(code_before, code_after)

    return {
        # ── Identity ──────────────────────────────────────────────────────
        "_schema_version":  SCHEMA_VERSION,
        "id":               fields["id"],
        "source":           fields["source"],
        "scraped_at":       datetime.now(timezone.utc).isoformat(),

        # ── Advisory IDs ──────────────────────────────────────────────────
        "cve_id":           fields.get("cve_id"),
        "ghsa_id":          fields.get("ghsa_id"),
        "osv_id":           fields.get("osv_id"),
        "pysec_id":         fields.get("pysec_id"),

        # ── Vulnerability label ───────────────────────────────────────────
        "cwe":              cwe,
        "cwe_name":         CWE_NAMES.get(cwe),
        "vuln_type":        fields.get("vuln_type"),
        "label_source":     fields.get("label_source", "advisory"),
        "label_confidence": fields.get("label_confidence", "medium"),

        # ── CVSS severity gradient ────────────────────────────────────────
        "cvss_score":               fields.get("cvss_score"),
        "cvss_severity":            fields.get("cvss_severity"),
        "cvss_version":             fields.get("cvss_version"),
        "cvss_vector":              fields.get("cvss_vector"),
        "cvss_attack_vector":       fields.get("cvss_attack_vector"),
        "cvss_attack_complexity":   fields.get("cvss_attack_complexity"),
        "cvss_privileges_required": fields.get("cvss_privileges_required"),
        "cvss_user_interaction":    fields.get("cvss_user_interaction"),
        "cvss_scope":               fields.get("cvss_scope"),
        "cvss_confidentiality":     fields.get("cvss_confidentiality"),
        "cvss_integrity":           fields.get("cvss_integrity"),
        "cvss_availability":        fields.get("cvss_availability"),
        "cvss_source":              fields.get("cvss_source"),

        # ── Git / commit provenance ───────────────────────────────────────
        "repo":               fields.get("repo"),
        "file_path":          fields.get("file_path"),
        "fix_commit":         fields.get("fix_commit"),
        "vulnerable_commit":  fields.get("vulnerable_commit"),
        "commit_message":     fields.get("commit_message", ""),
        "commit_date":        fields.get("commit_date"),
        "commit_author":      None,       # intentionally omitted — PII

        # ── Code payload ─────────────────────────────────────────────────
        "code_before":  code_before,
        "code_after":   code_after,

        # ── Code quality signals (auto-computed) ─────────────────────────
        "framework":        fields.get("framework", "unknown"),
        "language":         "python",
        "loc_before":       signals["loc_before"],
        "loc_after":        signals["loc_after"],
        "syntax_valid":     signals["syntax_valid"],
        "has_taint_source": signals["has_taint_source"],
        "is_web_code":      signals["is_web_code"],

        # ── Dataset management ────────────────────────────────────────────
        "content_hash": hash_code(code_before),
        "pair_id":      fields.get("pair_id"),

        # ── Pipeline state (populated by later phases) ────────────────────
        "classifier_cwe":        None,    # Phase 2
        "classifier_confidence": None,    # Phase 2
        "nvd_enriched":          False,   # Phase 3
        "split":                 None,    # Phase 4
    }


# ---------------------------------------------------------------------------
# Core I/O helpers
# ---------------------------------------------------------------------------

def save_code_sample(code: str, meta: dict, output_dir: str) -> str:
    """
    Save a code sample to both the local file system and MongoDB Atlas.

    File system: {output_dir}/{id}.py  +  {output_dir}/{id}.meta.json
    MongoDB:     vulnerability_samples collection (upsert on content_hash)

    MongoDB write is best-effort — if MONGODB_URI is not set or the connection
    fails, the file system write still succeeds and a warning is logged.
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    sample_id = meta["id"]
    code_path = Path(output_dir) / f"{sample_id}.py"
    meta_path = Path(output_dir) / f"{sample_id}.meta.json"

    code_path.write_text(code, encoding="utf-8")
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    # Dual-write to MongoDB (no-op if MONGODB_URI not configured)
    from src.utils.mongo_writer import upsert_sample
    upsert_sample(meta)

    return str(code_path)


def hash_code(code: str) -> str:
    """Return a short SHA-256 hash of the code string for deduplication."""
    return hashlib.sha256(code.encode()).hexdigest()[:16]


def load_meta(meta_path: str) -> dict:
    with open(meta_path) as f:
        return json.load(f)
