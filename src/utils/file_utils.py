import ast
import json
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path

from src.utils.cwe_taxonomy import (
    CWE_NAMES,
    CWES_REQUIRING_REQUEST_PROXIMITY,
    CWES_REQUIRING_SECURITY_CONTEXT,
    CWES_REQUIRING_TEST_EXCLUSION,
    SINK_PATTERNS,
)

# Schema 2.1 (2026-05-11): adds has_cwe_sink + sink_pattern auto-computed
# fields used by Phase 2B's pre-ingest quality filter. Earlier samples on
# disk lack these fields; readers should default to None.
SCHEMA_VERSION = "3.0"

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


# ---------------------------------------------------------------------------
# Phase 2B — sink-presence quality filter (pre-ingest)
# ---------------------------------------------------------------------------

# Security-context keywords used by has_security_context_near() — for CWE-798
# / CWE-330 the file must mention at least one of these within ±10 lines of
# the sink match.
#
# Why some terms have \b and others don't: in regex `_` is a word char, so
# `\btoken` does NOT match `access_token` (the boundary between `_` and `t`
# is word-word). For compound-identifier-friendly keywords like `password`,
# `secret`, `encrypt` we deliberately omit \b so `DATABASE_PASSWORD`,
# `decrypted_data` all match. \b is reserved for short terms that embed in
# unrelated words (`auth` → `author`, `sign` → `assignment`/`design`).
#
# 2026-05-12 spot-check fallout (after first proximity-filter rerun, on the
# 30 surviving CWE-330 samples):
#   * `token(?!iz)`         — NLP tokenizer/tokenize/tokenized triggered many
#                             ML-pipeline FPs (sentiment_analyzer, seq2seq).
#   * dropped `salt`        — Saltstack repos contain `salt '*' command`
#                             docstring examples on every page; `\bsalt\b`
#                             also matched the software name, not crypto.
#   * dropped `hash`        — caused the openstack/swift FP via `local_hash`.
#   * dropped `secure`      — too broad (`make sure`, `securely`).
#   * dropped `account`     — collides with `accounting`, `acct`.
#   * dropped `role`        — too short; matches `roles=[]` config noise.
#   * narrowed `sign`       — `signin/signup/signing/signed/signature` only.
#   * narrowed `auth`       — must be `auth` as a word or followed by
#                             n/z/orize/enticate/orization (excludes `author`).
_SECURITY_CONTEXT = re.compile(
    r"(\bauth(?:n|z|orize|enticate|orization|enticated)?\b|"
    r"password|passwd|credential|session|"
    r"token(?!iz)|"  # exclude tokenizer/tokenize/tokenized (NLP)
    r"\blog(?:in|out)\b|\bsign(?:in|up|ed|ing|ature|er)\b|"
    r"secret|verify|hmac|jwt|"
    r"oauth|saml|ldap|api[_-]?key|csrf|nonce|salt|"
    r"encrypt|decrypt|cipher|permission)",
    re.IGNORECASE,
)

# Comment + string-literal stripper. Used to remove docstring URLs, prose
# (`"Guess my secret number"`), and shell-style examples (`# salt '*' ...`)
# from the security-context window — those contribute lexical co-occurrence
# but not semantic auth/crypto use.
_STRING_LITERAL = re.compile(r"(\"[^\"\n]*\"|'[^'\n]*')")
_LINE_COMMENT = re.compile(r"#.*$")
# Triple-quoted docstrings (`"""..."""` / `'''...'''`). Saltstack and openstack
# heavily use multi-line `salt '*' command` and `keystone-manage` examples in
# docstrings; those would otherwise leak Saltstack/keystone software names
# into the context window. We blank the contents but keep newlines so the
# sink character offsets in the original `code` remain valid for splitlines().
_TRIPLE_QUOTED = re.compile(r'(\"{3}.*?\"{3}|\'{3}.*?\'{3})', re.DOTALL)


def _blank_keep_newlines(s: str) -> str:
    """Replace every non-newline char with a space — used to neutralize a
    multi-line region without shifting line numbers."""
    return "".join(c if c == "\n" else " " for c in s)

# Lines that are pure imports / from-imports contribute identifiers but not
# semantic use, so a security keyword in an import line is not evidence that
# the nearby sink is in a security context. (e.g. `from foo import EncryptedType`
# 8 lines above `random.choices(...)` in superset/utils/mock_data.py).
_IMPORT_LINE = re.compile(r"^\s*(?:from\s+\S+\s+)?import\s")

# Bandit suppression comments that developers add when intentionally using
# weak randomness (or other flagged patterns) in non-security code paths.
# If a sink line carries one of these, the dev has explicitly marked the
# call as a non-issue — treat it as not-a-CWE-330. S311 is bandit's
# weak-randomness rule; nosec is the broader suppression.
_SUPPRESSED_SINK = re.compile(r"#\s*(noqa\s*:\s*S311|nosec\b)", re.IGNORECASE)

# Test/example file detector — paths that should never count as production
# credential leaks (CWE-798). Matches typical Python test/example layouts.
_TEST_PATH = re.compile(
    r"(^|/)(tests?|test_[^/]+|[^/]+_test|examples?|docs?|fixtures?|"
    r"benchmarks?|samples?|demo|conftest\.py$)/",
    re.IGNORECASE,
)


def is_test_file(file_path: str | None) -> bool:
    """Return True if file_path looks like a test fixture / example / doc.
    Used to exclude false-positive credential leaks for CWE-798."""
    if not file_path:
        return False
    return bool(_TEST_PATH.search(file_path)) or (
        Path(file_path).name.startswith("test_")
        or Path(file_path).name.endswith("_test.py")
        or Path(file_path).name == "conftest.py"
    )


# HTTP-request taint sources used by has_request_near() — for CWE-22 the
# sink must be in the same neighborhood as a tainted-input reference,
# not just anywhere in the file. Test fixtures with hardcoded paths and
# static-string code don't have these references and so won't pass.
_REQUEST_TAINT_NEAR = re.compile(
    r"\brequest\.(args|form|data|json|values|files|cookies|headers|GET|POST"
    r"|query_params|path_params|body)\b"
    r"|\bHttpRequest\b|\bweb\.Request\b|\bself\.request\b"
    r"|\bawait\s+\w+\.read\s*\(",
    re.IGNORECASE,
)


def has_request_near(
    code: str, sink_offset: int, window: int = 20
) -> bool:
    """Return True if a tainted-request reference appears within `window`
    lines of the sink offset. Comments and docstrings are stripped before
    the check so prose mentioning `request.args` doesn't count as a real
    taint flow.

    Window of 20 lines (vs 10 for security-context) reflects that
    file-access vulnerabilities often have intermediate utility logic
    between the request read and the sink (validation, normalization,
    path construction)."""
    code = _TRIPLE_QUOTED.sub(lambda m: _blank_keep_newlines(m.group(0)), code)
    sink_line = code.count("\n", 0, sink_offset) + 1
    lines = code.splitlines()
    start = max(0, sink_line - window - 1)
    end = min(len(lines), sink_line + window)
    cleaned = []
    for ln in lines[start:end]:
        ln = _LINE_COMMENT.sub("", ln)
        cleaned.append(ln)
    return bool(_REQUEST_TAINT_NEAR.search("\n".join(cleaned)))


def _strip_comments_for_match(code: str) -> str:
    """Blank out line comments and triple-quoted docstrings so sink regex
    doesn't match prose. Keep newlines so character offsets / line
    positions in returned matches remain valid against the original code.

    Used by has_cwe_sink to suppress documentation-style FPs surfaced in
    the 2026-05-13 audit (e.g. `# pickle.loads is unsafe`,
    `# Use it like this: requests.get(...)`, jsonpickle docs)."""
    code = _TRIPLE_QUOTED.sub(lambda m: _blank_keep_newlines(m.group(0)), code)
    lines = code.splitlines(keepends=True)
    out = []
    for ln in lines:
        # Strip everything from the first # not inside a string literal.
        # Approximation: drop content after # at the end of any line that
        # isn't inside a string. Simple heuristic; misses # inside strings
        # but that's acceptable — sink regexes don't typically match #-
        # prefixed prose anyway when string literals stay intact.
        idx = -1
        in_str = None
        i = 0
        while i < len(ln):
            c = ln[i]
            if in_str:
                if c == "\\":
                    i += 2; continue
                if c == in_str:
                    in_str = None
            elif c in "\"'":
                in_str = c
            elif c == "#":
                idx = i; break
            i += 1
        if idx >= 0:
            # Replace the comment portion with spaces, preserve newline
            keep_newline = "\n" if ln.endswith("\n") else ""
            out.append(ln[:idx] + " " * (len(ln) - idx - len(keep_newline)) + keep_newline)
        else:
            out.append(ln)
    return "".join(out)


def has_security_context_near(
    code: str, sink_offset: int, window: int = 10
) -> bool:
    """Return True if a security-context keyword appears within `window` lines
    of the sink's character offset in `code`, ignoring pure import lines.

    The 2026-05-11 CWE-330 audit found that a file-wide context check fires
    on unrelated co-occurrences — e.g. `random.randint(0, 9)` for replication
    jitter passed because the word `auth` appeared 200 lines away in an
    unrelated function. Restricting the context window to ±10 lines around
    the sink, and skipping import lines (which contribute identifiers but
    not semantic use), keeps the check meaningful."""
    # Blank triple-quoted docstrings first, preserving newlines so offsets
    # stay valid. Saltstack and OpenStack ship CLI examples like
    # `salt '*' state.apply` inside docstrings, which would otherwise inject
    # the software name as a fake "salt" context match.
    code = _TRIPLE_QUOTED.sub(lambda m: _blank_keep_newlines(m.group(0)), code)
    sink_line = code.count("\n", 0, sink_offset) + 1
    lines = code.splitlines()
    start = max(0, sink_line - window - 1)
    end = min(len(lines), sink_line + window)
    cleaned = []
    for ln in lines[start:end]:
        if _IMPORT_LINE.match(ln):
            continue
        ln = _LINE_COMMENT.sub("", ln)
        ln = _STRING_LITERAL.sub('""', ln)
        cleaned.append(ln)
    return bool(_SECURITY_CONTEXT.search("\n".join(cleaned)))


def sink_was_modified(
    code_before: str,
    code_after: str,
    cwe: str,
) -> tuple[bool | None, str | None]:
    """Return ``(modified, evidence_line)`` for the sink-line-changed filter.

    The premise: for a sample to be a real CWE-XXX positive, the fix
    commit must have *changed the sink*. If `pickle.loads(data)` exists
    identically in both versions of the file, the CVE fixed something
    else and this is a co-changed-file mislabel.

    Returns:
      * ``(True, line)``  — at least one sink line in ``code_before`` does
        NOT appear in ``code_after`` (removed or altered). The line is
        returned as audit evidence.
      * ``(False, None)`` — all sink lines in ``code_before`` are still
        present verbatim in ``code_after``. The sink was untouched —
        likely commit-level noise. Drop.
      * ``(None, None)``  — ``code_after`` is empty or the CWE has no
        sink patterns. Caller decides whether to keep or drop.

    Comparison is line-level after stripping comments / docstrings and
    normalizing whitespace, so reformat-only edits don't count as real
    changes.

    Phase 2B audit (2026-05-13) introduced this filter to address the
    fundamental limitation of CVE-fix-derived labels: the labeled
    "vulnerable" file isn't necessarily the actual sink site.
    """
    patterns = SINK_PATTERNS.get(cwe)
    if not patterns:
        return None, None
    if not code_after or not code_after.strip():
        return None, None

    def _sink_lines(code: str) -> set[str]:
        stripped = _strip_comments_for_match(code)
        out: set[str] = set()
        for ln in stripped.splitlines():
            norm = " ".join(ln.split())
            if not norm:
                continue
            for p in patterns:
                if p.search(ln):
                    out.add(norm)
                    break
        return out

    before_sinks = _sink_lines(code_before)
    after_sinks = _sink_lines(code_after)

    if not before_sinks:
        # No sink lines in `code_before` — shouldn't happen if has_cwe_sink
        # already passed, but be defensive. Treat as "cannot determine".
        return None, None

    removed_or_changed = before_sinks - after_sinks
    if removed_or_changed:
        return True, next(iter(removed_or_changed))
    return False, None


def has_cwe_sink(
    code: str,
    cwe: str,
    *,
    file_path: str | None = None,
) -> tuple[bool, str | None]:
    """
    Return (passes_filter, matched_pattern_or_none).

    A sample passes the sink-presence filter if:
      1. At least one pattern in SINK_PATTERNS[cwe] matches `code`.
         Comments and docstrings are stripped before matching to suppress
         documentation-style FPs (audit 2026-05-13).
      2. For CWE-798 only: file_path does NOT look like a test/example file.
      3. For CWES_REQUIRING_SECURITY_CONTEXT: a security keyword appears
         within ±10 lines of the sink match (originally for CWE-798/CWE-330;
         now empty set after both were deprecated).
      4. For CWES_REQUIRING_REQUEST_PROXIMITY (CWE-22): a request-taint
         reference appears within ±20 lines of the sink (audit 2026-05-13
         found 80% FP rate without this; mostly test fixtures with static
         paths).

    If `cwe` has no defined sink patterns (e.g. unknown CWE), returns
    (True, None) — i.e. we don't filter what we can't validate.
    """
    patterns = SINK_PATTERNS.get(cwe)
    if not patterns:
        return True, None

    if cwe in CWES_REQUIRING_TEST_EXCLUSION and is_test_file(file_path):
        return False, None

    # Strip comments/docstrings before sink matching. Offsets in the
    # stripped code align with the original because _strip_comments_for_match
    # preserves newline positions (it blanks comments to spaces).
    match_code = _strip_comments_for_match(code)

    needs_security_context = cwe in CWES_REQUIRING_SECURITY_CONTEXT
    needs_request_proximity = cwe in CWES_REQUIRING_REQUEST_PROXIMITY

    for p in patterns:
        for m in p.finditer(match_code):
            if needs_security_context:
                # Skip sinks the developer explicitly suppressed (#noqa:S311,
                # #nosec) — these are intentional non-security uses.
                line_start = code.rfind("\n", 0, m.start()) + 1
                line_end = code.find("\n", m.start())
                if line_end == -1:
                    line_end = len(code)
                if _SUPPRESSED_SINK.search(code[line_start:line_end]):
                    continue
                if not has_security_context_near(code, m.start()):
                    continue
            if needs_request_proximity:
                if not has_request_near(code, m.start()):
                    continue
            return True, p.pattern

    return False, None


# ---------------------------------------------------------------------------

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

def compute_code_signals(
    code_before: str,
    code_after: str = "",
    *,
    cwe: str | None = None,
    file_path: str | None = None,
) -> dict:
    """Compute quality and structural signals from code_before/code_after."""
    def _loc(code: str) -> int:
        return len([line for line in code.splitlines() if line.strip()])

    try:
        ast.parse(code_before)
        syntax_valid = True
    except SyntaxError:
        syntax_valid = False

    sink_ok, sink_pat = (None, None)
    if cwe:
        sink_ok, sink_pat = has_cwe_sink(code_before, cwe, file_path=file_path)

    return {
        "loc_before":       _loc(code_before),
        "loc_after":        _loc(code_after) if code_after else 0,
        "syntax_valid":     syntax_valid,
        "has_taint_source": has_taint_source(code_before),
        "is_web_code":      is_web_code(code_before),
        "has_cwe_sink":     sink_ok,
        "sink_pattern":     sink_pat,
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
    signals = compute_code_signals(
        code_before,
        code_after,
        cwe=cwe or None,
        file_path=fields.get("file_path"),
    )

    return {
        # ── Identity ──────────────────────────────────────────────────────
        "_schema_version":  SCHEMA_VERSION,
        "id":               fields["id"],
        "source":           fields["source"],

        # ── Advisory IDs ──────────────────────────────────────────────────
        "cve_id":           fields.get("cve_id"),
        "ghsa_id":          fields.get("ghsa_id"),

        # ── Vulnerability label ───────────────────────────────────────────
        "cwe":              cwe,
        "label_source":     fields.get("label_source", "advisory"),
        "label_confidence": fields.get("label_confidence", "medium"),

        # ── CVSS severity (vector encodes the 8 base metrics) ─────────────
        "cvss_score":       fields.get("cvss_score"),
        "cvss_severity":    fields.get("cvss_severity"),
        "cvss_version":     fields.get("cvss_version"),
        "cvss_vector":      fields.get("cvss_vector"),

        # ── Git / commit provenance ───────────────────────────────────────
        "repo":         fields.get("repo"),
        "file_path":    fields.get("file_path"),
        "fix_commit":   fields.get("fix_commit"),

        # ── Code payload ─────────────────────────────────────────────────
        "code_before":  code_before,
        "code_after":   code_after,

        # ── Code quality signals ─────────────────────────────────────────
        "framework":    fields.get("framework", "unknown"),
        "sink_pattern": signals["sink_pattern"],

        # ── Dataset management ────────────────────────────────────────────
        "content_hash": hash_code(code_before),
        "pair_id":      fields.get("pair_id"),

        # ── Pipeline state ────────────────────────────────────────────────
        "nvd_enriched": False,   # Phase 3
        "split":        None,    # Phase 4 (Phase 2 in current numbering)

        # ── Phase 2.5 — hard-negative provenance ─────────────────────────
        "is_hard_negative":        fields.get("is_hard_negative", False),
        "parent_sample_id":        fields.get("parent_sample_id"),
        "sanitization_transform":  fields.get("sanitization_transform"),
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
