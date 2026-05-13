"""
cwe_taxonomy.py — Single source of truth for CWE labels, sink patterns,
and per-CWE knowledge shared across all scrapers and the labeler.

Phase 2B (2026-05-11): extended from 7 web-skewed CWEs to 12.
Phase 2B re-scope (2026-05-13): narrowed to the 9 *sink-shaped Top-25
Python CWEs* — the set where a closed fix-pattern alphabet exists.
Phase 2B finalize (2026-05-13, evening): dropped CWE-798 to land at
exactly 10 labels (9 sink-shaped + safe) for the evaluation benchmark.
See PHASE_2B_DESIGN.md §1 and the Top-25 taxonomy analysis for rationale.

Sink-shaped Top-25 Python CWEs (active, the benchmark label set):
  CWE-79, CWE-89, CWE-22, CWE-78, CWE-94, CWE-434, CWE-502, CWE-918

Dropped 2026-05-13 (reversible via data/raw_rejected/ manifests + git):
  CWE-611 (XXE), CWE-330 (weak rand), CWE-400 (resource exhaustion)
    → not in MITRE Top-25.
  CWE-798 (hardcoded credentials)
    → Top-25 but yields only a 2-bucket alphabet (remove literal / move
      to vault), and all 29 samples came from a single static miner
      (single-source bias). Dropped to fit the 10-label evaluation cap.
  CWE-77 (improper neutralization of special elements — command inj)
    → MITRE parent of CWE-78. For Python the distinction is bureaucratic;
      both fire on the same sink set (os.system / subprocess shell=True /
      Popen). Merged into CWE-78 on 2026-05-13 via
      scripts/merge_cwe77_into_cwe78.py — all 9 prior CWE-77 samples
      relabeled in place.
  All retained in CWE_NAMES / SINK_PATTERNS for back-compat with already-
  saved samples; CWE_VULN_MAP entries removed so scrapers won't write
  new ones.

Structural Top-25 Python CWEs (deferred to Phase 2C):
  CWE-352, CWE-862, CWE-863, CWE-284, CWE-306, CWE-639, CWE-200
  These lack a closed-alphabet sink; verification-metadata-only.

What lives here:
  * CWE_VULN_MAP      — CWE-NNN  → snake_case vuln_type used everywhere
  * CWE_NAMES         — CWE-NNN  → human-readable name
  * TARGET_CWES       — set of CWE-NNN strings for the current dataset
  * SINK_PATTERNS     — CWE-NNN  → [re.Pattern, ...]  used by has_cwe_sink()

What does NOT live here:
  * Sink-presence helper functions   → file_utils.has_cwe_sink()
  * Path-level helpers (is_test_file)→ file_utils.is_test_file()
  * Config-driven CVSS defaults      → configs/config.yaml
"""

import re

# ---------------------------------------------------------------------------
# CWE → vuln_type mapping (the canonical names used in metadata)
# ---------------------------------------------------------------------------

CWE_VULN_MAP: dict[str, str] = {
    # Sink-shaped Top-25 Python CWEs — Phase 1 originals (web-focused)
    "CWE-89":  "sql_injection",
    "CWE-78":  "command_injection",
    "CWE-22":  "path_traversal",
    "CWE-79":  "cross_site_scripting",
    "CWE-94":  "code_injection",
    "CWE-918": "ssrf",
    "CWE-502": "insecure_deserialization",

    # Sink-shaped Top-25 Python CWEs — Phase 2B additions
    "CWE-434": "unrestricted_file_upload",
}

TARGET_CWES: set[str] = set(CWE_VULN_MAP.keys())

# Dropped 2026-05-13 — see header comment. Kept as a constant so future
# Phase 2C work can re-enable selectively without re-deriving the list.
# CWE-77 was merged into CWE-78 (not orphaned) — samples relabeled in
# place rather than discarded.
DEPRECATED_CWES: set[str] = {"CWE-611", "CWE-330", "CWE-400", "CWE-798", "CWE-77"}

# ---------------------------------------------------------------------------
# CWE → human-readable name (used by build_meta and reports)
# ---------------------------------------------------------------------------

CWE_NAMES: dict[str, str] = {
    # Active sink-shaped Top-25 Python CWEs
    "CWE-89":  "SQL Injection",
    "CWE-78":  "OS Command Injection",
    "CWE-22":  "Path Traversal",
    "CWE-79":  "Cross-site Scripting",
    "CWE-94":  "Code Injection",
    "CWE-918": "Server-Side Request Forgery",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-77":  "Improper Neutralization of Special Elements (Command Injection)",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    # Kept for backward-compat with prior schema / already-saved samples;
    # not active targets (see DEPRECATED_CWES above and prior schema entries).
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-611": "Improper Restriction of XML External Entity Reference",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-327": "Use of Broken or Risky Cryptographic Algorithm",
    "CWE-295": "Improper Certificate Validation",
}

# ---------------------------------------------------------------------------
# Sink-presence patterns — used by file_utils.has_cwe_sink()
# ---------------------------------------------------------------------------
#
# Each list is the minimal set of tokens that MUST appear in a file before
# we'll accept it as labeled for the corresponding CWE. The intent is to
# catch "commit-level noise" — files co-changed in a fix commit that don't
# actually contain the vulnerability pattern.
#
# Patterns are deliberately permissive — they detect the *category of sink*,
# not the *unsafe usage*. e.g. CWE-89's `.execute(` catches every DB call,
# including parameterized safe ones. That's fine: the question we're asking
# is "could this file plausibly contain a CWE-89 vulnerability?" not "is
# it definitely vulnerable?"
#
# Conservative bias: false negatives (real positives dropped) are acceptable;
# false positives (noise kept) are what we're trying to eliminate.

SINK_PATTERNS: dict[str, list[re.Pattern]] = {
    "CWE-89": [
        re.compile(r"\.execute(?:many|script)?\s*\(", re.IGNORECASE),
        re.compile(r"\btext\s*\(\s*['\"f]", re.IGNORECASE),     # sqlalchemy.text
        re.compile(r"\.raw\s*\(\s*['\"f]", re.IGNORECASE),      # Django ORM .raw()
        re.compile(r"\bSELECT\b.*\bFROM\b", re.IGNORECASE),     # inline SQL string
        re.compile(r"\b(INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b", re.IGNORECASE),
        re.compile(r"\bcursor\b", re.IGNORECASE),                # cursor variable use
        re.compile(r"\bdb\.\w+\s*\(", re.IGNORECASE),            # db.method() — custom wrappers (e.g. trape's db.sentences_victim)
    ],
    "CWE-79": [
        # Explicit escape-bypass sinks (high precision)
        re.compile(r"\|\s*safe\b"),
        re.compile(r"\bmark_safe\s*\(", re.IGNORECASE),
        re.compile(r"\bMarkup\s*\(", re.IGNORECASE),
        re.compile(r"\brender_template_string\s*\(", re.IGNORECASE),
        re.compile(r"\bautoescape\s*=\s*False", re.IGNORECASE),
        re.compile(r"\.innerHTML\b"),
        # Web framework + user input — XSS sinks are typically the *absence*
        # of escape(), so any web file touching request data is plausibly
        # involved in XSS. Spot-check of 5 rejected samples (2026-05-11)
        # showed 4 were real CVE-confirmed XSS the strict patterns missed.
        # Pair with CWES_REQUIRING_TEST_EXCLUSION to drop fixture noise.
        # Flask/Django request attrs:
        re.compile(r"\brequest\.(args|form|data|json|values|files|cookies|GET|POST)", re.IGNORECASE),
        # Starlette/FastAPI request attrs:
        re.compile(r"\brequest\.(query_params|path_params|headers|body)", re.IGNORECASE),
        re.compile(r"\brender_template\s*\(", re.IGNORECASE),
        re.compile(r"\brender\s*\(\s*request", re.IGNORECASE),    # Django render(request, ...)
        re.compile(r"\bHttpResponse\s*\(", re.IGNORECASE),
        re.compile(r"\bself\.write\s*\(", re.IGNORECASE),         # Tornado RequestHandler
        re.compile(r"\bweb\.Response\s*\(", re.IGNORECASE),       # aiohttp
        re.compile(r"\bfrom\s+twisted\b", re.IGNORECASE),         # Twisted web apps (any html sink)
        re.compile(r"\bhtml\.escape\s*\(", re.IGNORECASE),        # HTML escape calls indicate HTML rendering
    ],
    "CWE-78": [
        re.compile(r"\bos\.(system|popen|spawn[lpvP])\s*\(", re.IGNORECASE),
        re.compile(r"\bsubprocess\.\w+\s*\([^)]*shell\s*=\s*True", re.IGNORECASE | re.DOTALL),
        re.compile(r"\bcommands\.(getoutput|getstatusoutput)\s*\(", re.IGNORECASE),
        re.compile(r"\bPopen\s*\(", re.IGNORECASE),
    ],
    "CWE-77": [
        re.compile(r"\bos\.(system|popen|spawn[lpvP])\s*\(", re.IGNORECASE),
        re.compile(r"\bsubprocess\.\w+\s*\([^)]*shell\s*=\s*True", re.IGNORECASE | re.DOTALL),
        re.compile(r"\bparamiko\b.*exec_command", re.IGNORECASE | re.DOTALL),
        re.compile(r"\bfabric\.", re.IGNORECASE),
        re.compile(r"\binvoke\..*\.run\s*\(", re.IGNORECASE),
        re.compile(r"\bexecute_command\s*\(", re.IGNORECASE),
    ],
    "CWE-22": [
        re.compile(r"\bopen\s*\(", re.IGNORECASE),
        re.compile(r"\bsend_file\s*\(", re.IGNORECASE),
        re.compile(r"\bsend_from_directory\s*\(", re.IGNORECASE),
        re.compile(r"\bos\.path\.join\s*\(", re.IGNORECASE),
        re.compile(r"\bPath\s*\(", re.IGNORECASE),
        re.compile(r"\.\./\.\.", re.IGNORECASE),
    ],
    "CWE-918": [
        re.compile(r"\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(", re.IGNORECASE),
        re.compile(r"\burllib\.request\.urlopen\s*\(", re.IGNORECASE),
        re.compile(r"\burlopen\s*\(", re.IGNORECASE),
        re.compile(r"\bhttpx\.\w+\s*\(", re.IGNORECASE),
        re.compile(r"\baiohttp\.\w+", re.IGNORECASE),
        re.compile(r"\bClientSession\s*\(", re.IGNORECASE),
    ],
    "CWE-502": [
        re.compile(r"\bpickle\.loads?\s*\(", re.IGNORECASE),
        re.compile(r"\bcPickle\.loads?\s*\(", re.IGNORECASE),
        re.compile(r"\byaml\.load\s*\((?!.*safe_load)", re.IGNORECASE),
        re.compile(r"\byaml\.unsafe_load\s*\(", re.IGNORECASE),
        re.compile(r"\bmarshal\.loads?\s*\(", re.IGNORECASE),
        re.compile(r"\b__reduce__\b", re.IGNORECASE),
        re.compile(r"\bshelve\.", re.IGNORECASE),
        re.compile(r"\bjsonpickle\.", re.IGNORECASE),
    ],
    "CWE-94": [
        re.compile(r"\beval\s*\(", re.IGNORECASE),
        re.compile(r"\bexec\s*\(", re.IGNORECASE),
        re.compile(r"\bcompile\s*\(", re.IGNORECASE),
        re.compile(r"\b__import__\s*\(", re.IGNORECASE),
        re.compile(r"\bimportlib\.import_module\b", re.IGNORECASE),
    ],
    "CWE-798": [
        # All patterns require:
        #   1. Assignment form (`keyword = 'literal'`) — not just a bare
        #      variable name.  Old pattern matched `AWS_SECRET_ACCESS_KEY`
        #      anywhere in the file even when the assignment was to
        #      `os.environ.get(...)` (the secure pattern).
        #   2. Literal value in quotes — function calls like
        #      `os.environ.get(...)` don't start with `'` or `"`, so they
        #      can't match the quoted-value pattern.
        #   3. Sufficient character variety. Audit (2026-05-11) found that
        #      enum constants like `INVALID_PASSWORD = "invalid_password"`
        #      and config keys like `VMAX_PASSWORD = 'san_password'` were
        #      passing the old length-only check. Real credentials have at
        #      least one of: digit, uppercase letter, or special char.
        # The (?i:...) inline flag keeps the keyword case-insensitive while
        # leaving the variety check case-sensitive.
        # NOTE: no \b prefix on the keyword — `_` is a regex word char, so
        # \b between `_` and `P` doesn't fire (would miss DATABASE_PASSWORD).

        # password / passwd — 10+ chars with variety.
        # The 10-char minimum (up from 8) eliminates `PASSWORD = "Password"`
        # style UI-label false positives without losing real hardcoded
        # production secrets (which are almost always 10+ chars).
        re.compile(
            r"(?i:password|passwd)\s*=\s*"
            r"(['\"])"
            r"(?=[^'\"\s]{10,})"                         # value: 10+ chars, no quotes/ws
            r"(?=[^'\"\s]*[A-Z0-9!@#$%^&*+\-./()])"      # value contains variety
            r"[^'\"\s]+\1"
        ),
        # api_key — 16+ chars (real API keys are long)
        re.compile(
            r"(?i:api[_-]?key)\s*=\s*"
            r"['\"][A-Za-z0-9_\-\.]{16,}['\"]"
        ),
        # secret / secret_key — 12+ chars with variety
        re.compile(
            r"(?i:secret(?:_key)?)\s*=\s*"
            r"(['\"])"
            r"(?=[^'\"\s]{12,})"
            r"(?=[^'\"\s]*[A-Z0-9!@#$%^&*+\-./()])"
            r"[^'\"\s]+\1"
        ),
        # access/auth/bearer/refresh tokens — 20+ chars
        re.compile(
            r"(?i:(?:access|auth|bearer|refresh)[_-]?token)\s*=\s*"
            r"['\"][A-Za-z0-9_\-\.]{20,}['\"]"
        ),
        # AWS keys — literal value, 16+ credential-shaped chars
        re.compile(
            r"(?i:AWS_(?:SECRET|ACCESS)[_-]?KEY(?:_ID)?)\s*=\s*"
            r"['\"][A-Za-z0-9/+=]{16,}['\"]"
        ),
        # PEM private key — always real if literal
        re.compile(
            r"(?i:private[_-]?key)\s*=\s*['\"]-----BEGIN"
        ),
        # client_secret — 12+ chars with variety
        re.compile(
            r"(?i:client[_-]?secret)\s*=\s*"
            r"(['\"])"
            r"(?=[^'\"\s]{12,})"
            r"(?=[^'\"\s]*[A-Z0-9!@#$%^&*+\-./()])"
            r"[^'\"\s]+\1"
        ),
    ],
    "CWE-434": [
        # Unrestricted file upload — the sink is the persist-to-disk call on
        # an HTTP-received file. The vulnerability is the *absence* of an
        # allowlist / mime / magic-byte check around the sink, which we
        # can't detect by regex alone — so we accept any persist-to-disk
        # call as a candidate and rely on CVE-confirmed sources for label
        # trust. Static mining for CWE-434 would be too noisy without
        # taint tracking; nvd_targeted / OSV / GHSA are the safer sources.
        #
        # Flask / werkzeug sink form:  request.files['x'].save(...)
        re.compile(r"\brequest\.files\b", re.IGNORECASE),
        re.compile(r"\bFileStorage\b", re.IGNORECASE),         # werkzeug
        re.compile(r"\bsave\s*\(\s*os\.path\.join", re.IGNORECASE),
        # Django sink form:  request.FILES['x'] then FileField / .save()
        re.compile(r"\brequest\.FILES\b", re.IGNORECASE),
        re.compile(r"\bFileField\s*\(", re.IGNORECASE),
        re.compile(r"\bImageField\s*\(", re.IGNORECASE),
        # FastAPI / Starlette sink form
        re.compile(r"\bUploadFile\b"),
        re.compile(r"\bawait\s+\w+\.read\s*\(", re.IGNORECASE),  # UploadFile.read()
        # The defenses we look for proximity to (not as positive evidence,
        # but to help downstream tools verify the bucket): secure_filename,
        # ALLOWED_EXTENSIONS, magic.from_buffer.
        re.compile(r"\bsecure_filename\s*\(", re.IGNORECASE),
        re.compile(r"\bALLOWED_EXTENSIONS\b"),
    ],
}

# ---------------------------------------------------------------------------
# CWEs that require a security-context co-occurrence check (not just a sink)
# ---------------------------------------------------------------------------
# For these CWEs, the sink alone is too noisy — the caller must also
# verify a security keyword appears within ±10 lines of the sink (see
# file_utils.has_security_context_near).
#
# Currently empty: CWE-798 and CWE-330 both used this gate but were
# deprecated 2026-05-13. The has_security_context_near() helper is kept
# in file_utils for Phase 2C revival.

CWES_REQUIRING_SECURITY_CONTEXT: set[str] = set()

# ---------------------------------------------------------------------------
# CWEs where test/fixture files are common false positives
# ---------------------------------------------------------------------------
# For these CWEs, files matching is_test_file() are rejected even if they
# would otherwise pass the sink check. Reasons:
#   * CWE-798: test fixtures contain dummy credentials.
#   * CWE-79:  Django/pytest XSS test cases import `request` and use template
#              rendering as part of the test scaffolding, not as a vuln site.

CWES_REQUIRING_TEST_EXCLUSION: set[str] = {"CWE-79"}

# ---------------------------------------------------------------------------
# Sources known to produce commit-level mislabels — dropped at the loader.
# ---------------------------------------------------------------------------
# Format: (source_name, cwe) → drop reason. Audit findings from 2026-05-11
# (see runs/phase3_v1/AUDIT.md) confirmed vudenc CWE-94 is 93% noise.

BLOCKED_SOURCE_CWE: dict[tuple[str, str], str] = {
    ("vudenc", "CWE-94"): "AUDIT 2026-05-11: 14/15 files lack eval/exec/compile sinks; commit-level mislabels.",
}
