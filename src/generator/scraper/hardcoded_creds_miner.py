"""
hardcoded_creds_miner.py — Phase 2B, CWE-798 static miner

Unlike the other scrapers (which index by CVE then mine commits), this
miner walks a curated list of open-source Python repos directly and
looks for *literal hardcoded credentials* in non-test code. The output
is a set of CWE-798 samples plus paired "safe" versions where the
credential value is replaced with `os.environ[...]`, giving the
classifier paired before/after examples for free.

Why static mining is appropriate here:
  • CWE-798 is one of the few CWEs detectable purely from a literal
    pattern in the file — no taint analysis needed.
  • Few CVEs are filed against hardcoded credentials in OSS libraries
    (most are reported/rotated quietly), so CVE-indexed scrapers
    under-cover this class.
  • The Phase 2B sink filter (`has_cwe_sink("CWE-798", ...)`) already
    encodes the right pattern set, including test-file exclusion and
    security-context co-occurrence. We reuse it directly.

Repo selection criteria:
  • Open-source, accessible without auth.
  • Mix of web apps, devops tooling, ML examples, and CLI utilities.
  • Skip huge libraries (transformers, tensorflow) — they're well-
    reviewed and their main code rarely contains literal creds.
  • Skip private/proprietary projects (obviously).
  • Bias toward older / less-maintained projects where hardcoded
    creds historically slipped in.

Disk usage: each shallow clone is ~5–50 MB. Total budget ~500 MB peak
across all clones; clones are deleted after scanning.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from src.utils.cwe_taxonomy import CWE_VULN_MAP
from src.utils.file_utils import (
    build_meta,
    detect_framework,
    has_cwe_sink,
    hash_code,
    is_test_file,
    save_code_sample,
)
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Curated repo list. Add/remove freely — there's no formal contract.
# Each entry is a GitHub URL; shallow-clone is used so repo size is bounded.
TARGET_REPOS: list[str] = [
    # ── Tutorials / example apps (high hit rate historically) ───────
    "https://github.com/realpython/flask-skeleton",
    "https://github.com/miguelgrinberg/flasky",
    "https://github.com/miguelgrinberg/microblog",
    # django/django-docker — removed 2026-05-11, repo 404s

    # ── E-commerce / CMS Python apps ────────────────────────────────
    "https://github.com/saleor/saleor",
    "https://github.com/wagtail/bakerydemo",
    "https://github.com/django-oscar/django-oscar",
    "https://github.com/django-cms/django-cms",

    # ── Deliberately vulnerable / security-training apps (high yield) ─
    "https://github.com/we45/DVPWA",
    "https://github.com/adeyosemanputra/pygoat",

    # ── OpenStack ecosystem (config-heavy, credentials common) ──────
    "https://github.com/openstack/cinder",
    "https://github.com/openstack/keystone",
    "https://github.com/openstack/nova",
    "https://github.com/openstack/glance",

    # ── Devops / CLI tooling ────────────────────────────────────────
    "https://github.com/ansible-community/molecule",
    "https://github.com/getsentry/sentry-python",
    "https://github.com/fabric/fabric",
    "https://github.com/paramiko/paramiko",
    "https://github.com/celery/celery",

    # ── ML / data examples (not libraries) ──────────────────────────
    "https://github.com/huggingface/notebooks",
    "https://github.com/mlflow/mlflow-example",
    "https://github.com/apache/superset",

    # ── Auth / OAuth implementations ────────────────────────────────
    "https://github.com/authlib/example-oauth2-server",
    "https://github.com/lepture/example-oauth2-server",

    # ── Mozilla and educational platforms ───────────────────────────
    "https://github.com/mozilla/kuma",
    "https://github.com/python-discord/site",
]


# ---------------------------------------------------------------------------
# Cred redaction — turn `password = "hunter2"` into `password = os.environ[...]`
# ---------------------------------------------------------------------------

# Common env var name fallbacks by keyword.
_ENV_VAR_HINT: dict[str, str] = {
    "password":     "PASSWORD",
    "passwd":       "PASSWORD",
    "secret":       "SECRET",
    "api_key":      "API_KEY",
    "apikey":       "API_KEY",
    "access_token": "ACCESS_TOKEN",
    "auth_token":   "AUTH_TOKEN",
    "token":        "TOKEN",
    "client_secret": "CLIENT_SECRET",
    "private_key":  "PRIVATE_KEY",
    "aws_secret":   "AWS_SECRET_ACCESS_KEY",
    "aws_access":   "AWS_ACCESS_KEY_ID",
}


import re

# Generic credential-assignment regex — captures the keyword (for env-var
# hinting) and the literal value (to be replaced). No \b anchor because
# the same boundary problem hits here as in the sink patterns (`_` is a
# regex word char, so `\b` between `_` and a letter doesn't fire — would
# miss DATABASE_PASSWORD etc.).
_CRED_ASSIGNMENT_RE = re.compile(
    r"(?P<key>password|passwd|secret(?:_key)?|api[_-]?key|"
    r"access[_-]?token|auth[_-]?token|client[_-]?secret|"
    r"private[_-]?key|aws_(?:secret|access)[_-]?key)"
    r"(?P<eq>\s*=\s*)"
    r"(?P<val>['\"][^'\"\s][^'\"]{5,}['\"])",
    re.IGNORECASE,
)


def redact_credential(code: str, sink_pattern_text: str | None) -> str:
    """
    Best-effort redaction. Find the first literal credential assignment in
    `code` and replace its value with `os.environ['<ENV_NAME>']`. If no
    assignment is found, returns the original code unchanged (safer than
    producing a corrupted code_after).
    """
    m = _CRED_ASSIGNMENT_RE.search(code)
    if not m:
        return code

    key = m.group("key").lower()
    env_name = "SECRET"
    for hint, name in _ENV_VAR_HINT.items():
        if hint in key:
            env_name = name
            break

    # Splice in the os.environ reference in place of the literal value
    redacted = code[:m.start("val")] + f"os.environ['{env_name}']" + code[m.end("val"):]

    # Ensure `import os` is present somewhere in the first ~20 lines
    head = redacted.splitlines()[:20]
    if not any(line.strip() == "import os" or line.strip().startswith("import os,") for line in head):
        lines = redacted.splitlines()
        insert_at = 0
        for i, line in enumerate(lines[:20]):
            if line.startswith("import ") or line.startswith("from "):
                insert_at = i + 1
        lines.insert(insert_at, "import os")
        redacted = "\n".join(lines)

    return redacted


# ---------------------------------------------------------------------------
# Clone helper
# ---------------------------------------------------------------------------

def _shallow_clone(repo_url: str, dest: str) -> bool:
    """Run a shallow `git clone --depth 1`. Returns True on success."""
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", repo_url, dest],
            capture_output=True,
            timeout=180,
        )
        if result.returncode != 0:
            logger.warning(f"  clone failed for {repo_url}: {result.stderr.decode()[:200]}")
            return False
        return True
    except subprocess.TimeoutExpired:
        logger.warning(f"  clone timed out for {repo_url}")
        return False
    except Exception as e:
        logger.warning(f"  clone error for {repo_url}: {e}")
        return False


# ---------------------------------------------------------------------------
# Per-repo scan
# ---------------------------------------------------------------------------

def _scan_repo(
    repo_dir: str,
    repo_url: str,
    seen_hashes: set[str],
    output_dir: str,
    max_file_bytes: int = 100_000,
) -> int:
    """Walk one cloned repo and save CWE-798 samples. Return count saved."""
    saved = 0
    cwe = "CWE-798"
    vuln_type = CWE_VULN_MAP[cwe]
    repo_path = Path(repo_dir)
    repo_name = repo_url.rstrip("/").split("/")[-1]

    for py_path in repo_path.rglob("*.py"):
        # Skip large files (likely vendored/minified)
        try:
            if py_path.stat().st_size > max_file_bytes:
                continue
        except OSError:
            continue

        # Skip test files (caught by has_cwe_sink too, but earlier is faster)
        rel_path = str(py_path.relative_to(repo_path))
        if is_test_file(rel_path):
            continue

        try:
            code_before = py_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if not code_before or len(code_before) < 50:
            continue

        sink_ok, sink_pat = has_cwe_sink(code_before, cwe, file_path=rel_path)
        if not sink_ok:
            continue

        h = hash_code(code_before)
        if h in seen_hashes:
            continue
        seen_hashes.add(h)

        code_after = redact_credential(code_before, sink_pat)
        framework = detect_framework(code_before)

        meta = build_meta(
            {
                "id":               f"hardcoded_creds_{vuln_type}_{h}",
                "source":           "hardcoded_creds_miner",
                "cwe":              cwe,
                "vuln_type":        vuln_type,
                "label_source":     "static_mining",
                "label_confidence": "medium",   # heuristic, not CVE-confirmed
                "framework":        framework,
                "repo":             repo_url,
                "file_path":        rel_path,
            },
            code_before,
            code_after,
        )
        save_code_sample(code_before, meta, output_dir)
        saved += 1
        logger.info(f"  [{cwe}] {repo_name}/{rel_path} (matched {sink_pat!r})")

    return saved


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(output_dir: str = "data/raw") -> int:
    # Sanity-check git availability up front
    if shutil.which("git") is None:
        logger.error("git not found in PATH — install git and rerun")
        return 0

    seen_hashes: set[str] = set()
    total = 0

    for repo_url in TARGET_REPOS:
        logger.info(f"Cloning {repo_url} …")
        with tempfile.TemporaryDirectory(prefix="creds_miner_") as td:
            target = os.path.join(td, "clone")
            if not _shallow_clone(repo_url, target):
                continue
            saved = _scan_repo(target, repo_url, seen_hashes, output_dir)
            total += saved
            logger.info(f"  → {saved} CWE-798 samples from {repo_url}")
        # Polite delay between clones
        time.sleep(0.5)

    logger.info(f"hardcoded_creds_miner finished — {total} samples saved to {output_dir}")
    return total
