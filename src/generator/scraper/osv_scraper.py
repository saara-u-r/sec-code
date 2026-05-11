"""
osv_scraper.py — Phase 1, CVE-linked source

Queries the OSV.dev REST API (Google's Open Source Vulnerability database)
for Python vulnerabilities matching our four target CWEs.

For each matching advisory this scraper:
  1. Extracts the GitHub "fix" commit SHA and repository URL
  2. Uses the GitHub API to get the parent commit (the vulnerable version)
     and the commit message
  3. Fetches the pre-fix file content (code_before) and post-fix content
     (code_after) for every changed .py file
  4. Saves code_before as the primary sample; code_after and commit_message
     are stored in metadata for Phase 2 (commit classifier) and Phase 5 (ML)

Scope: all Python web frameworks — Flask, Django, FastAPI, aiohttp, Tornado,
Bottle, Quart, Starlette. Removed Flask-only restriction per project revision.

OSV.dev API docs: https://google.github.io/osv.dev/
Rate limits: No auth required; be polite with 1s delays.
GitHub API limits: 30 req/min authenticated, set GITHUB_TOKEN in .env.
"""

import os
import re
import time

import requests
from dotenv import load_dotenv

from src.utils.cwe_taxonomy import BLOCKED_SOURCE_CWE, CWE_VULN_MAP
from src.utils.file_utils import build_meta, detect_framework, has_cwe_sink, hash_code, save_code_sample
from src.utils.logger import get_logger

load_dotenv()
logger = get_logger(__name__)

OSV_API = "https://api.osv.dev/v1"
GITHUB_API = "https://api.github.com"
TOKEN = os.getenv("GITHUB_TOKEN", "")

# Phase 2B (2026-05-11): expanded from web-only to broader Python coverage —
# CLI/devops, ML/scientific, stdlib-adjacent, crypto/auth. Adding packages
# here unlocks OSV advisories for CWEs that don't live in web code (798,
# 611, 330, 400, 77).
TARGET_PACKAGES = [
    # ── Web frameworks ───────────────────────────────────────────────
    "flask", "flask-login", "flask-sqlalchemy", "flask-restful", "flask-wtf",
    "django", "djangorestframework", "django-filter", "django-debug-toolbar",
    "fastapi", "starlette", "aiohttp", "tornado", "bottle", "quart",
    "werkzeug",

    # ── CLI / devops / sysadmin (CWE-78/77/798 targets) ──────────────
    "ansible", "ansible-core", "salt", "saltstack",
    "paramiko", "fabric", "invoke", "click", "typer",
    "supervisor", "celery", "psutil",

    # ── ML / scientific (CWE-502 via pickle, CWE-94 via eval) ────────
    "transformers", "torch", "tensorflow", "mlflow", "ray", "datasets",
    "huggingface-hub", "scikit-learn", "joblib",
    "numpy", "scipy", "pandas", "jupyter", "ipython", "notebook",

    # ── XML / serialization (CWE-611, CWE-502) ───────────────────────
    "lxml", "defusedxml", "xmltodict", "pyyaml", "ruamel.yaml",
    "msgpack", "pickle5",

    # ── Crypto / auth (CWE-798, CWE-330, CWE-295) ────────────────────
    "cryptography", "pycryptodome", "pyjwt", "authlib", "passlib",
    "python-jose", "oauthlib", "requests-oauthlib",

    # ── HTTP / SSRF surface (CWE-918, CWE-400) ───────────────────────
    "requests", "urllib3", "httpx", "httplib2", "feedparser",

    # ── Image / media (historic CVE hotspots) ────────────────────────
    "pillow", "imageio",

    # ── Cloud SDKs (often touch credentials) ─────────────────────────
    "boto3", "botocore", "google-cloud-storage", "azure-storage-blob",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _gh_headers() -> dict:
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if TOKEN:
        h["Authorization"] = f"Bearer {TOKEN}"
    return h


def _sleep(seconds: float) -> None:
    logger.debug(f"Sleeping {seconds:.1f}s…")
    time.sleep(seconds)


def _extract_cwe(vuln: dict) -> str | None:
    """Pull the first matching target CWE from an OSV entry."""
    # GHSA entries store CWEs under database_specific
    db_specific = vuln.get("database_specific", {})
    cwes = db_specific.get("cwe_ids", [])
    for cwe in cwes:
        if cwe in CWE_VULN_MAP:
            return cwe
    # Some entries list severity with CWE in the type field
    for sev in vuln.get("severity", []):
        cwe = sev.get("type", "")
        if cwe in CWE_VULN_MAP:
            return cwe
    return None


def _extract_fix_commits(vuln: dict) -> list[tuple[str, str]]:
    """
    Return a list of (repo_url, commit_sha) tuples for FIX-type references.
    Handles both github.com URLs and gitiles-style references.
    """
    results: list[tuple[str, str]] = []

    # Check references for GitHub commit links
    for ref in vuln.get("references", []):
        url = ref.get("url", "")
        # Match: https://github.com/{owner}/{repo}/commit/{sha}
        m = re.match(
            r"https://github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})",
            url, re.IGNORECASE,
        )
        if m:
            repo = m.group(1)
            sha = m.group(2)
            results.append((f"https://github.com/{repo}", sha))

    # Also check affected[].ranges for GIT type events
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            if rng.get("type") != "GIT":
                continue
            repo_url = rng.get("repo", "")
            if "github.com" not in repo_url:
                continue
            for event in rng.get("events", []):
                sha = event.get("fixed", "")
                if sha and len(sha) >= 7:
                    results.append((repo_url.rstrip("/"), sha))

    return results


def _github_repo_path(repo_url: str) -> str | None:
    """Extract '{owner}/{repo}' from a GitHub URL."""
    m = re.search(r"github\.com/([^/]+/[^/]+?)(?:\.git)?$", repo_url)
    return m.group(1) if m else None


def _get_commit_info(owner_repo: str, fix_sha: str) -> tuple[str | None, str]:
    """
    Return (parent_sha, commit_message) for fix_sha.
    parent_sha is the vulnerable state; commit_message is the fix description.
    """
    url = f"{GITHUB_API}/repos/{owner_repo}/commits/{fix_sha}"
    try:
        resp = requests.get(url, headers=_gh_headers(), timeout=15)
        if resp.status_code == 404:
            return None, ""
        if resp.status_code == 403:
            logger.warning("GitHub rate limit — sleeping 60s")
            _sleep(60)
            return None, ""
        resp.raise_for_status()
        data = resp.json()
        parents = data.get("parents", [])
        parent_sha = parents[0]["sha"] if parents else None
        commit_msg = data.get("commit", {}).get("message", "").strip()
        return parent_sha, commit_msg
    except Exception as e:
        logger.warning(f"Failed to get commit info for {owner_repo}@{fix_sha}: {e}")
        return None, ""


def _get_changed_py_files(owner_repo: str, fix_sha: str) -> list[str]:
    """Return the list of .py files changed in fix_sha."""
    url = f"{GITHUB_API}/repos/{owner_repo}/commits/{fix_sha}"
    try:
        resp = requests.get(url, headers=_gh_headers(), timeout=15)
        if resp.status_code != 200:
            return []
        files = resp.json().get("files", [])
        return [f["filename"] for f in files if f["filename"].endswith(".py")]
    except Exception as e:
        logger.warning(f"Failed to list files for {owner_repo}@{fix_sha}: {e}")
        return []


def _fetch_file_at_ref(owner_repo: str, file_path: str, ref: str) -> str | None:
    """Fetch the raw content of file_path at a given git ref."""
    # Use the raw content endpoint
    raw_url = f"https://raw.githubusercontent.com/{owner_repo}/{ref}/{file_path}"
    try:
        resp = requests.get(raw_url, headers=_gh_headers(), timeout=15)
        if resp.status_code == 200:
            return resp.text
    except Exception as e:
        logger.warning(f"Failed to fetch {raw_url}: {e}")
    return None


# ---------------------------------------------------------------------------
# OSV query
# ---------------------------------------------------------------------------

def query_osv_package(package: str, ecosystem: str = "PyPI") -> list[dict]:
    """Return all OSV vulnerabilities for a given package."""
    url = f"{OSV_API}/query"
    payload = {"package": {"name": package, "ecosystem": ecosystem}}
    try:
        resp = requests.post(url, json=payload, timeout=20)
        resp.raise_for_status()
        return resp.json().get("vulns", [])
    except Exception as e:
        logger.warning(f"OSV query failed for {package}: {e}")
        return []


def fetch_osv_vuln(vuln_id: str) -> dict | None:
    """Fetch the full OSV entry for a given vulnerability ID."""
    url = f"{OSV_API}/vulns/{vuln_id}"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        logger.warning(f"Failed to fetch OSV vuln {vuln_id}: {e}")
    return None


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

def run(output_dir: str = "data/raw") -> int:
    if not TOKEN:
        logger.warning(
            "GITHUB_TOKEN not set — GitHub API calls will be rate-limited severely. "
            "Add GITHUB_TOKEN to your .env file for much better results."
        )

    total = 0
    seen_hashes: set[str] = set()
    # Track which (repo, sha) pairs we already processed to avoid redundant API calls
    processed_commits: set[tuple[str, str]] = set()

    for package in TARGET_PACKAGES:
        logger.info(f"Querying OSV.dev for package: {package}")
        vulns = query_osv_package(package)
        logger.info(f"  → {len(vulns)} advisories found")
        _sleep(0.5)

        for vuln_stub in vulns:
            vuln_id = vuln_stub.get("id", "")

            # Fetch full entry to get CWE and commit details
            vuln = fetch_osv_vuln(vuln_id)
            if not vuln:
                continue
            _sleep(0.3)

            cwe = _extract_cwe(vuln)
            if not cwe:
                continue  # Not one of our target CWEs
            if ("osv", cwe) in BLOCKED_SOURCE_CWE:
                continue

            vuln_type = CWE_VULN_MAP[cwe]

            # Extract CVE alias if present
            cve_id = next(
                (a for a in vuln.get("aliases", []) if a.startswith("CVE-")),
                None,
            )

            fix_commits = _extract_fix_commits(vuln)
            if not fix_commits:
                logger.debug(f"No GitHub fix commits in {vuln_id} — skipping")
                continue

            for repo_url, fix_sha in fix_commits:
                owner_repo = _github_repo_path(repo_url)
                if not owner_repo:
                    continue

                commit_key = (owner_repo, fix_sha)
                if commit_key in processed_commits:
                    continue
                processed_commits.add(commit_key)

                # Single API call: get parent SHA + commit message together
                parent_sha, commit_msg = _get_commit_info(owner_repo, fix_sha)
                if not parent_sha:
                    continue
                _sleep(1.0 if TOKEN else 4.0)

                py_files = _get_changed_py_files(owner_repo, fix_sha)
                if not py_files:
                    continue
                _sleep(1.0 if TOKEN else 4.0)

                for file_path in py_files:
                    # Fetch vulnerable version (parent = before fix)
                    code_before = _fetch_file_at_ref(owner_repo, file_path, parent_sha)
                    if not code_before or not code_before.strip():
                        continue

                    # Phase 2B: replaced is_web_code() with sink-presence filter
                    # so non-web Python CWEs (798, 611, 330, 400) can be ingested.
                    sink_ok, _ = has_cwe_sink(code_before, cwe, file_path=file_path)
                    if not sink_ok:
                        logger.debug(
                            f"  Skipping sink-less {cwe}: {owner_repo}/{file_path}"
                        )
                        continue

                    # Fetch fixed version (code_after) for paired dataset
                    code_after = _fetch_file_at_ref(owner_repo, file_path, fix_sha) or ""

                    h = hash_code(code_before)
                    if h in seen_hashes:
                        continue
                    seen_hashes.add(h)

                    framework = detect_framework(code_before)

                    meta = build_meta(
                        {
                            "id":               f"osv_{vuln_type}_{h}",
                            "source":           "osv",
                            "osv_id":           vuln_id,
                            "cve_id":           cve_id,
                            "cwe":              cwe,
                            "vuln_type":        vuln_type,
                            "label_source":     "osv",
                            "label_confidence": "high",
                            "commit_message":   commit_msg,
                            "framework":        framework,
                            "repo":             owner_repo,
                            "file_path":        file_path,
                            "fix_commit":       fix_sha,
                            "vulnerable_commit": parent_sha,
                            "pair_id":          f"{fix_sha[:8]}_{file_path}",
                        },
                        code_before,
                        code_after,
                    )
                    save_code_sample(code_before, meta, output_dir)
                    total += 1

                    logger.info(
                        f"  Saved [{cwe}] {vuln_id} — "
                        f"{owner_repo}/{file_path}@{parent_sha[:8]} ({framework})"
                    )
                    _sleep(0.5)

    logger.info(f"osv_scraper finished — {total} samples saved to {output_dir}")
    return total
