"""
pypa_scraper.py — Phase 1, CVE-linked source

Scrapes the PyPA Advisory Database (https://github.com/pypa/advisory-database),
a curated YAML repository of Python package security advisories maintained by
the Python Packaging Authority.

Why PyPA?
  - Python-specific: every advisory is for a PyPI package
  - Structured YAML with CVE IDs, CWE IDs, and fix commit references
  - Complements OSV and GHSA with different advisory coverage

Pipeline:
  1. Shallow-clone pypa/advisory-database (cached after first run)
  2. Walk advisories/pypa/**/*.yaml
  3. Filter for entries with a target CWE and a GitHub fix commit
  4. Fetch code_before (parent commit) and code_after (fix commit)
  5. Fetch commit message for Phase 2 classifier training
  6. Save with metadata (cvss_score left null for Phase 3 NVD enricher)
"""

import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml
from dotenv import load_dotenv

from src.utils.file_utils import build_meta, detect_framework, hash_code, is_web_code, save_code_sample
from src.utils.logger import get_logger

load_dotenv()
logger = get_logger(__name__)

GITHUB_API = "https://api.github.com"
TOKEN = os.getenv("GITHUB_TOKEN", "")

PYPA_REPO_URL = "https://github.com/pypa/advisory-database"
PYPA_LOCAL_DIR = "data/pypa_advisory_db"

CWE_VULN_MAP = {
    "CWE-89":  "sql_injection",
    "CWE-78":  "command_injection",
    "CWE-22":  "path_traversal",
    "CWE-502": "insecure_deserialization",
}

_COMMIT_RE = re.compile(
    r"https://github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})",
    re.IGNORECASE,
)


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


def _clone_or_update_pypa_db(local_dir: str) -> bool:
    """Shallow-clone pypa/advisory-database or pull latest if already cloned."""
    dest = Path(local_dir)
    if (dest / ".git").exists():
        logger.info(f"PyPA advisory DB already cloned at {local_dir} — pulling latest")
        result = subprocess.run(
            ["git", "-C", local_dir, "pull", "--ff-only"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            logger.warning(f"git pull failed: {result.stderr[:200]}")
        return True

    logger.info(f"Cloning PyPA advisory database to {local_dir}…")
    dest.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["git", "clone", "--depth=1", PYPA_REPO_URL, local_dir],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        logger.error(f"git clone failed: {result.stderr[:300]}")
        return False
    logger.info("PyPA advisory database cloned")
    return True


def _extract_cwe_from_advisory(data: dict) -> str | None:
    """Extract the first target CWE from a PyPA YAML advisory."""
    # CWEs may be in database_specific or severity fields
    db_specific = data.get("database_specific", {}) or {}
    for cwe in db_specific.get("cwe_ids", []):
        if cwe in CWE_VULN_MAP:
            return cwe
    for sev in data.get("severity", []):
        cwe = sev.get("type", "")
        if cwe in CWE_VULN_MAP:
            return cwe
    return None


def _extract_fix_commits(data: dict) -> list[tuple[str, str]]:
    """Return (owner/repo, sha) pairs from references and affected ranges."""
    results: list[tuple[str, str]] = []

    for ref in data.get("references", []):
        url = ref.get("url", "") if isinstance(ref, dict) else str(ref)
        m = _COMMIT_RE.match(url)
        if m:
            results.append((m.group(1), m.group(2)))

    for affected in data.get("affected", []):
        for rng in affected.get("ranges", []):
            if rng.get("type") != "GIT":
                continue
            repo_url = rng.get("repo", "")
            if "github.com" not in repo_url:
                continue
            m = re.search(r"github\.com/([^/]+/[^/]+?)(?:\.git)?$", repo_url)
            if not m:
                continue
            owner_repo = m.group(1)
            for event in rng.get("events", []):
                sha = event.get("fixed", "")
                if sha and len(sha) >= 7:
                    results.append((owner_repo, sha))

    return results


def _get_commit_info(owner_repo: str, sha: str) -> tuple[str | None, str]:
    """Return (parent_sha, commit_message) for the given commit."""
    url = f"{GITHUB_API}/repos/{owner_repo}/commits/{sha}"
    try:
        resp = requests.get(url, headers=_gh_headers(), timeout=15)
        if resp.status_code == 403:
            logger.warning("GitHub rate limit — sleeping 60s")
            _sleep(60)
            return None, ""
        if resp.status_code != 200:
            return None, ""
        data = resp.json()
        parents = data.get("parents", [])
        parent_sha = parents[0]["sha"] if parents else None
        commit_msg = data.get("commit", {}).get("message", "").strip()
        return parent_sha, commit_msg
    except Exception as e:
        logger.warning(f"Failed to get commit info for {owner_repo}@{sha}: {e}")
        return None, ""


def _get_changed_py_files(owner_repo: str, sha: str) -> list[str]:
    url = f"{GITHUB_API}/repos/{owner_repo}/commits/{sha}"
    try:
        resp = requests.get(url, headers=_gh_headers(), timeout=15)
        if resp.status_code != 200:
            return []
        return [f["filename"] for f in resp.json().get("files", [])
                if f["filename"].endswith(".py")]
    except Exception as e:
        logger.warning(f"Failed to list files for {owner_repo}@{sha}: {e}")
        return []


def _fetch_file_at_ref(owner_repo: str, file_path: str, ref: str) -> str | None:
    url = f"https://raw.githubusercontent.com/{owner_repo}/{ref}/{file_path}"
    try:
        resp = requests.get(url, headers=_gh_headers(), timeout=15)
        return resp.text if resp.status_code == 200 else None
    except Exception as e:
        logger.warning(f"Failed to fetch {url}: {e}")
        return None


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

def run(output_dir: str = "data/raw") -> int:
    if not _clone_or_update_pypa_db(PYPA_LOCAL_DIR):
        return 0

    if not TOKEN:
        logger.warning(
            "GITHUB_TOKEN not set — PyPA scraper will hit GitHub rate limits quickly."
        )

    total = 0
    seen_hashes: set[str] = set()
    processed_commits: set[tuple[str, str]] = set()
    delay = 1.5 if TOKEN else 6.0

    advisory_dir = Path(PYPA_LOCAL_DIR) / "advisories" / "pypa"
    if not advisory_dir.exists():
        logger.error(f"Advisory directory not found: {advisory_dir}")
        return 0

    yaml_files = list(advisory_dir.rglob("*.yaml"))
    logger.info(f"PyPA: {len(yaml_files)} advisory YAML files found")

    for yaml_path in yaml_files:
        try:
            with open(yaml_path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            logger.debug(f"Failed to parse {yaml_path}: {e}")
            continue

        if not data:
            continue

        cwe = _extract_cwe_from_advisory(data)
        if not cwe:
            continue

        vuln_type = CWE_VULN_MAP[cwe]
        pysec_id = data.get("id", str(yaml_path.stem))
        cve_id = next(
            (a for a in data.get("aliases", []) if a.startswith("CVE-")),
            None,
        )

        fix_commits = _extract_fix_commits(data)
        if not fix_commits:
            continue

        for owner_repo, fix_sha in fix_commits:
            commit_key = (owner_repo, fix_sha)
            if commit_key in processed_commits:
                continue
            processed_commits.add(commit_key)

            parent_sha, commit_msg = _get_commit_info(owner_repo, fix_sha)
            if not parent_sha:
                continue
            _sleep(delay)

            py_files = _get_changed_py_files(owner_repo, fix_sha)
            if not py_files:
                continue
            _sleep(delay)

            for file_path in py_files:
                code_before = _fetch_file_at_ref(owner_repo, file_path, parent_sha)
                if not code_before or not code_before.strip():
                    continue

                if not is_web_code(code_before):
                    continue

                code_after = _fetch_file_at_ref(owner_repo, file_path, fix_sha) or ""

                h = hash_code(code_before)
                if h in seen_hashes:
                    continue
                seen_hashes.add(h)

                framework = detect_framework(code_before)

                meta = build_meta(
                    {
                        "id":               f"pypa_{vuln_type}_{h}",
                        "source":           "pypa",
                        "pysec_id":         pysec_id,
                        "cve_id":           cve_id,
                        "cwe":              cwe,
                        "vuln_type":        vuln_type,
                        "label_source":     "pypa",
                        "label_confidence": "medium",
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
                    f"  Saved [{cwe}] {pysec_id} — "
                    f"{owner_repo}/{file_path} ({framework})"
                )
                _sleep(0.5)

    logger.info(f"pypa_scraper finished — {total} samples saved to {output_dir}")
    return total
