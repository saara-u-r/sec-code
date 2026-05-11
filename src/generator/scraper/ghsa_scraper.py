"""
ghsa_scraper.py — Phase 1, CVE-linked source

Scrapes GitHub Security Advisories (GHSA) via the GitHub REST API for Python
vulnerabilities matching our four target CWEs.

Advantages over OSV:
  - CVSS score is returned directly in the advisory (no NVD call needed)
  - Different CVE coverage than OSV — broader combined dataset
  - Structured cwes[] array with CWE ID and name

For each matching advisory this scraper:
  1. Pages through /advisories?ecosystem=pip
  2. Filters for target CWEs
  3. Extracts GitHub fix commit from references or affected.ranges
  4. Fetches code_before (parent commit) and code_after (fix commit)
  5. Fetches the commit message for Phase 2 classifier training
  6. Saves with CVSS score included directly (no enrichment step needed)

GitHub REST API docs: https://docs.github.com/en/rest/security-advisories
Rate limits: 30 req/min authenticated. Set GITHUB_TOKEN in .env.
"""

import os
import re
import time

import requests
from dotenv import load_dotenv

from src.utils.cwe_taxonomy import BLOCKED_SOURCE_CWE, CWE_VULN_MAP
from src.utils.file_utils import (
    build_meta, detect_framework, has_cwe_sink, hash_code,
    parse_cvss_vector, save_code_sample,
)
from src.utils.logger import get_logger

load_dotenv()
logger = get_logger(__name__)

GITHUB_API = "https://api.github.com"
TOKEN = os.getenv("GITHUB_TOKEN", "")

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


def _extract_cwe(advisory: dict) -> str | None:
    """Return the first target CWE from an advisory's cwes[] array."""
    for entry in advisory.get("cwes", []):
        cwe_id = entry.get("cwe_id", "")
        if cwe_id in CWE_VULN_MAP:
            return cwe_id
    return None


def _extract_cvss(advisory: dict) -> tuple[float | None, str | None]:
    """Return (cvss_score, cvss_vector_string) from a GHSA advisory."""
    cvss = advisory.get("cvss", {}) or {}
    score = cvss.get("score")
    vector = cvss.get("vector_string")
    try:
        score = float(score) if score is not None else None
    except (TypeError, ValueError):
        score = None
    return score, vector


def _cvss_severity(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _extract_fix_commits(advisory: dict) -> list[tuple[str, str]]:
    """Return (owner/repo, sha) pairs from references and affected ranges."""
    results: list[tuple[str, str]] = []

    for ref in advisory.get("references", []) or []:
        url = ref if isinstance(ref, str) else ref.get("url", "")
        m = _COMMIT_RE.match(url)
        if m:
            results.append((m.group(1), m.group(2)))

    for vuln in advisory.get("vulnerabilities", []) or []:
        for rng in (vuln.get("vulnerable_version_range") and [] or []):
            pass  # ranges here are semver, not git SHAs — skip

    return results


def _get_commit_info(owner_repo: str, sha: str) -> tuple[str | None, str]:
    """Return (parent_sha, commit_message) for the given commit SHA."""
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
    """Return .py filenames changed in the given commit."""
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
    """Fetch raw file content at a specific git ref."""
    url = f"https://raw.githubusercontent.com/{owner_repo}/{ref}/{file_path}"
    try:
        resp = requests.get(url, headers=_gh_headers(), timeout=15)
        return resp.text if resp.status_code == 200 else None
    except Exception as e:
        logger.warning(f"Failed to fetch {url}: {e}")
        return None


# ---------------------------------------------------------------------------
# GHSA paging
# ---------------------------------------------------------------------------

def _list_advisories(page: int) -> list[dict]:
    """Fetch one page of pip-ecosystem GHSA advisories."""
    try:
        resp = requests.get(
            f"{GITHUB_API}/advisories",
            headers=_gh_headers(),
            params={"ecosystem": "pip", "per_page": 100, "page": page},
            timeout=30,
        )
        if resp.status_code == 403:
            logger.warning("Rate limit on /advisories — sleeping 60s")
            _sleep(60)
            return []
        if resp.status_code != 200:
            logger.warning(f"/advisories returned {resp.status_code}")
            return []
        return resp.json()
    except Exception as e:
        logger.warning(f"Failed to list advisories page {page}: {e}")
        return []


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

def run(output_dir: str = "data/raw") -> int:
    if not TOKEN:
        logger.warning(
            "GITHUB_TOKEN not set — GHSA scraper will hit rate limits quickly. "
            "Add GITHUB_TOKEN to your .env file."
        )

    total = 0
    seen_hashes: set[str] = set()
    processed_commits: set[tuple[str, str]] = set()
    delay = 1.5 if TOKEN else 6.0

    page = 1
    while True:
        advisories = _list_advisories(page)
        if not advisories:
            break

        logger.info(f"GHSA page {page}: {len(advisories)} advisories")

        for advisory in advisories:
            cwe = _extract_cwe(advisory)
            if not cwe:
                continue
            if ("ghsa", cwe) in BLOCKED_SOURCE_CWE:
                continue

            vuln_type = CWE_VULN_MAP[cwe]
            cvss_score, cvss_vector = _extract_cvss(advisory)
            cvss_components = parse_cvss_vector(cvss_vector)
            ghsa_id = advisory.get("ghsa_id", "")
            cve_id = advisory.get("cve_id")

            fix_commits = _extract_fix_commits(advisory)
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

                    # Phase 2B: replaced is_web_code() filter with sink-presence
                    # gate so non-web Python CWEs (798, 611, 330, 400, etc.)
                    # aren't silently dropped.
                    sink_ok, _ = has_cwe_sink(code_before, cwe, file_path=file_path)
                    if not sink_ok:
                        continue

                    code_after = _fetch_file_at_ref(owner_repo, file_path, fix_sha) or ""

                    h = hash_code(code_before)
                    if h in seen_hashes:
                        continue
                    seen_hashes.add(h)

                    framework = detect_framework(code_before)

                    meta = build_meta(
                        {
                            "id":               f"ghsa_{vuln_type}_{h}",
                            "source":           "ghsa",
                            "ghsa_id":          ghsa_id,
                            "cve_id":           cve_id,
                            "cwe":              cwe,
                            "vuln_type":        vuln_type,
                            "label_source":     "ghsa",
                            "label_confidence": "high",
                            "commit_message":   commit_msg,
                            "framework":        framework,
                            # CVSS available directly from GHSA — no Phase 3 needed
                            "cvss_score":               cvss_score,
                            "cvss_severity":            _cvss_severity(cvss_score),
                            "cvss_source":              "ghsa",
                            **cvss_components,
                            "repo":             owner_repo,
                            "file_path":        file_path,
                            "fix_commit":       fix_sha,
                            "vulnerable_commit": parent_sha,
                            "pair_id":          f"{fix_sha[:8]}_{file_path}",
                        },
                        code_before,
                        code_after,
                    )
                    # GHSA samples already have CVSS — mark enrichment done
                    meta["nvd_enriched"] = True
                    save_code_sample(code_before, meta, output_dir)
                    total += 1
                    logger.info(
                        f"  Saved [{cwe}] {ghsa_id} — "
                        f"{owner_repo}/{file_path} (CVSS {cvss_score}, {framework})"
                    )
                    _sleep(0.5)

        if len(advisories) < 100:
            break
        page += 1
        _sleep(delay)

    logger.info(f"ghsa_scraper finished — {total} samples saved to {output_dir}")
    return total
